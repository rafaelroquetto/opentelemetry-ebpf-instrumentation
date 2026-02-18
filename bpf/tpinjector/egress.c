// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/http_buf_size.h>
#include <common/http_info.h>
#include <common/http_types.h>
#include <common/msg_buffer.h>
#include <common/protocol_defs.h>
#include <common/scratch_mem.h>
#include <common/ssl_helpers.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_common.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <generictracer/protocol_http.h>
#include <generictracer/protocol_tcp.h>
#include <generictracer/protocol_http2.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/msg_buffers.h>
#include <maps/sock_dir.h>

#include <tpinjector/common_defs.h>
#include <tpinjector/helpers.h>
#include <tpinjector/http.h>
#include <tpinjector/maps/sk_data_map.h>
#include <tpinjector/maps/sk_storage_map.h>
#include <tpinjector/maps/sk_tp_info_pid_map.h>
#include <tpinjector/sk_storage_data.h>
#include <tpinjector/socket_data.h>

volatile const u32 track_request_headers = 0;

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline u32 ctx_len(void *ctx) {
    return ((struct sk_msg_md *)ctx)->size;
}

static __always_inline void ctx_pull_data(void *ctx, u32 len) {
    bpf_msg_pull_data(ctx, 0, len, 0);
}

static __always_inline void *ctx_data(void *ctx) {
    return ((struct sk_msg_md *)ctx)->data;
}

static __always_inline void *ctx_data_end(void *ctx) {
    return ((struct sk_msg_md *)ctx)->data_end;
}

static __always_inline pid_connection_info_t
pid_connection_info(const struct socket_data *sk_data) {
    const pid_connection_info_t p_conn = {.conn = sk_data->sorted_conn,
                                          .pid = sk_data->pid_tgid >> 32};

    return p_conn;
}

static __always_inline void set_client_trace(const struct socket_data *sk_data,
                                             const tp_info_pid_t *tp_p) {
    set_trace_info_for_connection(&sk_data->sorted_conn, TRACE_TYPE_CLIENT, tp_p);

    const egress_key_t e_key = {
        .d_port = sk_data->sorted_conn.d_port,
        .s_port = sk_data->sorted_conn.s_port,
    };

    bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, BPF_ANY);
}

// Flags to control what tpinjector should inject
enum {
    k_inject_http_headers = 1 << 0, // Bit 0: inject HTTP headers
    k_inject_tcp_options = 1 << 1,  // Bit 1: inject TCP options
};

volatile const u32 inject_flags =
    k_inject_http_headers | k_inject_tcp_options; // default: both enabled

// TCP option kind for OpenTelemetry context propagation
// Kind 25 is unassigned per IANA TCP Parameters registry (released 2000-12-18)
// Better than experimental options (253-254) which must not be shipped as defaults
enum { k_tcp_option_kind_otel = 25 };

enum {
    k_tail_packet_extender,
    k_tail_write_msg_traceparent,
    k_tail_egress_http_req,
    k_tail_egress_http_create_tp
};

int obi_packet_extender(struct sk_msg_md *msg);
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg);
int obi_egress_http_req(struct sk_msg_md *msg);
int obi_egress_http_create_tp(struct sk_msg_md *msg);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} obi_egress_progs SEC(".maps") = {
    .values =
        {
            [k_tail_packet_extender] = (void *)&obi_packet_extender,
            [k_tail_write_msg_traceparent] = (void *)&obi_packet_extender_write_msg_tp,
            [k_tail_egress_http_req] = (void *)&obi_egress_http_req,
            [k_tail_egress_http_create_tp] = (void *)&obi_egress_http_create_tp,
        },
};

static __always_inline void *prog_map() {
    return &obi_egress_progs;
}

static __always_inline u32 tail_http_req() {
    return k_tail_egress_http_req;
}

[[maybe_unused]]
static __always_inline egress_key_t make_key(const connection_info_t *conn) {
    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    sort_egress_key(&e_key);

    return e_key;
}

// This is setup here for Go and SSL tracking.
// Essentially, when the Go or the OpenSSL userspace
// probes activate for an outgoing HTTP request they setup this
// outgoing_trace_map for us. We then know this is a connection we should
// be injecting the Traceparent in. Another place which sets up this map is
// the kprobe on tcp_sendmsg, however that happens after the sock_msg runs,
// so we have a different detection for that - protocol_detector.
[[maybe_unused]]
static __always_inline tp_info_pid_t *get_tp_info_pid(const egress_key_t *e_key) {
    return bpf_map_lookup_elem(&outgoing_trace_map, e_key);
}

[[maybe_unused]]
static __always_inline void set_tp_info_pid(const egress_key_t *e_key, const tp_info_pid_t *tp_p) {
    bpf_map_update_elem(&outgoing_trace_map, e_key, tp_p, BPF_ANY);
}

static __always_inline void clear_tp_info_pid(const egress_key_t *e_key) {
    bpf_map_delete_elem(&outgoing_trace_map, e_key);
}

static __always_inline u8 already_tracked(const pid_connection_info_t *p_conn) {
    return already_tracked_http(p_conn) || already_tracked_tcp(p_conn) ||
           already_tracked_http2(p_conn);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv4
static __always_inline connection_info_t sk_msg_extract_key_ip4(const struct sk_msg_md *msg) {
    connection_info_t conn = {};

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = msg->remote_ip4;

    conn.s_port = msg->local_port;
    conn.d_port = bpf_ntohl(msg->remote_port);

    return conn;
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_msg_extract_key_ip6(struct sk_msg_md *msg) {
    connection_info_t conn = {};

    sk_msg_read_remote_ip6(msg, conn.d_ip);
    sk_msg_read_local_ip6(msg, conn.s_ip);

    conn.d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn.s_port = sk_msg_local_port(msg);

    return conn;
}

[[maybe_unused]]
static __always_inline void init_tp_ctx_parent_tp(tailcall_ctx *t_ctx) {
    t_ctx->parent_tp.ts = bpf_ktime_get_ns();
    t_ctx->parent_tp.flags = 1;

    t_ctx->has_parent_tp = find_parent_trace_for_client_request(
        &t_ctx->p_conn, t_ctx->p_conn.conn.d_port, &t_ctx->parent_tp);
}

[[maybe_unused]]
static __always_inline bool create_trace_info(const tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    // t_ctx->parent_tp was initialised earlier in init_tp_ctx_parent_tp - if
    // t_ctx->has_parent_tp is true, then it actually contains a valid tp_info
    // with the corrent trace_id and parent_id - all we need to do is generate
    // a new span_id
    // this logic is cumbersome, but it is done so to avoid calling
    // find_trace_for_client_request multiple times (i.e. once here, and once
    // earlier in  k_tail_egress_http_req - sorry!
    urand_bytes(tp_p->tp.span_id, sizeof(tp_p->tp.span_id));
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;

    if (t_ctx->has_parent_tp) {
        bpf_dbg_printk("found existing tp info");

        __builtin_memcpy(tp_p->tp.trace_id, t_ctx->parent_tp.trace_id, sizeof(tp_p->tp.trace_id));
        __builtin_memcpy(tp_p->tp.parent_id, t_ctx->parent_tp.span_id, sizeof(tp_p->tp.parent_id));
    } else {
        bpf_dbg_printk("generating tp info");

        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    return true;
}

// This code is copied from the kprobe on tcp_sendmsg and it's called from
// the sock_msg program, which does the packet extension for injecting the
// Traceparent. Since the sock_msg runs before the kprobe on tcp_sendmsg, we
// need to extend the packet before we'll have the opportunity to setup the
// outgoing_trace_map metadata. We can directly perhaps run the same code that
// the kprobe on tcp_sendmsg does, but it's complicated, no tail calls from
// sock_msg programs and inlining will eventually hit us with the instruction
// limit when we eventually add HTTP2/gRPC support.
static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn,
                                            const egress_key_t *e_key) {
    bpf_dbg_printk("id=%d, size=%d", id, msg->size);

    pid_connection_info_t p_conn = {};
    __builtin_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&p_conn.conn);
    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (msg->size == 0 || is_ssl_connection(&p_conn)) {
        return 0;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
        .real_size = msg->size > k_msg_buffer_size_max ? k_msg_buffer_size_max : msg->size,
        .cpu_id = bpf_get_smp_processor_id(),
    };

    bpf_probe_read_kernel(msg_buf.fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes =
        msg_buf.real_size > k_kprobes_http2_buf_size ? msg_buf.real_size : k_kprobes_http2_buf_size;

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        bpf_d_printk("failed to reserve msg_buffer space [%s]", __FUNCTION__);
        return 0;
    }

    msg_ptr[0] = 0;
    bpf_probe_read_kernel(msg_ptr, copy_bytes & k_msg_buffer_size_max_mask, msg->data);
    bpf_map_update_elem(&msg_buffer_mem, &(u32){0}, msg_ptr, BPF_ANY);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    if (bpf_map_update_elem(&msg_buffers, e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return 0;
    }

    // We should check if we have already seen this request and we've
    // started tracking it. We only want to extend the first packet that
    // looks like HTTP, not something that's passing HTTP in the body.
    if (already_tracked(&p_conn)) {
        bpf_dbg_printk("already extended before, ignoring this packet...");
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_ptr)) {
        bpf_dbg_printk("setting up request to be extended");

        return 1;
    }

    return 0;
}

[[maybe_unused]]
static __always_inline connection_info_t get_connection_info(struct sk_msg_md *msg) {
    return msg->family == AF_INET6 ? sk_msg_extract_key_ip6(msg) : sk_msg_extract_key_ip4(msg);
}

// this "beauty" ensures we hold pkt in the same register being range
// validated
static __always_inline unsigned char *
check_pkt_access(unsigned char *buf, //NOLINT(readability-non-const-parameter)
                 u32 offset,
                 const unsigned char *end) {
    unsigned char *ret;

    asm goto("r4 = %[buf]\n"
             "r4 += %[offset]\n"
             "if r4 > %[end] goto %l[error]\n"
             "%[ret] = %[buf]"
             : [ret] "=r"(ret)
             : [buf] "r"(buf), [end] "r"(end), [offset] "i"(offset)
             : "r4"
             : error);

    return ret;
error:
    return NULL;
}

static __always_inline void
make_tp_string_skb(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, TP_SIZE, end);

    if (!buf) {
        return;
    }

    const __attribute__((unused)) unsigned char *tp_string = buf;

    *buf++ = 'T';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    *buf++ = '0';
    *buf++ = (tp->flags == 0) ? '0' : '1';
    *buf++ = '\r';
    *buf++ = '\n';

    bpf_dbg_printk("tp_string=%s", tp_string);
}

static __always_inline bool
extend_and_write_tp(struct sk_msg_md *msg, u32 offset, const tp_info_t *tp) {
    const long err = bpf_msg_push_data(msg, offset, TP_SIZE, 0);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d [%s]", err, __FUNCTION__);
        return false;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk(
        "offset to split=%d, available=%u, size=%u", offset, msg->data_end - msg->data, msg->size);

    if (!msg->data) {
        bpf_d_printk("null data [%s]", __FUNCTION__);
        return false;
    }

    unsigned char *ptr = msg->data + offset;

    if ((void *)ptr + TP_SIZE >= msg->data_end) {
        bpf_d_printk("not enough space [%s]", __FUNCTION__);
        return false;
    }

    make_tp_string_skb(ptr, tp, msg->data_end);

    return true;
}

static __always_inline bool write_msg_traceparent(struct sk_msg_md *msg, const tp_info_t *tp) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return false;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return false;
    }

    const u32 write_offset = newline_pos + 1;

    return extend_and_write_tp(msg, write_offset, tp);
}

static __always_inline void schedule_write_tcp_option(struct sk_msg_md *msg, tp_info_pid_t *tp_p) {
    struct bpf_sock *sk = msg->sk;

    if (!sk) {
        return;
    }

    tp_info_pid_t *stp =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);

    if (!stp) {
        return;
    }

    // associate it also with this socket for the tcp options program
    *stp = *tp_p;

    tp_p->written = 1;
}

static __always_inline void write_http_traceparent(struct sk_msg_md *msg, tp_info_pid_t *tp_pid) {
    // used for the upcoming tailcall
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_pid->written = 1;
    *tp_p = *tp_pid;

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_write_msg_traceparent);

    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

[[maybe_unused]]
static __always_inline void handle_existing_tp_pid(struct sk_msg_md *msg,
                                                   u64 id,
                                                   const connection_info_t *conn,
                                                   const egress_key_t *e_key,
                                                   tp_info_pid_t *tp_pid) {
    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_pid);
    }

    // shortcut: if valid == 0, this is not a HTTP request (likely SSL, but
    // could be anything really - don't bother with protocol_detector)
    if (tp_pid->valid == 0) {
        clear_tp_info_pid(e_key);
        return;
    }

    // check if this really is a HTTP request whose headers we can also extend
    // (it could be an SSL packet instead, or just rubbish, for instance)
    const bool is_http = protocol_detector(msg, id, conn, e_key);

    if (is_http) {
        // here we'll leave it for protocol_http clean it up
        if (inject_flags & k_inject_http_headers) {
            write_http_traceparent(msg, tp_pid);
        }
    } else {
        clear_tp_info_pid(e_key);
    }
}

static __always_inline void obi_server_egress(struct sk_msg_md *msg, struct socket_data *sk_data) {
    bpf_dbg_enter();

    handle_http_res(msg, sk_data);
}

static __always_inline void obi_client_egress(struct sk_msg_md *msg, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http_req(msg, sk_data)) {
        return;
    }

    // TODO: handle other protocols
    //bpf_tail_call_static(msg, &obi_egress_progs, k_tail_packet_extender);
}

SEC("sk_msg")
int obi_socket_egress(struct sk_msg_md *msg) {
    const struct sk_storage_data *sk_storage =
        bpf_sk_storage_get(&sk_storage_map, msg->sk, NULL, 0);

    if (!sk_storage) {
        bpf_printk("no sk data msg->sk = %llx", msg->sk);
        return SK_PASS;
    }

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &sk_storage->sk_cookie);

    if (!sk_data) {
        bpf_printk("socket no longer tracked, cleaning up storage");

        bpf_sk_storage_delete(&sk_storage_map, msg->sk);

        return SK_PASS;
    }

    switch (sk_data->sk_type) {
    case sk_type_server:
        obi_server_egress(msg, sk_data);
        break;
    case sk_type_client:
        obi_client_egress(msg, sk_data);
        break;
    }

    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_req);

    return SK_PASS;
}

#if 0
SEC("sk_msg")
int obi_packet_extender(struct sk_msg_md *msg) {
    // If neither injection method is enabled, nothing to do
    if (!(inject_flags & (k_inject_http_headers | k_inject_tcp_options))) {
        return SK_PASS;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const connection_info_t conn = get_connection_info(msg);
    const egress_key_t e_key = make_key(&conn);

    t_ctx->p_conn.conn = conn;
    t_ctx->p_conn.pid = pid_from_pid_tgid(id);
    t_ctx->e_key = e_key;
    t_ctx->niter = 0;

    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);

    // Higher-level uprobes have already set the tp_pid for us (either Go, or SSL)
    if (tp_pid) {
        handle_existing_tp_pid(msg, id, &conn, &e_key, tp_pid);
        return SK_PASS;
    }

    // At this stage, there were no previously TP information setup - it's the first
    // time we are seeing this packet - so we need to detect whether this is the start
    // of a new request and perform any injection if so.
    // Valid PID only works for kprobes since Go programs don't add their
    // PIDs to the PID map (we instrument the binaries), handled in the
    // previous check
    const struct sk_storage_data *sk_data = bpf_sk_storage_get(&sk_storage_map, msg->sk, NULL, 0);

    if (!sk_data) {
        bpf_printk("no sk data msg->sk = %llx", msg->sk);
        return SK_PASS;
    }

    const struct socket_data *data = bpf_map_lookup_elem(&sk_data_map, &sk_data->sk_cookie);

    if (!data) {
        bpf_printk("socket no longer tracked, cleaning up storage");

        bpf_sk_storage_delete(&sk_storage_map, msg->sk);

        return SK_PASS;
    }

    bpf_printk("obi_packet_extender");

    bpf_dbg_printk("MSG=%llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO=%llx:%d", conn.d_ip[3], conn.d_port);
    bpf_dbg_printk("MSG SIZE=%u", msg->size);

    if (msg->size <= MIN_HTTP_SIZE) {
        // not enough data to detect anything, bail
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    // TODO: execute the protocol handlers here with tail calls, don't
    // rely on tcp_sendmsg to do it and record these message buffers.

    const u8 is_http = protocol_detector(msg, id, &conn, &e_key);

    // at this point, we can't handle anything other than HTTP, as we need to be able
    // to tell whether this is the start of a new request
    if (!is_http) {
        return SK_PASS;
    }

    // at this point we've found the start of a new HTTP request

    bpf_dbg_printk("len=%d, s_port=%d", msg->size, msg->local_port);
    bpf_dbg_printk("buf=[%s]", msg->data);
    bpf_dbg_printk("ptr=%llx, end=%llx", ctx_msg_data(msg), ctx_msg_data_end(msg));
    bpf_dbg_printk("BUF=[%s]", ctx_msg_data(msg));

    init_tp_ctx_parent_tp(t_ctx);

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_req);

    return SK_PASS;
}
#endif

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        bpf_dbg_printk("empty tp_buf");
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    if (!write_msg_traceparent(msg, &tp_p->tp)) {
        bpf_d_printk("failed to write traceparent [%s]", __FUNCTION__);
    }

    print_tp("written TP to headers", &tp_p->tp);
    bpf_dbg_printk("BUF=[%s]", msg->data);

    return SK_PASS;
}

static __always_inline void
assign_client_parent_tp(const tailcall_ctx *t_ctx, tp_info_t *tp, unsigned char *span_id) {
    if (!t_ctx->has_parent_tp) {
        return;
    }

    // test if the trace ids are equal - if they aren't, we don't
    // assign a parent
    if (__bpf_memcmp(tp->trace_id, t_ctx->parent_tp.trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return;
    }

    __builtin_memcpy(tp->parent_id, t_ctx->parent_tp.span_id, SPAN_ID_SIZE_BYTES);

    // check if the TP we parsed is a legimate one, or a
    // proxy-forwarded header - in which case we need to
    // override it
    if (__bpf_memcmp(tp->span_id, t_ctx->parent_tp.parent_id, SPAN_ID_SIZE_BYTES) != 0) {
        return;
    }

    // at this point, the span id of this outgoing call is equal to the span
    // id of the parent call (i.e. the Traceparent header is the same), which
    // hints it's being forwarded by some kind of proxy - in this case, we
    // generate a new span id and overwrite the header

    bpf_dbg_printk("detected forwarded TP header, overriding span id");

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);

    encode_hex(span_id, tp->span_id, SPAN_ID_SIZE_BYTES);
}

//k_tail_egress_http_req
SEC("sk_msg")
int obi_egress_http_req(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    const u32 k_max_iter = 4; // iterate up to 4KB

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const u64 cookie = t_ctx->sock_cookie;

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    const u32 niter = t_ctx->niter;

    if (niter >= k_max_iter) {
        return SK_PASS;
    }

    unsigned char *b = msg->data;
    const unsigned char *e = msg->data_end;
    unsigned char *ptr = b + (niter * 1024);

    if (ptr >= e) {
        return SK_PASS;
    }

    bpf_dbg_printk("looking for traceparent header (iter=%u)", niter);

    const u32 data_size = (e - ptr) & 0x3ff; // 1KB chunks per iteration

    for (u32 i = 0; i < data_size; ++i) {
        if (ptr + TP_SIZE >= e || is_eoh(ptr)) {
            bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_create_tp);
            break;
        }

        if (is_traceparent(ptr)) {
            ptr += TP_TID_PREFIX_SIZE;

            decode_hex(tp_p->tp.trace_id, ptr, TRACE_ID_CHAR_LEN);

            ptr += TRACE_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex(tp_p->tp.span_id, ptr, SPAN_ID_CHAR_LEN);

            unsigned char *span_id = ptr;

            ptr += SPAN_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex((unsigned char *)&tp_p->tp.flags, ptr, FLAGS_CHAR_LEN);

            ptr += FLAGS_CHAR_LEN;

            if (*ptr++ != '\r' || *ptr != '\n') {
                return SK_PASS;
            }

            // if we got to this point, we managed to parse a valid
            // 'Traceparent: ...' header that we can utilise

            assign_client_parent_tp(t_ctx, &tp_p->tp, span_id);

            tp_p->tp.ts = bpf_ktime_get_ns();
            tp_p->tp.flags = 1;
            tp_p->valid = 1;
            tp_p->written = 1;
            tp_p->pid = sk_data->pid_tgid >> 32;
            tp_p->req_type = request_type(sk_data);

            print_tp("found TP in headers", &tp_p->tp);

            set_client_trace(sk_data, tp_p);

            sk_data->request.http.tp = tp_p->tp;

            if (inject_flags & k_inject_tcp_options) {
                schedule_write_tcp_option(msg, tp_p);
            }

            return SK_PASS;
        }

        ++ptr;
    }

    t_ctx->niter++;

    if (t_ctx->niter < k_max_iter) {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_req);
    } else {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_create_tp);
    }

    return SK_PASS;
}

//k_tail_egress_http_create_tp
SEC("sk_msg")
int obi_egress_http_create_tp(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    const u64 cookie = t_ctx->sock_cookie;

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const pid_connection_info_t p_conn = pid_connection_info(sk_data);

    tp_info_t parent_tp = {};

    const bool has_parent =
        find_parent_trace_for_client_request(&p_conn, sk_data->conn.d_port, &parent_tp);

    if (has_parent) {
        __builtin_memcpy(tp_p->tp.trace_id, &parent_tp.trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(tp_p->tp.parent_id, &parent_tp.span_id, SPAN_ID_SIZE_BYTES);
    } else {
        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, SPAN_ID_SIZE_BYTES);
    }

    urand_bytes(tp_p->tp.span_id, sizeof(tp_p->tp.span_id));

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 1;
    tp_p->pid = sk_data->pid_tgid >> 32;
    tp_p->req_type = request_type(sk_data);

    sk_data->request.http.tp = tp_p->tp;

    print_tp("created new TP", &tp_p->tp);

    set_client_trace(sk_data, tp_p);

    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_p);
    }

    if (inject_flags & k_inject_http_headers) {
        // write the HTTP headers
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_write_msg_traceparent);
        bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
    }

    return SK_PASS;
}
