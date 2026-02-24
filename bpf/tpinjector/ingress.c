// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>
#include <common/trace_common.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/sock_dir.h>

#include <tpinjector/common_defs.h>
#include <tpinjector/helpers.h>
#include <tpinjector/http.h>
#include <tpinjector/maps/sk_data_map.h>
#include <tpinjector/socket_data.h>
#include <tpinjector/tcp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline u32 ctx_len(void *ctx) {
    return ((struct __sk_buff *)ctx)->len;
}

static __always_inline void ctx_pull_data(void *ctx, u32 len) {
    bpf_skb_pull_data(ctx, len);
}

static __always_inline void *ctx_data(void *ctx) {
    return ctx_skb_data((struct __sk_buff *)ctx);
}

static __always_inline void *ctx_data_end(void *ctx) {
    return ctx_skb_data_end((struct __sk_buff *)ctx);
}

static __always_inline void schedule_write_tcp_option(void *ctx, tp_info_pid_t *tp_p) {
    (void)ctx;
    (void)tp_p;
    // no-op - we never inject options on ingress
}

static __always_inline trace_key_t trace_key(const struct socket_data *sk_data) {
    trace_key_t t_key = {};
    t_key.p_key = sk_data->pid_key;
    t_key.extra_id = extra_runtime_id();

    return t_key;
}

static __always_inline void set_server_trace(const struct socket_data *sk_data,
                                             const tp_info_pid_t *tp_p) {
    set_trace_info_for_connection(&sk_data->sorted_conn, TRACE_TYPE_SERVER, tp_p);

    const u32 host_pid = sk_data->pid_tgid >> 32;

    connection_info_part_t conn_part = {};

    populate_ephemeral_info(
        &conn_part, &sk_data->sorted_conn, sk_data->conn.d_port, host_pid, FD_SERVER);

    bpf_dbg_printk("Saving connection server span for pid=%u, tid=%u, ephemeral_port=%u",
                   sk_data->pid_key.pid,
                   sk_data->pid_key.tid,
                   conn_part.port);

    bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

    const trace_key_t t_key = trace_key(sk_data);

#if 0
    tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);

    if (existing && existing->req_type == tp_p->req_type && tp_p->req_type == EVENT_HTTP_REQUEST) {
        existing->valid = 0;
        bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
        return;
    }
#endif

    bpf_dbg_printk(
        "Saving thread server span for ns=%u, extra_id=%llx", t_key.p_key.ns, t_key.extra_id);

    bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);

    obi_ctx__set(sk_data->pid_tgid, &tp_p->tp);
}

static __always_inline void set_trace(const struct socket_data *sk_data,
                                      const tp_info_pid_t *tp_p) {
    set_server_trace(sk_data, tp_p);
}

// this "beauty" ensures we hold pkt in the same register being range
// validated

// ----- ingress programs

enum {
    k_tail_ingress_http_req,
    k_tail_ingress_http_create_tp,
    k_tail_ingress_http_write_tp,
};

int obi_ingress_http_req(struct __sk_buff *skb);
int obi_ingress_http_create_tp(struct __sk_buff *skb);
int obi_ingress_http_write_tp(struct __sk_buff *skb);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} obi_ingress_progs SEC(".maps") = {
    .values = {[k_tail_ingress_http_req] = (void *)&obi_ingress_http_req,
               [k_tail_ingress_http_create_tp] = (void *)&obi_ingress_http_create_tp,
               [k_tail_ingress_http_write_tp] = (void *)&obi_ingress_http_write_tp},
};

static __always_inline void *prog_map() {
    return &obi_ingress_progs;
}

static __always_inline u32 tail_http_req() {
    return k_tail_ingress_http_req;
}

static __always_inline u32 tail_http_create_tp() {
    return k_tail_ingress_http_create_tp;
}

static __always_inline unsigned char *tp_span_id_field(tp_info_t *tp) {
    return tp->parent_id;
}

static __always_inline const tp_info_pid_t *
find_parent_trace_for_server_request(const connection_info_t *conn, const tp_info_t *tp) {
    //TODO: rename incoming_trace_map to something like incoming_tcp_opts
    const tp_info_pid_t *tcp_opt_tp = bpf_map_lookup_elem(&incoming_trace_map, conn);

    if (tcp_opt_tp) {
        return tcp_opt_tp;
    }

    if (disable_black_box_cp) {
        return NULL;
    }

    tp_info_pid_t *parent_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

    if (!parent_tp || !correlated_requests(tp, parent_tp)) {
        return NULL;
    }

    if (parent_tp->req_type != EVENT_HTTP_CLIENT) {
        return NULL;
    }

    // We ensure that server requests match the client type, otherwise SSL
    // can often be confused with TCP.
    // TODO: really?
    parent_tp->valid = 0;

    return parent_tp;
}

SEC("sk_skb/stream_verdict")
int obi_ingress_http_write_tp(struct __sk_buff *skb) {
    bpf_dbg_enter();

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const u32 write_off = t_ctx->tp_write_off & 0xfff;

    unsigned char *ptr = ctx_skb_data(skb) + write_off;

    if ((void *)ptr + TP_SIZE > ctx_skb_data_end(skb)) {
        return SK_PASS;
    }

    make_tp_string_skb(ptr, &tp_p->tp, ctx_skb_data_end(skb));

    bpf_printk("WRITTEN BUF = %s", ctx_skb_data(skb));
    return SK_PASS;
}

static __always_inline void init_tp(struct socket_data *sk_data, tp_info_t *tp) {
    const tp_info_pid_t *parent_tp =
        find_parent_trace_for_server_request(&sk_data->sorted_conn, tp);

    if (parent_tp) {
        __builtin_memcpy(tp->trace_id, parent_tp->tp.trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(tp->parent_id, parent_tp->tp.span_id, SPAN_ID_SIZE_BYTES);
    } else {
        new_trace_id(tp);
        __builtin_memset(tp->parent_id, 0, SPAN_ID_SIZE_BYTES);
    }
}

static __always_inline void write_tp_http_header(void *ctx, tailcall_ctx *t_ctx) {
#if 0
    bpf_dbg_enter();

    struct __sk_buff *skb = (struct __sk_buff *)ctx;

    //TODO: check config option and bail early if we shouldn't inject the TP
    if (bpf_skb_change_head(skb, TP_SIZE, 0) != 0) {
        return;
    }

    //TODO: pull max len computed in previous tailcall
    ctx_pull_data(skb, ctx_len(skb));

    unsigned char *ptr = ctx_data(skb);
    const unsigned char *e = ctx_data_end(skb);

    const u32 data_size = (e - ptr) & 0x1ff;
    (void) data_size;

    for (u32 i = 0; i < data_size; ++i) {
        if (ptr + TP_SIZE + 1 >= e) {
            break;
        }

        *ptr = *(ptr + TP_SIZE);

        if (*ptr == '\n') {
            break;
        }

        ++ptr;
    }

    ++ptr;

    t_ctx->tp_write_off = ((void *)ptr) - ctx_data(skb);

    bpf_dbg_printk("after buf=%s", ptr);

    bpf_tail_call_static(skb, &obi_ingress_progs, k_tail_ingress_http_write_tp);

    bpf_dbg_printk("TAILCALL FAILED");
#endif
}

// k_tail_ingress_http_create_tp
SEC("sk_skb/stream_verdict")
int obi_ingress_http_create_tp(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_create_tp(skb);
}

static __always_inline void
init_span_id(const tailcall_ctx *t_ctx, tp_info_t *tp, unsigned char *span_id) {
    (void)t_ctx;
    (void)span_id;

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
}

SEC("sk_skb/stream_verdict")
int obi_ingress_http_req(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_find_tp(skb);
}

static __always_inline void obi_server_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http_req(skb, sk_data)) {
        return;
    }

    // TODO: handle other protocols

    if (handle_tcp(skb, sk_data)) {
        return;
    }
}

static __always_inline void obi_client_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    handle_http_res(skb, sk_data);
}

SEC("sk_skb/stream_verdict")
int obi_socket_ingress(struct __sk_buff *skb) {
    const u64 cookie = bpf_get_socket_cookie(skb);

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    bpf_dbg_printk("cookie=%llu", cookie);

    switch (sk_data->sk_type) {
    case sk_type_server:
        obi_server_ingress(skb, sk_data);
        break;
    case sk_type_client:
        obi_client_ingress(skb, sk_data);
        break;
    }

    return SK_PASS;
}

// used to map a socket cookie to a pid
SEC("fexit/inet_csk_accept")
int BPF_PROG(obi_inet_csk_accept, struct sock *sk, void *arg, struct sock *accepted_sk) {
    (void)arg;

    const u64 cookie = bpf_get_socket_cookie(sk);
    const u64 accepted_cookie = bpf_get_socket_cookie(accepted_sk);
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        // stop tracking this socket
        bpf_map_delete_elem(&sk_data_map, &accepted_cookie);
        return 0;
    }

    const u32 pid = id >> 32;

    bpf_dbg_printk("pid=%u, cookie=%llu, accepted_cookie=%llu", pid, cookie, accepted_cookie);

    struct socket_data *data = bpf_map_lookup_elem(&sk_data_map, &accepted_cookie);

    if (!data) {
        bpf_dbg_printk("BUG: socket should be tracked, but isn't");
        return 0;
    }

    data->pid_tgid = id;
    data->accept_time = bpf_ktime_get_ns();
    data->task_tid = get_task_tid();
    task_pid(&data->pid_info);
    task_tid(&data->pid_key);

    return 0;
}
