// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/runtime.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>
#include <common/trace_key.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/server_traces.h>

#include <shared/obi_ctx.h>

#include <socktracer/common_defs.h>
#include <socktracer/helpers.h>
#include <socktracer/http.h>
#include <socktracer/http2.h>
#include <socktracer/maps/listener_pid_map.h>
#include <socktracer/maps/sk_data_map.h>
#include <socktracer/socket_data.h>
#include <socktracer/ssl_detect.h>
#include <socktracer/tcp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SCRATCH_MEM_SIZED(payload_buf, 4096);

// cgroup_skb/ingress: data pointer starts at the IP header (L3).
// We compute the TCP payload offset once in the entry program, store it in
// skb->cb[0], and all ctx_* helpers use it to hide the L3/L4 headers from the
// protocol parsers (which expect data to start at the TCP payload).

enum {
    k_ipproto_hopopts  = 0,
    k_ipproto_routing  = 43,
    k_ipproto_fragment = 44,
    k_ipproto_dstopts  = 60,
};

static __always_inline u32 ctx_compute_payload_offset_v4(struct __sk_buff *skb) {
    void *data     = ctx_skb_data(skb);
    void *data_end = ctx_skb_data_end(skb);

    const struct iphdr *ip = data;

    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) {
        return 0;
    }

    const u32 ip_hlen = (u32)ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr)) {
        return 0;
    }

    const struct tcphdr *tcp = data + ip_hlen;
    if ((void *)(tcp + 1) > data_end) {
        return 0;
    }

    const u32 tcp_hlen = (u32)tcp->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr)) {
        return 0;
    }

    return ip_hlen + tcp_hlen;
}

static __always_inline u32 ctx_compute_payload_offset_v6(struct __sk_buff *skb) {
    void *data     = ctx_skb_data(skb);
    void *data_end = ctx_skb_data_end(skb);

    const struct ipv6hdr *ip6 = data;

    if ((void *)(ip6 + 1) > data_end) {
        return 0;
    }

    if (ip6->version != 6) {
        return 0;
    }

    const void *ptr = (const void *)(ip6 + 1);
    u8 curr_hdr = ip6->nexthdr;

    // iterate at most 4 extension headers
    for (u8 i = 0; i < 4; i++) {
        if (curr_hdr == IPPROTO_TCP) {
            break;
        }

        const struct ipv6_opt_hdr *opt_hdr = ptr;

        if ((const void *)(opt_hdr + 1) > data_end) {
            return 0;
        }

        switch (curr_hdr) {
        case k_ipproto_hopopts:
        case k_ipproto_routing:
        case k_ipproto_dstopts:
            ptr += ((u32)opt_hdr->hdrlen + 1) * 8;
            break;
        case k_ipproto_fragment:
            ptr += 8;
            break;
        default:
            return 0;
        }

        curr_hdr = opt_hdr->nexthdr;
    }

    if (curr_hdr != IPPROTO_TCP) {
        return 0;
    }

    const struct tcphdr *tcp = ptr;

    if ((const void *)(tcp + 1) > data_end) {
        return 0;
    }

    const u32 tcp_hlen = (u32)tcp->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr)) {
        return 0;
    }

    return (u32)(ptr - data) + tcp_hlen;
}

static __always_inline u32 ctx_compute_payload_offset(struct __sk_buff *skb) {
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        return ctx_compute_payload_offset_v4(skb);
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return ctx_compute_payload_offset_v6(skb);
    }

    return 0;
}

static __always_inline u32 ctx_len(void *ctx) {
    struct __sk_buff *skb = ctx;
    const u32 offset = min(skb->cb[0], 0xff);
    return skb->len > offset ? skb->len - offset : 0;
}

static __always_inline void ctx_pull_data(void *ctx, u32 len) {
    (void) ctx;
    (void) len;
}

static __always_inline void *ctx_data(void *ctx) {
    unsigned char *p = payload_buf_mem();

    if (!p) {
        return NULL;
    }

    (void) ctx;
    //struct __sk_buff *skb = ctx;

    //p += skb->cb[0];

    return p;
}

static __always_inline void *ctx_data_end(void *ctx) {
    (void) ctx;

    unsigned char *p = payload_buf_mem();
    p += 0xfff;

    return p;
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

    const u32 host_pid = sk_data->pid_tgid;

    connection_info_part_t conn_part = {};

    populate_ephemeral_info(
        &conn_part, &sk_data->sorted_conn, sk_data->conn.d_port, host_pid, FD_SERVER);

    bpf_dbg_printk("Saving connection server span for pid=%u, tid=%u, ephemeral_port=%u",
                   sk_data->pid_key.pid,
                   sk_data->pid_key.tid,
                   conn_part.port);

    bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

    const trace_key_t t_key = trace_key(sk_data);

    tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);

    if (existing && existing->req_type == tp_p->req_type && tp_p->req_type == EVENT_HTTP_REQUEST) {
        existing->valid = 0;
        bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
        return;
    }

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
    k_tail_ingress_http_found_tp,
};

int obi_ingress_http_req(struct __sk_buff *skb);
int obi_ingress_http_create_tp(struct __sk_buff *skb);
int obi_ingress_http_found_tp(struct __sk_buff *skb);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} obi_ingress_progs SEC(".maps") = {
    .values = {[k_tail_ingress_http_req] = (void *)&obi_ingress_http_req,
               [k_tail_ingress_http_create_tp] = (void *)&obi_ingress_http_create_tp,
               [k_tail_ingress_http_found_tp] = (void *)&obi_ingress_http_found_tp},
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

static __always_inline u32 tail_http_found_tp() {
    return k_tail_ingress_http_found_tp;
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
    (void) ctx;
    (void) t_ctx;
}

// k_tail_ingress_http_create_tp
SEC("cgroup_skb/ingress")
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

SEC("cgroup_skb/ingress")
int obi_ingress_http_req(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_find_tp(skb);
}

// k_tail_ingress_http_found_tp
SEC("cgroup_skb/ingress")
int obi_ingress_http_found_tp(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_found_tp(skb);
}

// Resolves PID info for a newly accepted socket whose pid_tgid is not yet set.
// Looks up {netns_cookie, local_port} in listener_pid_map, which is populated
// by post_bind (BPF) and backfillPidForSockets (userspace).
static __always_inline const struct listener_pid_val *
resolve_listener_pid_val(struct __sk_buff *skb) {
    const struct listener_pid_key key = {
        .netns_cookie = bpf_get_netns_cookie(skb),
        .local_port   = skb->local_port,
    };

    const struct listener_pid_val *val = bpf_map_lookup_elem(&listener_pid_map, &key);

    if (!val) {
        bpf_dbg_printk("resolve_pid: no entry for netns=%llu port=%u",
                       key.netns_cookie, key.local_port);
    } else {
        bpf_dbg_printk("resolve_pid: found pid_tgid=%llu for netns=%llu port=%u",
                       val->pid_tgid, key.netns_cookie, key.local_port);
    }

    return val;
}

static __always_inline void obi_server_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http2(skb, sk_data, k_packet_direction_ingress)) {
        return;
    }

    if (handle_http_req(skb, sk_data)) {
        return;
    }

    // TODO: handle other protocols

    if (handle_tcp(skb, sk_data, k_packet_direction_ingress)) {
        return;
    }
}

static __always_inline void obi_client_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http2(skb, sk_data, k_packet_direction_ingress)) {
        return;
    }

    if (handle_http_res(skb, sk_data)) {
        return;
    }

    handle_tcp(skb, sk_data, k_packet_direction_ingress);
}

SEC("cgroup_skb/ingress")
int obi_socket_ingress(struct __sk_buff *skb) {
    const u32 payload_offset = ctx_compute_payload_offset(skb);

    if (payload_offset == 0) {
        // Not IPv4 TCP — pass through without processing.
        return SK_PASS;
    }

    skb->cb[0] = payload_offset;

    unsigned char *payload_mem = payload_buf_mem();

    if (!payload_mem) {
        return SK_PASS;
    }

    const u32 skb_len = skb->len & 0xfff;

    if (skb_len == 0) {
        return SK_PASS;
    }

    const u64 cookie = bpf_get_socket_cookie(skb);

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    if (sk_data->pid_tgid == 0) {
        const struct listener_pid_val *pid_val = resolve_listener_pid_val(skb);

        if (!pid_val) {
            return SK_PASS;
        }

        sk_data->pid_tgid = pid_val->pid_tgid;
        sk_data->pid_info  = pid_val->pid_info;
        sk_data->pid_key   = pid_val->pid_key;
    }

    if (payload_offset >= skb_len) {
        return SK_PASS;
    }

    const u32 payload_len = (skb_len - payload_offset) & 0xfff;

    if (payload_len == 0) {
        return SK_PASS;
    }

    if (bpf_skb_load_bytes(skb, payload_offset, payload_mem, payload_len) != 0) {
        return SK_PASS;
    }

    bpf_dbg_printk("obi_socket_ingress: cookie=%llu, payload_len=%u offset = %u data=[%s]",
        cookie, ctx_len(skb), payload_offset, ctx_data(skb));

    if (sk_data_is_ssl_ingress(sk_data, skb)) {
        bpf_dbg_printk("ingress: cookie=%llu ssl, skipping", cookie);
        return SK_PASS;
    }

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

