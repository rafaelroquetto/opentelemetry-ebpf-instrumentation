// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/sock_dir.h>

#include <socktracer/maps/sk_data_map.h>
#include <socktracer/maps/sk_storage_map.h>

#include <socktracer/sk_storage_data.h>

#include <socktracer/socket_data.h>

char __license[] SEC("license") = "Dual MIT/GPL";

static const struct socket_data _sock_data_zero = {};

// max IPv6+port: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535" = 48 chars
enum { k_addr_buf_len = 48 };

static __always_inline void format_in_addr(__be32 addr, u16 port, char buf[k_addr_buf_len]) {
    BPF_SNPRINTF(buf,
                 k_addr_buf_len,
                 "%u.%u.%u.%u:%u",
                 (addr) & 0xFF,
                 (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF,
                 (addr >> 24) & 0xFF,
                 port);
}

static __always_inline void format_sock_addrs_v4(struct sock_common *skc,
                                                 char src_buf[k_addr_buf_len],
                                                 char dst_buf[k_addr_buf_len],
                                                 u16 src_port,
                                                 __be16 dst_port) {
    format_in_addr(BPF_CORE_READ(skc, skc_rcv_saddr), src_port, src_buf);
    format_in_addr(BPF_CORE_READ(skc, skc_daddr), bpf_ntohs(dst_port), dst_buf);
}

static __always_inline void
format_in6_addr(const struct in6_addr *addr, u16 port, char buf[k_addr_buf_len]) {
    BPF_SNPRINTF(buf,
                 k_addr_buf_len,
                 "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
                 bpf_ntohs(addr->in6_u.u6_addr16[0]),
                 bpf_ntohs(addr->in6_u.u6_addr16[1]),
                 bpf_ntohs(addr->in6_u.u6_addr16[2]),
                 bpf_ntohs(addr->in6_u.u6_addr16[3]),
                 bpf_ntohs(addr->in6_u.u6_addr16[4]),
                 bpf_ntohs(addr->in6_u.u6_addr16[5]),
                 bpf_ntohs(addr->in6_u.u6_addr16[6]),
                 bpf_ntohs(addr->in6_u.u6_addr16[7]),
                 port);
}

static __always_inline void format_sock_addrs_v6(struct sock_common *skc,
                                                 char src_buf[k_addr_buf_len],
                                                 char dst_buf[k_addr_buf_len],
                                                 u16 src_port,
                                                 __be16 dst_port) {
    struct in6_addr src6;
    struct in6_addr dst6;

    BPF_CORE_READ_INTO(&src6, skc, skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&dst6, skc, skc_v6_daddr);

    format_in6_addr(&src6, src_port, src_buf);
    format_in6_addr(&dst6, bpf_ntohs(dst_port), dst_buf);
}

static __always_inline void format_sock_addrs(struct sock_common *skc,
                                              char src_buf[k_addr_buf_len],
                                              char dst_buf[k_addr_buf_len]) {
    const u16 family = BPF_CORE_READ(skc, skc_family);
    const __be16 dst_port = BPF_CORE_READ(skc, skc_dport);
    const u16 src_port = BPF_CORE_READ(skc, skc_num);

    if (family == AF_INET) {
        format_sock_addrs_v4(skc, src_buf, dst_buf, src_port, dst_port);
    } else {
        format_sock_addrs_v6(skc, src_buf, dst_buf, src_port, dst_port);
    }
}

static __always_inline connection_info_t extract_conn_ip4(struct sock_common *skc) {
    connection_info_t conn = {};

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = BPF_CORE_READ(skc, skc_rcv_saddr);
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = BPF_CORE_READ(skc, skc_daddr);
    conn.s_port = BPF_CORE_READ(skc, skc_num);
    conn.d_port = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));

    return conn;
}

static __always_inline connection_info_t extract_conn_ip6(struct sock_common *skc) {
    connection_info_t conn = {};

    BPF_CORE_READ_INTO(&conn.s_ip, skc, skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&conn.d_ip, skc, skc_v6_daddr.in6_u.u6_addr32);
    conn.s_port = BPF_CORE_READ(skc, skc_num);
    conn.d_port = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));

    return conn;
}

static __always_inline connection_info_t extract_conn(struct sock_common *skc) {
    const u16 family = BPF_CORE_READ(skc, skc_family);

    return family == AF_INET6 ? extract_conn_ip6(skc) : extract_conn_ip4(skc);
}

SEC("iter/tcp")
int obi_sk_iter_tcp(struct bpf_iter__tcp *ctx) {
    struct sock_common *skc = ctx->sk_common;

    if (!skc) {
        return 0;
    }

    const u8 state = BPF_CORE_READ(skc, skc_state);

    if (state != TCP_ESTABLISHED) {
        return 0;
    }

    struct tcp_sock *tcp = bpf_skc_to_tcp_sock(skc);

    if (!tcp) {
        return 0;
    }

    const u64 cookie = bpf_get_socket_cookie(skc);

    char src_buf[k_addr_buf_len] = {};
    char dst_buf[k_addr_buf_len] = {};

    format_sock_addrs(skc, src_buf, dst_buf);

    struct seq_file *seq = ctx->meta->seq;

    BPF_SEQ_PRINTF(seq, "Tracking socket cookie=%llu state=%u src=%s dst=%s\n", cookie, state, src_buf, dst_buf);

    bpf_d_printk("Tracking socket cookie=%llu state=%u src=%s dst=%s", cookie, state, src_buf, dst_buf);

    // Pre-existing socket at OBI startup: full initialisation.
    if (bpf_map_update_elem(&sock_dir, &cookie, skc, BPF_NOEXIST) != 0) {
        bpf_dbg_printk("sock_dir already has cookie=%llu, skipping", cookie);
        return 0;
    }

    if (bpf_map_update_elem(&sk_data_map, &cookie, &_sock_data_zero, BPF_NOEXIST) != 0) {
        bpf_dbg_printk("Failed to init sk_data for cookie=%llu", cookie);
        return 0;
    }

    struct socket_data *data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!data) {
        return 0;
    }

    data->pid_tgid = 0;
    data->cookie = cookie;
    data->conn = extract_conn(skc);
    data->sorted_conn = data->conn;
    sort_connection_info(&data->sorted_conn);
    data->sk_type = likely_ephemeral_port(data->conn.s_port) ? sk_type_client : sk_type_server;

    struct sk_storage_data sk_storage = {.sk_cookie = cookie};

    if (!bpf_sk_storage_get(
            &sk_storage_map, (struct sock *)tcp, &sk_storage, BPF_SK_STORAGE_GET_F_CREATE)) {
        bpf_dbg_printk("Failed to create sk_storage for cookie=%llu", cookie);
    }

    return 0;
}
