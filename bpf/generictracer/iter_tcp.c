// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/sock_port_ns.h>

#include <maps/sock_dir.h>

#include <generictracer/maps/listening_ports.h>

static __always_inline void conn_info_port_from_skc(const struct sock_common *skc,
                                                    connection_info_t *conn) {
    conn->s_port = skc->skc_num;
    conn->d_port = bpf_ntohs(skc->skc_dport);
}

static __always_inline void conn_info_from_sock4(const struct sock_common *skc,
                                                 connection_info_t *conn) {
    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(
        conn->s_addr + sizeof(ip4ip6_prefix), &skc->skc_rcv_saddr, sizeof(skc->skc_rcv_saddr));
    __builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &skc->skc_daddr, sizeof(skc->skc_daddr));

    conn_info_port_from_skc(skc, conn);
}

static __always_inline void conn_info_from_sock6(const struct sock_common *skc,
                                                 connection_info_t *conn) {
    __builtin_memcpy(conn->s_addr, &skc->skc_v6_rcv_saddr, sizeof(skc->skc_v6_rcv_saddr));
    __builtin_memcpy(conn->d_addr, &skc->skc_v6_daddr, sizeof(skc->skc_v6_daddr));

    conn_info_port_from_skc(skc, conn);
}

static __always_inline bool conn_info_from_sock(const struct sock_common *skc,
                                                connection_info_t *conn) {
    switch (skc->skc_family) {
    case AF_INET:
        conn_info_from_sock4(skc, conn);
        return true;
    case AF_INET6:
        conn_info_from_sock6(skc, conn);
        return true;
    }

    return false;
}

static __always_inline void track_sock(const struct sock_common *ptr) {
    struct sock_common skc = {};

    if (bpf_probe_read_kernel(&skc, sizeof(skc), ptr) != 0) {
        return;
    }

    connection_info_t conn = {};

    if (conn_info_from_sock(&skc, &conn)) {
        if (bpf_map_update_elem(&sock_dir, &conn, ptr, BPF_NOEXIST) == 0) {
            bpf_printk("TRACKING SOCK");

            const connection_info_t *info = &conn;
            bpf_printk("[conn] s_h = %llx, s_l = %llx, s_port=%d",
                       *(u64 *)(&info->s_addr),
                       *(u64 *)(&info->s_addr[8]),
                       info->s_port);
            bpf_printk("[conn] d_h = %llx, d_l = %llx, d_port=%d",
                       *(u64 *)(&info->d_addr),
                       *(u64 *)(&info->d_addr[8]),
                       info->d_port);
        }
    }
}

SEC("iter/tcp")
int obi_iter_tcp(struct bpf_iter__tcp *ctx) {
    struct sock_common *skc = ctx->sk_common;
    if (!skc) {
        return 0;
    }

    track_sock(skc);

    const unsigned char skc_state = BPF_CORE_READ(skc, skc_state);
    if (skc_state != TCP_LISTEN) {
        return 0;
    }

    struct sock_port_ns pn = sock_port_ns_from_skc(skc);
    bpf_map_update_elem(&listening_ports, &pn, &(bool){true}, BPF_ANY);

    struct seq_file *seq = ctx->meta->seq;
    BPF_SEQ_PRINTF(seq, "Add listening port=%d netns=%d\n", pn.port, pn.netns);

    return 0;
}
