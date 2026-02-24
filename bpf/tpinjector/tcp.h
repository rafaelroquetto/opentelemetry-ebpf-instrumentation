// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>

#include <tpinjector/common_defs.h>
#include <tpinjector/socket_data.h>

static __always_inline bool handle_tcp(void *ctx, struct socket_data *sk_data) {
    bpf_dbg_enter();

    tcp_req_t *tcp = &sk_data->request.tcp;

    const u32 len = ctx_len(ctx);

    // ongoing TCP session
    if (tcp->flags == EVENT_TCP_REQUEST) {
        tcp->len += len;
        tcp->end_monotime_ns = bpf_ktime_get_ns();
        ;
        return true;
    }

    if (sk_data->request.flags != 0) {
        return false;
    }

    const enum sk_type sk_type = sk_data->sk_type;

    const u8 direction = sk_type == sk_type_client ? TCP_SEND : TCP_RECV;

    tcp->flags = EVENT_TCP_REQUEST;
    tcp->is_server = sk_data->sk_type == sk_type_server;
    tcp->conn_info = sk_data->conn;
    tcp->ssl = false;
    tcp->direction = direction;
    tcp->start_monotime_ns = bpf_ktime_get_ns();
    tcp->end_monotime_ns = bpf_ktime_get_ns();
    ;
    tcp->resp_len = 0;
    tcp->len = len;
    tcp->req_len = len;
    tcp->extra_id = 0; //extra_runtime_id();
    tcp->protocol_type = k_protocol_type_unknown;
    tcp->pid = sk_data->pid_info;

    tcp->tp.ts = bpf_ktime_get_ns();

    init_tp(sk_data, &tcp->tp);

    urand_bytes(tcp->tp.span_id, sizeof(tcp->tp.span_id));

    __builtin_memset(tcp->buf, 0, sizeof(tcp->buf));

    if (len == 0) {
        return true;
    }

    const u32 nbytes = len > sizeof(tcp->buf) ? sizeof(tcp->buf) : len;

    ctx_pull_data(ctx, nbytes);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (ptr + nbytes > e) {
        return true;
    }

    for (u32 i = 0; i < nbytes; ++i) {
        if (ptr + 1 > e) {
            break;
        }

        tcp->buf[i] = *ptr++;
    }

    return true;
}
