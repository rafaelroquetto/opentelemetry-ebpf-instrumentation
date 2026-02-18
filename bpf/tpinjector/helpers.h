// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <tpinjector/socket_data.h>

static __always_inline void print_tp(const char *msg, const tp_info_t *tp) {
    if (!g_bpf_debug) {
        return;
    }

    unsigned char tp_buf_str[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf_str, tp);
    bpf_dbg_printk("%s: %s", msg, tp_buf_str);
}

static __always_inline u8 request_type(struct socket_data *sk_data) {
    return sk_data->sk_type == sk_type_client ? EVENT_HTTP_CLIENT : EVENT_HTTP_REQUEST;
}
