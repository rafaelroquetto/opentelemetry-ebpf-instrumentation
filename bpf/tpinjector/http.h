// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_info.h>

#include <logger/bpf_dbg.h>

#include <tpinjector/common_defs.h>
#include <tpinjector/http_core.h>
#include <tpinjector/socket_data.h>
#include <tpinjector/tailcall_ctx.h>

volatile const u32 high_request_volume = 0;

static __always_inline void
init_http_request(void *ctx, struct socket_data *sk_data, u8 direction) {
    bpf_dbg_enter();

    const u32 len = ctx_len(ctx);

    init_http_request_common(sk_data, len, direction);

    http_info_t *info = &sk_data->request.http;

    __builtin_memset(info->buf, 0, sizeof(info->buf));

    if (len == 0) {
        return;
    }

    const u32 nbytes = len > sizeof(info->buf) ? sizeof(info->buf) : len;

    ctx_pull_data(ctx, nbytes);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (ptr + nbytes > e) {
        return;
    }

    for (u32 i = 0; i < nbytes; ++i) {
        if (ptr + 1 > e) {
            break;
        }

        info->buf[i] = *ptr++;
    }
}

static __always_inline bool handle_http_req(void *ctx, struct socket_data *sk_data) {
    bpf_dbg_enter();

    // check if this is an ongoing request of if we have anything stale to
    // flush
    const u32 len = ctx_len(ctx);

    if (handle_pending_http_req(sk_data, len)) {
        return true;
    }

    // now begin trying to process a new HTTP request
    if (len < MIN_HTTP_REQ_SIZE) {
        return false;
    }

    ctx_pull_data(ctx, MIN_HTTP_REQ_SIZE);

    const unsigned char *b = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (b + MIN_HTTP_REQ_SIZE > e) {
        return false;
    }

    if (!is_http_request_buf(b)) {
        return false;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return false;
    }

    t_ctx->sock_cookie = sk_data->cookie;
    t_ctx->niter = 0;

    init_http_request(ctx, sk_data, TCP_SEND);

    bpf_tail_call_static(ctx, prog_map(), tail_http_req());

    return true;
}

static __always_inline void handle_http_res(void *ctx, struct socket_data *data) {
    bpf_dbg_enter();

    if (data->request.flags != EVENT_K_HTTP_REQUEST) {
        return;
    }

    struct http_info *info = &data->request.http;

    // have we just begun processing this response?
    const bool response_beginning = info->resp_len == 0;

    info->resp_len += ctx_len(ctx);
    info->end_monotime_ns = bpf_ktime_get_ns();

    if (!response_beginning) {
        // we've either parsed or missed the headers, anyway, no need to look
        // them up anymore
        return;
    }

    const char HTTP_RES[] = "HTTP/1.x 000";
    const size_t HTTP_RES_SIZE = sizeof(HTTP_RES) - 1;
    const size_t k_status_code_off = 9;

    ctx_pull_data(ctx, HTTP_RES_SIZE);

    const unsigned char *ptr = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);

    if (ptr + HTTP_RES_SIZE > e) {
        return;
    }

    if (ptr[0] != HTTP_RES[0] || ptr[1] != HTTP_RES[1] || ptr[2] != HTTP_RES[2] ||
        ptr[3] != HTTP_RES[3] || ptr[4] != HTTP_RES[4] || ptr[5] != HTTP_RES[5] ||
        ptr[6] != HTTP_RES[6]) {
        return;
    }

    ptr += k_status_code_off;

    // parse status
    info->status = (*ptr++ - '0') * 100;
    info->status += (*ptr++ - '0') * 10;
    info->status += *ptr - '0';

    if (info->status > MAX_HTTP_STATUS) {
        // we read something invalid
        info->status = 0;
    }

    bpf_dbg_printk("status=%u", info->status);

    // XXX it seems we don't wait for the entire request to complete when
    // reading a client response
    if (high_request_volume || data->sk_type == sk_type_client) {
        finish_http_req(data);
    }
}
