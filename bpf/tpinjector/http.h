// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/http_info.h>
#include <common/large_buffers.h>
#include <common/trace_common.h>

#include <logger/bpf_dbg.h>

#include <tpinjector/common_defs.h>
#include <tpinjector/http_core.h>
#include <tpinjector/maps/sk_data_map.h>
#include <tpinjector/socket_data.h>
#include <tpinjector/tailcall_ctx.h>

volatile const u32 high_request_volume = 0;

enum : u8 { k_packet_type_request = 1, k_packet_type_response = 2 };

static __always_inline u32 lb_payload_size(u32 size) {
    const u32 payload_size = size > http_buffer_size ? http_buffer_size : size;

    return payload_size > sizeof(void *) ? payload_size : sizeof(void *);
}

static __always_inline void
send_http_large_buffer(void *ctx, struct socket_data *sk_data, u8 packet_type, u8 action) {
    bpf_dbg_enter();

    if (http_buffer_size == 0) {
        return;
    }

    u32 remaining_len = ctx_len(ctx);

    const u8 nbuffers = remaining_len / http_buffer_size + (remaining_len % http_buffer_size != 0);

    http_info_t *info = &sk_data->request.http;

    for (u8 i = 0; i < nbuffers; ++i) {
        const u32 payload_size = lb_payload_size(remaining_len);
        u32 total_size = (sizeof(tcp_large_buffer_t) + payload_size) & k_large_buf_max_size_mask;

        if (total_size > 4096) {
            return;
        } else if (total_size > 2048) {
            total_size = 4096;
        } else if (total_size > 1024) {
            total_size = 2048;
        } else {
            total_size = 1024;
        }

        tcp_large_buffer_t *buf = (tcp_large_buffer_t *)bpf_ringbuf_reserve(&events, total_size, 0);

        if (!buf) {
            return;
        }

        buf->type = EVENT_TCP_LARGE_BUFFER;
        buf->packet_type = packet_type;
        buf->direction = info->direction;
        buf->conn_info = info->conn_info;
        buf->action = action;
        buf->tp = info->tp;

        bpf_ringbuf_submit(buf, get_flags());

        action = k_large_buf_action_append;

#if 0
        unsigned char *b = ctx_data(ctx);
        const unsigned char *e = ctx_data_end(ctx);
        unsigned char *ptr = b + (i * http_buffer_size);

#endif
        remaining_len -= payload_size;
    }

#if 0
    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *) http_large_buffers_mem();

    if (!large_buf) {
        bpf_dbg_printk("failed to reserve space for HTTP large buffer");
        return;
    }

    http_info_t *info = &sk_data->request.http;

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->direction = info->direction;
    large_buf->conn_info = info->conn_info;
    large_buf->action = action;
    large_buf->tp = info->tp;


    if (len > http_buffer_size) {
        len = http_buffer_size;
        bpf_dbg_printk("WARN: buffer is full, truncating data");
    }

    large_buf->len = len;

    ctx_pull_data(ctx, len);

    const u32 niter = 0;

    unsigned char *b = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);
    unsigned char *ptr = b + (niter * 1024);

    unsigned char *buf = large_buf->buf;
    const u32 data_size = (e - ptr) & 0xfff; // 1KB chunks per iteration

    for (u32 i = 0; i < data_size; ++i) {
        if (ptr + 1 > e) {
            return;
        }

        *buf++ = *ptr++;
    }

#if 0
    bpf_probe_read(large_buf->buf, large_buf->len & k_large_buf_payload_max_size_mask, ctx_data(ctx));
#endif

    const u32 payload_size = large_buf->len > sizeof(void *) ? large_buf->len : sizeof(void *);
    const u32 total_size = (sizeof(tcp_large_buffer_t) + payload_size) & k_large_buf_max_size_mask;;


    bpf_dbg_printk("sending large buffer, size=%u", payload_size);

    if (bpf_ringbuf_output(&events, large_buf, total_size, get_flags()) == 0) {
        info->has_large_buffers = true;
    }
#endif
}

static __always_inline void init_http_request(void *ctx, struct socket_data *sk_data) {
    bpf_dbg_enter();

    const u32 len = ctx_len(ctx);

    init_http_request_common(sk_data, len);

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

    init_http_request(ctx, sk_data);

    send_http_large_buffer(ctx, sk_data, k_packet_type_request, k_large_buf_action_init);

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

static __always_inline int http_find_tp(void *ctx) {
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

    unsigned char *b = ctx_data(ctx);
    const unsigned char *e = ctx_data_end(ctx);
    unsigned char *ptr = b + (niter * 1024);

    if (ptr >= e) {
        return SK_PASS;
    }

    bpf_dbg_printk("looking for traceparent header (iter=%u)", niter);

    bpf_dbg_printk("buf=%s", b);

    const u32 data_size = (e - ptr) & 0x3ff; // 1KB chunks per iteration

    for (u32 i = 0; i < data_size; ++i) {
        if (ptr + TP_SIZE >= e || is_eoh(ptr)) {
            t_ctx->niter = 0;
            bpf_tail_call_static(ctx, prog_map(), tail_http_create_tp());
            bpf_dbg_printk("TAILCALL FAILED");
            break;
        }

        if (is_traceparent(ptr)) {
            ptr += TP_TID_PREFIX_SIZE;

            decode_hex(tp_p->tp.trace_id, ptr, TRACE_ID_CHAR_LEN);

            ptr += TRACE_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            unsigned char *dest = tp_span_id_field(&tp_p->tp);

            decode_hex(dest, ptr, SPAN_ID_CHAR_LEN);

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

            init_span_id(t_ctx, &tp_p->tp, span_id);

            tp_p->tp.ts = bpf_ktime_get_ns();
            tp_p->tp.flags = 1;
            tp_p->valid = 1;
            tp_p->written = 1;
            tp_p->pid = sk_data->pid_tgid >> 32;
            tp_p->req_type = request_type(sk_data);

            print_tp("found TP in headers", &tp_p->tp);

            set_trace(sk_data, tp_p);

            sk_data->request.http.tp = tp_p->tp;

            schedule_write_tcp_option(ctx, tp_p);

            return SK_PASS;
        }

        ++ptr;
    }

    t_ctx->niter++;

    if (t_ctx->niter < k_max_iter) {
        bpf_tail_call_static(ctx, prog_map(), tail_http_req());
        bpf_dbg_printk("TAILCALL FAILED");
    } else {
        t_ctx->niter = 0;
        bpf_tail_call_static(ctx, prog_map(), tail_http_create_tp());
        bpf_dbg_printk("TAILCALL FAILED");
    }

    return SK_PASS;
}

static __always_inline int http_create_tp(void *ctx) {
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

    init_tp(sk_data, &tp_p->tp);

    urand_bytes(tp_p->tp.span_id, sizeof(tp_p->tp.span_id));

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 1;
    tp_p->pid = sk_data->pid_tgid >> 32;
    tp_p->req_type = request_type(sk_data);

    sk_data->request.http.tp = tp_p->tp;

    print_tp("created new TP", &tp_p->tp);

    set_trace(sk_data, tp_p);

    schedule_write_tcp_option(ctx, tp_p);

    write_tp_http_header(ctx, t_ctx);

    return SK_PASS;
}
