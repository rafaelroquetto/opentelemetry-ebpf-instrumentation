// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

typedef struct tailcall_ctx {
    u64 sock_cookie;
    tp_info_t parent_tp;
    pid_connection_info_t p_conn;
    u32 tp_write_off;
    egress_key_t e_key;
    u8 niter;
    bool has_parent_tp;
    u16 tp_val_off;
    u8 _pad[4];
} tailcall_ctx;

SCRATCH_MEM(tailcall_ctx);
