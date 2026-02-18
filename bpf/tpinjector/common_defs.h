// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static __always_inline u32 ctx_len(void *ctx);
static __always_inline void ctx_pull_data(void *ctx, u32 len);
static __always_inline void *ctx_data(void *ctx);
static __always_inline void *ctx_data_end(void *ctx);

static __always_inline void *prog_map();

static __always_inline u32 tail_http_req();
