// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "pid/types/pid_key.h"
#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/http_info.h>

#include <pid/types/pid_info.h>

enum sk_type : u8 { sk_type_client, sk_type_server };

struct socket_data {
    u64 pid_tgid;
    u64 cookie;
    u64 accept_time;

    pid_info pid_info;

    u32 task_tid;

    union {
        u8 flags;
        http_info_t http;
    } request;

    pid_key_t pid_key;

    connection_info_t conn;
    connection_info_t sorted_conn;

    enum sk_type sk_type;

    u8 _pad[3];
};
