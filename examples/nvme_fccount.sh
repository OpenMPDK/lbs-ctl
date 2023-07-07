#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author:
# Daniel Gomez <da.gomez@samsung.com>
set -xv

bpftrace -e 'kprobe:nvme_* { @[func] = count(); }'
