#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author:
# Daniel Gomez <da.gomez@samsung.com>
set -xv

bpftrace -l 'kprobe:nvme_pci_setup_prps,kprobe:nvme_pci_setup_sgls,kprobe:nvme_setup_prp_simple,kprobe:nvme_setup_sgl_simple'
