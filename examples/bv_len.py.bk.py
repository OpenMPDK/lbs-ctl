#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author:
# Daniel Gomez <da.gomez@samsung.com>

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(bv_len);
BPF_HISTOGRAM(bv_len_hist);
BPF_HISTOGRAM(bi_vcnt_hist);
BPF_HISTOGRAM(bi_vcnt_lhist);

void kprobe__blk_execute_rq_nowait(struct pt_regs *ctx, struct request *req) 
{
        u64 i, aux, aux2;
        bi_vcnt_hist.increment(bpf_log2l(req->bio->bi_vcnt));
        bi_vcnt_lhist.increment(req->bio->bi_vcnt / 10);

        for (i=0; i<256; i++) {
            u64 idx=i;
            if (i >= req->bio->bi_vcnt)
                break;
            aux = req->bio->bi_io_vec[i].bv_len;
            if (aux == 0)
                break;
            aux2 = aux/1024;
            bv_len.lookup_or_try_init(&idx, &aux2);
            bv_len_hist.increment(bpf_log2l(aux));
            //bv_len_hist.increment(idx, aux);
        }
}
""")

# header
print("Tracing...");

try:
    sleep(9999999)
except KeyboardInterrupt:
    print()

bv_len = b.get_table("bv_len")
for k, v in sorted(bv_len.items(), key=lambda bv_len: bv_len[1].value):
    print("- key: {}, value: {}".format(k.value, v.value))

bv_len_hist = b.get_table("bv_len_hist")
print("bv_len histogram (log2 scale):")
bv_len_hist.print_log2_hist("bv_len")

bi_vcnt_hist = b.get_table("bi_vcnt_hist")
print("bi_vcnt histogram (log2 scale):")
bi_vcnt_hist.print_log2_hist("bi_vcnt")
bi_vcnt_hist.print_linear_hist("bi_vcnt")

print("done")
