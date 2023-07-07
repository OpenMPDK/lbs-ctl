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
#include <linux/bio.h>

struct data_t {
    u32 pid;
    u64 ts;
    u32 maxio;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HISTOGRAM(dist);
//BPF_ARRAY(adist, struct data_t, 1);
BPF_ARRAY(adist, u64, 1);
BPF_HASH(hdist, char *, u64, 3);

void kprobe__blk_execute_rq_nowait(struct pt_regs *ctx, struct request *req) 
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.maxio = BIO_MAX_VECS;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    //dist.increment(bpf_log2l(req->__data_len / 1024));
    //dist.increment(req->__data_len / 1024);
    //dist.increment(req->bio->bi_vcnt);
    //u64 value = req->__data_len / 1024;
    //u64 value = req->bio->bi_vcnt;
    //u64 value = BIO_MAX_VECS /4;
    //u64 value = BIO_MAX_VECS;
    int key = 0;
    //u64 val;
    //dist.increment(bpf_log2l(value));
    //adist.increment(2);
    //struct data_t *val;
    u64 *val;
    val = adist.lookup(&key);
    if (val)
        *val = 111;

    char ckey[] = "BIO";

    u64 *cval = hdist.lookup(ckey);


}
""")

# header
print("Tracing...");

bmc = 0
def print_event(cpu, data, size):
    global bmc
    event = b["events"].event(data)
    #print("cpu: {cpu} data.comm {comm} data.pid: {pid} data.ts: {ts} size: {size}".format(cpu=cpu, comm=event.comm, pid=event.pid, ts=event.ts, size=size))
    if bmc == 0:
        print("BIO_MAX_VECS={bmc}".format(bmc=event.maxio))
        bmc = event.maxio


b["events"].open_perf_buffer(print_event)

try:
    while 1:
        b.perf_buffer_poll()
        sleep(0.1)
except KeyboardInterrupt:
    print()

#b["dist"].print_log2_hist("kbytes")
b["dist"].print_linear_hist("kbytes")
ad = b["adist"]
print(ad.values())

import pdb; pdb.set_trace()


print("done")
#    sleep(9999999)
#except KeyboardInterrupt:
#    print()
#
#import pdb; pdb.set_trace
