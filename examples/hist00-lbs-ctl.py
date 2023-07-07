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
import argparse
import logging
import sys
import os

try:
    import colorlog
    HAVE_COLORLOG = True
except ImportError:
    HAVE_COLORLOG = False
    pass

__version__ = "0.1"

b = BPF(text="""
""")


def bio_prog():
    """
    kprobe__blk_execute_rq_nowait
    """

    prog = """
    #include <uapi/linux/ptrace.h>
    #include <linux/blk-mq.h>
    #include <linux/bio.h>
    
    struct data_t {
        u32 pid;
        u64 ts;
        u32 maxio;
        char comm[TASK_COMM_LEN];
    };

    struct bio_data_t {
        u32 nr_phys_segments;
        u16 bio_max_vecs;
    };
    
    BPF_PERF_OUTPUT(events);
    BPF_PERF_OUTPUT(bio_events);
    
    void kprobe__blk_execute_rq_nowait(struct pt_regs *ctx, struct request *req) 
    {
        struct data_t data = {};
        struct bio_data_t bio_data = {};
    
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.maxio = BIO_MAX_VECS;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        bio_data.nr_phys_segments = req->nr_phys_segments;
        bio_data.bio_max_vecs = BIO_MAX_VECS;
    
        events.perf_submit(ctx, &data, sizeof(data));
        bio_events.perf_submit(ctx, &bio_data, sizeof(bio_data));
    }
    """
    logging.debug(prog)
    return prog


def _logger_conf(args: argparse.Namespace) -> None:
    """Setup the logging environment."""
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    format_str = "%(asctime)s - %(levelname)-8s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(format_str, date_format)
    if os.isatty(2):
        cformat = "%(log_color)s" + format_str
        colors = {
            "DEBUG": "reset",
            "INFO": "bold_black",
            "WARNING": "bold_yellow",
            "ERROR": "bold_red",
            "CRITICAL": "bold_red",
        }
        if HAVE_COLORLOG:
            formatter = colorlog.ColoredFormatter(cformat, date_format, log_colors=colors)
        else:
            formatter = logging.Formatter(format_str, date_format)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)
    log.setLevel(logging.INFO)
    _logger_level(args)
    return


def _logger_level(args: argparse.Namespace) -> None:
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    return


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Large Block Size Analysis tool")
    parser.add_argument(
        "-d",
        "--debug",
        help="enable debug output",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="%(prog)s version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparser = parser.add_subparsers(help='sub command help', dest='cmd')
    subparser.add_parser("bio", help="bio eBPF")
    return parser


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("cpu: {cpu} data.comm {comm} data.pid: {pid} data.ts: {ts} size: {size}".format(cpu=cpu, comm=event.comm, pid=event.pid, ts=event.ts, size=size))


nr_phys_segments = bio_max_vecs = 0
def print_bio_event(cpu, bio_data, size):
    global nr_phys_segments, bio_max_vecs
    bio_event = b["bio_events"].event(bio_data)
    nps = bio_event.nr_phys_segments
    bmv = bio_event.bio_max_vecs
    if (nps != nr_phys_segments):
        print("nr_phys_segments={nps}".format(nps=bio_event.nr_phys_segments))
        nr_phys_segments = nps
    if (bmv != bio_max_vecs):
        print("BIO_MAX_VECS={bmv}".format(bmv=bmv))
        bio_max_vecs = bmv


def bio():
    global b
    prog = bio_prog()
    logging.info("Loading...")
    b = BPF(text=prog)
    logging.info("Tracing enabled. Press 'Ctrl+C' to cancel.")
    b["events"].open_perf_buffer(print_event)
    b["bio_events"].open_perf_buffer(print_bio_event)
    try:
        while 1:
            b.perf_buffer_poll()
            sleep(0.1)
    except KeyboardInterrupt:
        print()

    logging.info("bio done")


def main() -> None:
    """The tool."""
    p = _parser()
    args, _ = p.parse_known_args()

    _logger_conf(args)

    logging.info("Large Block Size Analysis tool")

    if not args.cmd:
        p.print_usage()
        return

    logging.info("cmd: {}".format(args.cmd))
    bio()


if __name__ == "__main__":
    ret = 0
    try:
        main()
    except Exception:
        ret = 1
        import traceback

        traceback.print_exc()
    sys.exit(ret)
