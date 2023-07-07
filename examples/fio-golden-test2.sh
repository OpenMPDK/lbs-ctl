fio -bs=8k -iodepth=8 -rw=write -ioengine=io_uring -size=200M -name=io_uring_1 -filename=/dev/nvme0n1
