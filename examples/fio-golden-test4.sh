fio -bs=16k -iodepth=8 -rw=write -ioengine=io_uring -size=200M -name=io_uring_1 -filename=/dev/nvme0n1 -verify=md5
