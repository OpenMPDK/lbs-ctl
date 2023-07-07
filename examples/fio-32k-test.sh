fio -bs=32k -iodepth=8 -rw=write -ioengine=io_uring -size=200M -name=io_uring_1 -filename=/dev/nvme10n1 -verify=md5 -direct=1
