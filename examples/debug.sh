nvme show-regs -H /dev/nvme0 | grep MPS
nvme id-ctrl -H /dev/nvme0n1 | grep ^mdts
nvme id-ns -H /dev/nvme0n1 | grep ^LBA
aux=$(cat /sys/class/block/nvme0n1/queue/max_hw_sectors_kb)
echo "max_hw_sectors_kb: $aux"
aux=$(cat /sys/class/block/nvme0n1/queue/logical_block_size)
echo "logical_block_size: $aux"
aux=$(cat /sys/class/block/nvme0n1/queue/physical_block_size)
echo "physical_block_size: $aux"
aux=$(cat /sys/class/block/nvme0n1/queue/max_segments)
echo "max_segments: $aux"
aux=$(getconf PAGE_SIZE)
echo "PAGE_SIZE: $aux"
printf "| %8s | %8s | %15s |\n| -------- | -------- | --------------- |\n" "NVMe" "blk-mq" "Device Name"; sudo nvme list | cut -d " " -f1 | grep nvm | xargs -I {} bash -c 'LBA=$(sudo nvme id-ns -H {} | grep ^LBA | grep "in use" | cut -d " " -f15); nvme=$(echo {} | sed s,/dev/,,); LBA_blkmq=$(cat /sys/class/block/${nvme}/queue/logical_block_size); printf "| %8s | %8s | %15s | \n" $LBA $LBA_blkmq {}'
