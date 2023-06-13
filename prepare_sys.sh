# RUN FROM ROOT SHELL

# disable ASLR
echo 0 > /proc/sys/kernel/randomize_va_space

# allow mapping of low address space
echo "vm.mmap_min_addr = 0" > /etc/sysctl.d/mmap_min_addr.conf
