
rmmod custom_mkdir.ko
rmmod custom.ko
rmmod ioctl.ko
rmmod register_unregister.ko
insmod register_unregister.ko
insmod ioctl.ko
insmod custom.ko
insmod custom_mkdir.ko
gcc -o test test_open.c
gcc -o test_protected test_protected.c
gcc -o test_set_diff_vector test_set_diff_vector.c
gcc -o test_vector2 test_vector2.c
gcc -o clone_default test_clone_default.c
gcc -o clone_syscall test_clone_syscall.c
gcc -o httpd test_vector2.c
gcc -o test_clone test_clone.c


mknod /dev/ioctl_device c 89 1
