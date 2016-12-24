obj-m += register_unregister.o 
obj-m += custom.o
obj-m += ioctl.o
obj-m += custom_mkdir.o

all: register_unregister_mod

register_unregister_mod:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build -I/usr/src/hw3-cse506p12/include M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f custom register_unregister ioctl custom_mkdir
