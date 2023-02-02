obj-m += linuxvisor.o
linuxvisor-objs := ../src/entry.o ../src/vmm.o

# Set PWD to the current directory
PWD := $(CURDIR) 

all: 

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# move linuxvisor.ko to root folder of project.
	cp linuxvisor.ko ../linuxvisor.ko

clean: 

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# delete all .o and o.cmd files
	find ../src -type f -name '*.o' -delete
	find ../src -type f -name '*.o.cmd' -delete

rm:

	find ../src -type f -name '*.o' -delete
	find ../src -type f -name '*.o.cmd' -delete