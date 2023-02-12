# Module name
MODULENAME		:= linuxvisor

# Build
MODULEDIR	:= /lib/modules/$(shell uname -r)
BUILDDIR	:= $(MODULEDIR)/build
KERNELDIR 	:= $(MODULEDIR)/kernel

# Source files
SRCS_S 		:= src
LIBS_S 		:= src/libs
INCL_S 		:= src/include

# Header files
SRCS_H		:= $(PWD)/include
LIBS_H		:= $(PWD)/$(LIBS_S)/headers
INCL_H		:= $(PWD)/$(INCL_S)/headers

# Module
obj-m 		:= $(MODULENAME).o

# Core
$(MODULENAME)-y 	+= src/entry.o

# Source
$(MODULENAME)-y 	+= src/vmm.o
$(MODULENAME)-y 	+= src/vmx.o
$(MODULENAME)-y 	+= src/vmcs.o
$(MODULENAME)-y 	+= src/cpu.o
#$(MODULENAME)-y 	+= src/socket_hiding.o
#$(MODULENAME)-y 	+= src/packet_hiding.o
#$(MODULENAME)-y 	+= src/port_knocking.o
#$(MODULENAME)-y 	+= src/privilege_escalation.o
#$(MODULENAME)-y 	+= src/module_hiding.o

# Libs
#$(MODULENAME)-y 	+= src/libs/syscalltable.o

# Include
#$(MODULENAME)-y 	+= src/include/utils.o

ccflags-y	:= -I$(SRCS_H) -Wno-declaration-after-statement

# Recipes
all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules

load:
#insmod $(KERNELDIR)/net/ipv4/netfilter/nf_reject_ipv4.ko
#insmod $(KERNELDIR)/net/ipv6/netfilter/nf_reject_ipv6.ko
	sudo insmod $(MODULENAME).ko
	dmesg |tail

unload:
	sudo rmmod $(MODULENAME)
	dmesg |tail
	
clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean