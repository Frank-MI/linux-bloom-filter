obj-m+=bloom_filter.o
EXTRA_CFLAGS=-I$(PWD)/inc
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) ccflags-y="-g -DDEBUG" modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean