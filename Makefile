obj-m+=bloom_filter.o
EXTRA_CFLAGS=-I$(PWD)/inc
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean