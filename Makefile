PWD         := $(shell pwd)
KVERSION    := $(shell uname -r)
KERNEL_DIR   = /usr/src/linux-headers-$(KVERSION)/
XTABLES_LIBDIR ?= $(shell pkg-config xtables --variable=xtlibdir)
ccflags-y += -O3
obj-m := xt_SPOOFTCP.o

all: libxt_SPOOFTCP.so mod strip

strip: libxt_SPOOFTCP.so mod
	strip libxt_SPOOFTCP.so
	strip --strip-debug xt_SPOOFTCP.ko

libxt_SPOOFTCP.so: libxt_SPOOFTCP.o
	$(CC) ${CFLAGS} ${LDFLAGS} -shared -lxtables libxt_SPOOFTCP.o -o libxt_SPOOFTCP.so

libxt_SPOOFTCP.o:
	$(CC) ${CFLAGS} -O3 -fPIC -c libxt_SPOOFTCP.c -o libxt_SPOOFTCP.o

mod:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f libxt_SPOOFTCP.so libxt_SPOOFTCP.o
install: all
	install -m 0644 libxt_SPOOFTCP.so $(XTABLES_LIBDIR)/
	modprobe ip6_tables
	-rmmod xt_SPOOFTCP
	insmod xt_SPOOFTCP.ko
	#install -m 0644 xt_SPOOFTCP.ko /lib/modules/$(KVERSION)/kernel/net/netfilter/
