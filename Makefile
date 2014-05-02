DEST?=/usr/local
CFLAGS += -g $(SET_DEBUG)

all: nflogtable
debug: nflogtable

debug:  SET_DEBUG=-DDEBUG

nflogtable: main.c
	gcc $(CFLAGS) -lnetfilter_log -o nflogtable main.c

clean:
	rm -f nflogtable

install:
	install nflogtable $(DEST)/sbin

uninstall:
	rm -f $(DEST)/sbin/nflogtable
