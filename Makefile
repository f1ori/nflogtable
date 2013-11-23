all: nflogtable

nflogtable: main.c
	gcc -g -lnetfilter_log -o nflogtable main.c

clean:
	rm -f nflogtable
