
// The MIT License (MIT)

// Copyright (c) 2013 Florian Richter

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <getopt.h>

#include <libnetfilter_log/libnetfilter_log.h>

#if DEBUG
#define DEBUG_ON 1
#else
#define DEBUG_ON 0
#endif

const char *version_text = "nflogtable Version 0.1\n";

const char *help_text =
    "Usage: nflogtable [OPTION]\n"
    "Traffic counter for a ipv4 or ipv6 subnet.\n"
    "Packets are captured via netfilter_log and counted.\n"
    "Table with the counters is synced to the filesystem via memory-mapping.\n"
    "\n"
    "Options:\n"
    "  -h --help                 print this help\n"
    "  -v --version              print version information\n"
    "     --nflog-group=<id>     nflog group\n"
    "     --subnet=<ip/cidr>     ipv4 or ipv6 subnet to counter traffic for\n"
    "     --filename=<path>      path to file for table\n"
    "\n"
    "Example:\n"
    "  sudo iptables -I OUTPUT -j NFLOG --nflog-group 32\n"
    "  sudo ./nflogtable --nflog-group=32 --filename=test.tab --subnet=172.20.64.0/19\n"
    "\n"
    "Hint:\n"
    "  You might want to use \"--nflog-qthreshold N\" for better performance (see man iptables).\n"
    "\n";

// for netfilter_log documentation, see http://netfilter.org/projects/libnetfilter_log/doxygen/

// table header
struct table_header_t {
    uint8_t version;
    uint8_t address_family;
    uint8_t prefix_size;
    uint8_t unused1; // 64 bit padding
    uint32_t unused2;
    union subnet_t {
        struct in_addr subnet_address4;
        struct in6_addr subnet_address6;
    } subnet;
    uint64_t start_time;
    uint64_t end_time;
} __attribute__((packed)) *table_header;

// table cell
struct counter_entry_t {
    uint64_t sent_packets;
    uint64_t sent_bytes;
    uint64_t received_packets;
    uint64_t received_bytes;
} *counters;


#define ASSERT(condition, error_msg) if (!(condition)) { fputs((error_msg), stderr); exit(1); }
#define IF_ERROR(command, error_msg) if (command) { perror((error_msg)); exit(1); }
#define POSITIV(value)  ( ((value)>=0) ? (value) : 0 )
#define RANGE(value, min, max)  ( ((value)>=(min)) ? ( (value)<=(max) ? (value) : (max) ) : (min) )
#define RIGHT_BITSHIFT128(addr, nbit) if((nbit)>=64) { *((uint64_t*)addr); *((uint64_t*)addr) = 0;}
#define debug_print(format, ...) if (DEBUG_ON) { fprintf (stdout, format, ##__VA_ARGS__); }

int address_family;
struct in_addr subnet_address4;
struct in6_addr subnet_address6;
struct in_addr mask4;
struct in6_addr mask6;
int prefix_size = 0;
unsigned int aggregate_suffix;
unsigned long num_counters;
size_t table_size;


void sig_handler(int signo)
{
    if (signo == SIGHUP) {
        msync(table_header, table_size, MS_ASYNC);
    }
}

static int print_pkt(struct nflog_data *ldata)
{
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
    u_int32_t mark = nflog_get_nfmark(ldata);
    u_int32_t indev = nflog_get_indev(ldata);
    u_int32_t outdev = nflog_get_outdev(ldata);
    char *prefix = nflog_get_prefix(ldata);
    char *payload;
    int payload_len = nflog_get_payload(ldata, &payload);

    if (ph) {
            printf("hw_protocol=0x%04x hook=%u ",
                    ntohs(ph->hw_protocol), ph->hook);
    }

    printf("mark=%u ", mark);

    if (indev > 0)
            printf("indev=%u ", indev);

    if (outdev > 0)
            printf("outdev=%u ", outdev);


    if (prefix) {
            printf("prefix=\"%s\" ", prefix);
    }
    if (payload_len >= 0)
            printf("payload_len=%d ", payload_len);

    if (payload_len >= 0) {
        if ((payload[0] & 0xf0) == (address_family == AF_INET ? 0x40 : 0x60)) {
            int addr_size = address_family == AF_INET ? 4 : 16;
            int src_addr_offset = address_family == AF_INET ? 12 : 8;
            int dest_addr_offset = address_family == AF_INET ? 16 : 24;
            int size_offset = address_family == AF_INET ? 2 : 4;

            char out[64];
            inet_ntop(address_family, &payload[src_addr_offset], out, 64);
            printf("src=%s ", out);

            uint32_t x = *((uint32_t*)(payload + src_addr_offset)) & mask4.s_addr;
            inet_ntop(address_family, &x, out, 64);
            printf("x=%s ", out);

            char src_in = (*((uint32_t*)(payload + src_addr_offset)) & mask4.s_addr) == subnet_address4.s_addr;
            printf("%lu ", src_in);

            inet_ntop(address_family, &payload[dest_addr_offset], out, 64);
            printf("dest=%s ", out);

            char dest_in = (*((uint32_t*)(payload + dest_addr_offset)) & mask4.s_addr) == subnet_address4.s_addr;
            printf("%lu ", dest_in);

            uint16_t size;
            memcpy(&size, &payload[size_offset], 2);
            size = ntohs(size);
            printf("size=%hu ", size);
        }
    }

    fputc('\n', stdout);
    return 0;
}

static int handle_packet(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
                struct nflog_data *nfa, void *data)
{
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(nfa);
    char *payload;
    int payload_len = nflog_get_payload(nfa, &payload);

    // if we log ipv4 and the packet is ipv4
    if ( (address_family == AF_INET) && ((payload[0] & 0xf0) == 0x40) ) {
        int addr_size = 4;
        int src_addr_offset = 12;
        int dest_addr_offset = 16;
        int size_offset = 2;

        char out[64];
        inet_ntop(address_family, &payload[src_addr_offset], out, 64);
        debug_print("src=%s ", out);
        inet_ntop(address_family, &payload[dest_addr_offset], out, 64);
        debug_print("dest=%s ", out);

        // test network mask against source and destination address
        char src_internal = (*((uint32_t*)(payload + src_addr_offset)) & mask4.s_addr) == subnet_address4.s_addr;
        char dest_internal = (*((uint32_t*)(payload + dest_addr_offset)) & mask4.s_addr) == subnet_address4.s_addr;

        // extract size field
        uint16_t size;
        memcpy(&size, &payload[size_offset], 2);
        size = ntohs(size);
        debug_print("%d %d ", src_internal, dest_internal);

        if (src_internal && !dest_internal) {
            // outgoing packet
            debug_print("out ");
            uint32_t table_offset = ntohl(*((uint32_t*)(payload + src_addr_offset)) & ~mask4.s_addr);
            debug_print("offset=%d ", table_offset);
            counters[table_offset].sent_packets++;
            counters[table_offset].sent_bytes += size;
        }
        if (!src_internal && dest_internal) {
            // incoming packet
            debug_print("in ");
            uint32_t table_offset = ntohl(*((uint32_t*)(payload + dest_addr_offset)) & ~mask4.s_addr);
            debug_print("offset=%d ", table_offset);
            counters[table_offset].received_packets++;
            counters[table_offset].received_bytes += size;
        }

        debug_print("size=%hu ", size);
    }
    // if we log ipv6 and the packet is ipv6
    if ( (address_family == AF_INET6) && ((payload[0] & 0xf0) == 0x60) ) {
        int addr_size = 16;
        int src_addr_offset = 8;
        int dest_addr_offset = 24;
        int size_offset = 4;

        char out[64];
        inet_ntop(address_family, &payload[src_addr_offset], out, 64);
        debug_print("src=%s ", out);
        inet_ntop(address_family, &payload[dest_addr_offset], out, 64);
        debug_print("dest=%s ", out);

        // test network mask against source and destination address
        char src_internal = (*((uint32_t*)(payload + src_addr_offset     )) & mask6.s6_addr32[0]) == subnet_address6.s6_addr32[0]
                        &&  (*((uint32_t*)(payload + src_addr_offset +  4)) & mask6.s6_addr32[1]) == subnet_address6.s6_addr32[1]
                        &&  (*((uint32_t*)(payload + src_addr_offset +  8)) & mask6.s6_addr32[2]) == subnet_address6.s6_addr32[2]
                        &&  (*((uint32_t*)(payload + src_addr_offset + 12)) & mask6.s6_addr32[3]) == subnet_address6.s6_addr32[3];
        char dest_internal = (*((uint32_t*)(payload + dest_addr_offset     )) & mask6.s6_addr32[0]) == subnet_address6.s6_addr32[0]
                         &&  (*((uint32_t*)(payload + dest_addr_offset +  4)) & mask6.s6_addr32[1]) == subnet_address6.s6_addr32[1]
                         &&  (*((uint32_t*)(payload + dest_addr_offset +  8)) & mask6.s6_addr32[2]) == subnet_address6.s6_addr32[2]
                         &&  (*((uint32_t*)(payload + dest_addr_offset + 12)) & mask6.s6_addr32[3]) == subnet_address6.s6_addr32[3];

        // extract size field
        uint16_t size;
        memcpy(&size, &payload[size_offset], 2);
        size = ntohs(size);
        debug_print("%d %d ", src_internal, dest_internal);

        if (src_internal && !dest_internal) {
            // outgoing packet
            debug_print("out ");
            uint32_t table_offset = ntohl(*((uint32_t*)(payload + src_addr_offset + 4)) & ~mask6.s6_addr32[1]);
            debug_print("offset=%d ", table_offset);
            counters[table_offset].sent_packets++;
            counters[table_offset].sent_bytes += size;
        }
        if (!src_internal && dest_internal) {
            // incoming packet
            debug_print("in ");
            uint32_t table_offset = ntohl(*((uint32_t*)(payload + dest_addr_offset + 4)) & ~mask6.s6_addr32[1]);
            debug_print("offset=%d ", table_offset);
            counters[table_offset].received_packets++;
            counters[table_offset].received_bytes += size;
        }

        debug_print("size=%hu ", size);
    }
    debug_print("\n");

}


int main(int argc, char **argv)
{
    struct nflog_handle *handle;
    struct nflog_g_handle *group_handle;
    int rv, nflog_filedesc, mmap_fd;
    char buf[4096];
    int nflog_group = -1;
    char daemonize = 0;
    char *filename = NULL;
    address_family = AF_UNSPEC;

    struct option longopts[] = {
        /* name, has_args, flag, val */
        {"daemonize", no_argument, NULL, 'd'},
        {"subnet", required_argument, NULL, 's'},
        {"nflog-group", required_argument, NULL, 'g'},
        {"filename", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    while ( (opt = getopt_long(argc, argv, "ds:g:f:a:hv", longopts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            printf("%s", help_text);
            exit(0);
            break;
        case 'v':
            printf("%s", version_text);
            exit(0);
            break;
        case 'f':
            filename = optarg;
            break;
        case 's': {
            char* iparg = (char *)strdup(optarg);
            char *maskarg;
            if ( (maskarg = strchr(iparg, '/')) ) {
                *maskarg = 0;
                maskarg++;
            }
            // try to parse as ipv4 and ipv6 address
            if ( inet_pton(AF_INET, iparg, &subnet_address4) != 1 ) {
                if ( inet_pton(AF_INET6, iparg, &subnet_address6) != 1 ) {
                    fprintf(stderr, "Invalid ip addresss\n");
                    exit(1);
                } else {
                    address_family = AF_INET6;
                }
            } else {
                address_family = AF_INET;
            }
            if ( maskarg )
                prefix_size = atoi(maskarg);
            if (address_family==AF_INET) {
                ASSERT( (prefix_size > 0) && (prefix_size <= 32), "Error: prefix must be in 1-32 range\n");
                mask4.s_addr = ntohl(0xffffffff << (32 - prefix_size) );
              }
            if (address_family==AF_INET6) {
                ASSERT( (prefix_size > 0) && (prefix_size <= 128), "Error: prefix must be in 1-128 range\n");
                mask6.s6_addr32[0] = ntohl(0xffffffff << POSITIV(32 - prefix_size));
                mask6.s6_addr32[1] = prefix_size>32 ? ntohl(0xffffffff << POSITIV(64 - prefix_size)) : 0;
                mask6.s6_addr32[2] = prefix_size>64 ? ntohl(0xffffffff << POSITIV(96 - prefix_size)) : 0;
                mask6.s6_addr32[3] = prefix_size>96 ? ntohl(0xffffffff << POSITIV(128 - prefix_size)) : 0;
            }
            break;
        }
        case 'g':
            nflog_group = atoi(optarg);
            break;
        case 'd':
            daemonize = 1;
            break;
        case '?':
            fprintf(stderr, "Unknown argument, see --help\n");
        exit(1);
        }
    }

    // verify arguments
    ASSERT(nflog_group != -1, "You must provide a nflog group (see --help)!\n");
    ASSERT(address_family != AF_UNSPEC, "You must provide a ipv4 or ipv6 subnet (see --help)\n");
    ASSERT(filename != NULL, "You must provide a filename (see --help)\n");

    // calculate size of table file
    char max_prefix_size = address_family == AF_INET ? 32 : 128;
    int aggregate_suffix = AF_INET ? 0 : 64; // only log /64 for ipv6 subnets
    num_counters = 1 << (max_prefix_size - prefix_size - aggregate_suffix);
    table_size = sizeof(struct table_header_t) + num_counters*sizeof(struct counter_entry_t);

    // register signal handler
    IF_ERROR(signal(SIGHUP, sig_handler) == SIG_ERR, "Could not set SIGHUP handler");

    // open file and map to memory
    IF_ERROR( (mmap_fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600)) == -1, "Could not open file" );
    IF_ERROR( lseek(mmap_fd, table_size - 1, SEEK_SET) == -1, "Could not seek to end of file" );
    IF_ERROR( write(mmap_fd, "", 1) == -1, "Could not write to end of file" );

    table_header = mmap(NULL, table_size, PROT_READ|PROT_WRITE, MAP_SHARED, mmap_fd, 0);
    ASSERT( table_header != MAP_FAILED, "Could not map file into memory");
    counters = ((void*)table_header) + sizeof(struct table_header_t);

    // initialize file
    table_header->version = 1;
    table_header->address_family = address_family;
    if (address_family == AF_INET)
        table_header->subnet.subnet_address4 = subnet_address4;
    else
        table_header->subnet.subnet_address6 = subnet_address6;
    table_header->prefix_size = prefix_size;
    table_header->start_time = time(NULL);
    memset(counters, 0, sizeof(struct counter_entry_t)*num_counters);

    // open nflog
    IF_ERROR( (handle = nflog_open())==NULL, "error during nflog_open()")
    IF_ERROR( nflog_bind_pf(handle, address_family) < 0, "error during nflog_bind_pf()");

    // bind to group
    group_handle = nflog_bind_group(handle, nflog_group);

    // only copy first 40 bytes of packet (ipv6 header size)
    IF_ERROR(nflog_set_mode(group_handle, NFULNL_COPY_PACKET, 40) < 0, "Could not set copy mode");

    // registering callback for group
    nflog_callback_register(group_handle, &handle_packet, NULL);

    // get file descriptor for receiving packets
    nflog_filedesc = nflog_fd(handle);

    debug_print("going into main loop\n");
    // main processing loop
    while ((rv = recv(nflog_filedesc, buf, sizeof(buf), 0)) && rv >= 0) {
        struct nlmsghdr *nlh;
        debug_print("nflog packet received (len=%u)\n", rv);

        /* handle messages in just-received packet */
        nflog_handle_packet(handle, buf, rv);
    }

    nflog_unbind_group(group_handle);

#ifdef INSANE
    /* norally, applications SHOULD NOT issue this command,
     * since it detaches other programs/sockets from AF_INET, too ! */
    printf( "unbinding from AF_INET\n" );
    nflog_unbind_pf( handle, AF_INET );
#endif

    printf( "closing handle\n" );
    nflog_close( handle );

    // cleanup counter table
    table_header->end_time = time( NULL );
    msync( table_header, table_size, MS_SYNC );
    munmap( table_header, table_size );
    close( mmap_fd );

    exit(0);
}

// vim: sw=4 expandtab
