# nflogtable

Traffic counter daemon

This program captures packets via the netfilter_log kernel interface and
counts the total transfered number bytes and the number of packets.
Accounting is done for a whole subnet on a per ip basis. Incoming and
outgoing traffic is counted separately. The counter table is written to
a file via memory mapping. The file format is specified below.


## Install

```
make
make install
```

If you need to debug the application (e. g. to see if packets come in), run `make debug`.


## Options

```
  -h --help                 print this help
  -v --version              print version information
     --nflog-group=<id>     nflog group
     --subnet=<ip/cidr>     ipv4 or ipv6 subnet to counter traffic for
     --filename=<path>      path to file for table
```

## Example usage

```
sudo iptables -I OUTPUT -j NFLOG --nflog-group 32
sudo ./nflogtable --nflog-group=32 --filename=test.tab --subnet=172.20.64.0/19
```


## File format

### Header

| Size   | Purpose                          |
| ------ |:--------------------------------:|
| 1      | Version (1)                      |
| 1      | IP-Version (AF_INET or AF_INET6) |
| 1      | prefix size                      |
| 5      | reserved for alignment           |
| 16     | Subnet (for v4 only first bytes) |
| 8      | Start time of statistic          |
| 8      | End time                         |

### Entry

| Size   | Purpose                 |
| ------ |:-----------------------:|
| 8      | # Sent Packets          |
| 8      | # Sent Bytes            |
| 8      | # Received Packets      |
| 8      | # Received Bytes        |
