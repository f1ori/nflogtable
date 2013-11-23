# nflogtable

Traffic counter daemon

## File format

### Header

| Size   | Purpose                          |
| ------ |:--------------------------------:|
| 1      | Version (1)                      |
| 1      | IP-Version (AF_INET or AF_INET6) |
| 1      | prefix size                      |
| 1      | Resolution                       |
| 4      | reserved for alignment           |
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
