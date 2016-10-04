### Introduce

A common c/cpp api for dump network traffics as pcap file.

### API 
create a new pcap file with specified linktype, timezone and snaplen. If the file is exsit, it will open in append mode.  
`int openPcapFile(const char * path, int linktype, int thiszone, int snaplen);`  
create a new pcap file with linktype `DLT_EN10MB`, timezone `0` and snaplen `65535`. If the file is exsit, it will open in append mode.  
 `int autoOpenPcapFile(const char * path);`  
write a buf into the pcap file. Notice that you need to provide the timestamp.  
`int writePcap(int fd, char * buf,int len,struct timeval tv);`  
Close a pcap file.  
`void closePcapFile(int fd);`  

### Usage

First open the file.  
`fd = openPcapFile("test.pcap",1,0,65535);`  
Then you can capture your packets. Here I used it in DPDK. So my packet `buf`'s format is `struct rte_mbuf *`.
So I call the function as the following:  
`writePcap(fd,rte_pktmbuf_mtod(bufs,struct ether_hdr *),bufs->pkt_len,tv);`  
`rte_pktmbuf_mtod(bufs,struct ether_hdr *)` and `bufs->pkt_len` means the ether packet's true head ptr and true size of the packets in DPDK. `tv` is timestamp.
After all, close the file.  
`closePcapFile(fd);`

### Notice 
If you want to write your own pcap dumper. Please notice the size of timestamp in pcap_header.
In x64 system, the size of `struct timeval` is 16. But in pcap format, the space for `struct timeval` is 8.
So you need to define your own pcap struct to avoid the possible mismatch bit.

