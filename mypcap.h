#ifndef MYPCAP_H_
#define MYPCAP_H_

struct _timeval {
        uint32_t tv_sec;     /* seconds */
        uint32_t tv_usec;    /* microseconds */
};

struct _pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;    /* accuracy of timestamps */
	uint32_t snaplen;    /* max length saved portion of each pkt */
	uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

struct _pcap_pkthdr {
	struct _timeval ts;      /* time stamp using 32 bits fields */
	uint32_t caplen;     /* length of portion present */
	uint32_t len;        /* length this packet (off wire) */
};
static inline uint16_t bswap16(uint16_t x){
	return (uint16_t)(((x & 0x00ffU) << 8) |
		((x & 0xff00U) >> 8));
}
static inline uint32_t bswap32(uint32_t x){
    return  ((x & 0x000000ffUL) << 24) |
	((x & 0x0000ff00UL) << 8) |
	((x & 0x00ff0000UL) >> 8) |
	((x & 0xff000000UL) >> 24);
}
static inline uint64_t bswap64(uint64_t x){
	return  ((x & 0x00000000000000ffULL) << 56) |
		((x & 0x000000000000ff00ULL) << 40) |
		((x & 0x0000000000ff0000ULL) << 24) |
		((x & 0x00000000ff000000ULL) <<  8) |
		((x & 0x000000ff00000000ULL) >>  8) |
		((x & 0x0000ff0000000000ULL) >> 24) |
		((x & 0x00ff000000000000ULL) >> 40) |
		((x & 0xff00000000000000ULL) >> 56);
}
//write a pcap header to a new file. Called by openPcapFile. Shouldn't be used outside mypcap.c
//int PcapWriteHead(FILE * fp, int linktype, int thiszone, int snaplen);
//create a new pcap file and write pcap file or open an exsit pcap file and point to it's end.
int autoOpenPcapFile(const char * path);
int openPcapFile(const char * path, int linktype, int thiszone, int snaplen);
//write a packet into a pcap file.
int writePcap(int fd, char * buf,int len,struct timeval tv);
//close a pcap file.
 void closePcapFile(int fd);
#endif //end of mypcap.h