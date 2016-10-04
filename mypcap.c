#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h>
#include <fcntl.h>
#include "mypcap.h"
#define DEBUG 1
#if DEBUG 
#define DBG(var, ...) printf(var, __VA_ARGS__)
#else 
#define DBG(var, ...) //printf(var, __VA_ARGS__)
#endif


int PcapWriteHead(int fd, int linktype, int thiszone, int snaplen){
    struct _pcap_file_header hdr;
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;
    int left = sizeof(hdr),ret;
    char * ptr = &hdr;
    while(left>0){
        ret = write(fd,ptr,left);
        left -=ret;
        ptr += ret;
    }
    fsync(fd);
    return 0;
}

int writePcap(int fd, char * buf,int len,struct timeval tv){
    struct _pcap_pkthdr h;
   // char mem[65535];
    if(len>65535){
        len = 65535;
    }
    int left = sizeof(h),ret;
    h.ts.tv_sec = (uint32_t)tv.tv_sec;
    h.ts.tv_usec = (uint32_t)tv.tv_usec;

    h.caplen = len;
    h.len = len;

    char * ptr = &h;
    while(left>0){
        ret = write(fd,ptr,left);
        left -= ret;
        ptr += ret;

    }

    left = len;
    while(left >0){
        ret = write(fd,buf,left);
        buf += ret;
        left -= ret;

    }
    return 0;
}

 int openPcapFile(const char * path, int linktype, int thiszone, int snaplen){
     int fd;
    fd = open(path,O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
    if(fd == -1)return fd;
    int pos =lseek(fd,0,SEEK_END);
    if (pos == -1)return -1;
    if(pos ==0){
        PcapWriteHead(fd,linktype,thiszone,snaplen);
    }
     return fd;
 }

int autoOpenPcapFile(const char * path){
    return openPcapFile(path,1,0,65535);
}


 void closePcapFile(int fd){

     close(fd);
 }