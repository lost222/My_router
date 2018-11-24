#include "pcap.h"
#include <QVector>
#include <QString>
#include  <sys/types.h>
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif

#ifndef GETINFO_H
#define GETINFO_H


#pragma pack(1)

typedef struct FrameHeader_t {
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}FrameHeader_t;


typedef struct IPHeader_t{
    BYTE Ver_Hlen;
    BYTE TOS;
    WORD TotalLen;
    WORD ID;
    WORD Flag_Segment;
    BYTE TTL;
    BYTE Protocol;
    WORD Checksum;
    ULONG SrcIP;
    ULONG DesIP;
}IPHeader_t;

typedef struct Data_t{
    FrameHeader_t FrameHeade;
    IPHeader_t IPHeader;

}Data_t;

#pragma pack()




class GETINFO
{
private:
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
public:
    GETINFO();
    ~GETINFO(){pcap_freealldevs(alldevs);}
    QVector<QString> dev_list();
    QVector<QString> desc_list();
//    Data_t get_dev_packet(int devid);
    pcap_t* open_dev(int i);
    WORD cal_IP_checksum(Data_t *);

};


#endif // GETINFO_H
