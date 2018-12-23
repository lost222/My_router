#include "pcap.h"
#include <QVector>
#include <QString>
#include  <sys/types.h>
#include <QMap>
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock2.h>
#endif
//#pragma comment(lib,"ws2_32.lib") //for vc++

#ifndef GETINFO_H
#define GETINFO_H
#define IPTOSBUFFERS    12

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

typedef struct ARPFrame_t{
    FrameHeader_t FrameHeade;
    WORD HardwareType;
    WORD ProtocolType;
    BYTE HLen;
    BYTE PLen;
    WORD Opareation;
    BYTE SendHa[6];
    DWORD SendIP;
    BYTE recvHa[6];
    DWORD RecvIP;
}ARPFrame_t;


#pragma pack()

unsigned int IpStr_to_int(QString IpStr);


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
    QVector<BYTE> ip2mac(unsigned int ip);

//    Data_t get_dev_packet(int devid);
    pcap_t* open_dev(int i);
    WORD cal_IP_checksum(Data_t *);
    QMap<QString, unsigned int> get_IP_data(int i);

    char *iptos(u_long in);

};


#endif // GETINFO_H
