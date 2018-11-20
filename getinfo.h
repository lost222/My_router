#include "pcap.h"
#include <QVector>
#include <QString>
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif

#ifndef GETINFO_H
#define GETINFO_H


class GETINFO
{
private:
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    GETINFO();
    QVector<QString> dev_list();
    QVector<QString> desc_list();

};


#endif // GETINFO_H
