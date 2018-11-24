#include "getinfo.h"


GETINFO::GETINFO()
{
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }
}


QVector<QString> GETINFO::dev_list()
{
    // 没有申请内存,不知道会有什么情况
    QVector<QString> result;

    for(d=alldevs; d; d=d->next)
        {
//            printf("%d. %s", ++i, d->name);
        QString i = QString(d->name);
        result<<i;
    }
    return result;
}

QVector<QString> GETINFO::desc_list()
{
    QVector<QString> result;
    for(d=alldevs;d;d=d->next){
        QString i = "";
        if(d->description)
            {
                i =i + QString(d->description) + "\n";
            }else{
                i = i + "(No description available)\n";
            }
//                result[j] = i;j++;
                  result<<i;
            }
    return result;
}

pcap_t *GETINFO::open_dev(int i)
{
     pcap_t* result_dev = NULL;
     d = alldevs;
     for(int j=0; j<i;j++)
     {
        d = d->next;
     }
     if ( (result_dev= pcap_open(d->name,          // name of the device
                                   65536,            // portion of the packet to capture.
                                                     // 65536 guarantees that the whole packet will be captured on all the link layers
                                   PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                                   1000,             // read timeout
                                   NULL,             // authentication on the remote machine
                                   errbuf            // error buffer
                                   ) ) == NULL)
         {
             return NULL;
         }
     return result_dev;
}

WORD GETINFO::cal_IP_checksum(Data_t * p_data)
{
    unsigned int sum=0;
    BYTE* Start = (BYTE* )&(p_data->IPHeader);
    for(int i=0; i< 10; i+=2){
        // problem here
        sum += *(Start+i+1)*256 + *(Start+i);
    }
    unsigned int outflow = sum >> 16;
    while(outflow){
        sum += outflow;
        outflow = sum >> 16;
    }
    WORD result = (WORD) sum&0xffff;
    return result;
}
