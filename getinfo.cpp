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
    int j = 0;
    for(d=alldevs; d; d=d->next)
        {
//            printf("%d. %s", ++i, d->name);
        QString i = QString(d->name);
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
