#include "getinfo.h"


/* From tcptraceroute, convert a numeric IP address to a string */


//char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
//{
////    socklen_t sockaddrlen;
//    unsigned int sockaddrlen;
//    #ifdef WIN32
//    sockaddrlen = sizeof(struct sockaddr_in6);
//    #else
//    sockaddrlen = sizeof(struct sockaddr_storage);
//    #endif


//    if(getnameinfo(sockaddr,
//        sockaddrlen,
//        address,
//        addrlen,
//        NULL,
//        0,
//        NI_NUMERICHOST) != 0) address = NULL;

//    return address;
//}


GETINFO::GETINFO()
{
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }
//    QString ip_str = QString("192.168.1.1");
//    QStringList ips = ip_str.split('.');
//    unsigned int IP_Address = 0;
//    for(int i=0; i<4;i++){
//        IP_Address += ips[i].toInt()<<(24 - 8*i);
//    }
//    QVector<BYTE> m(6);
//    m[0]=0x00;m[1]=0x0c;m[2]=0x29;m[3]=0x47;m[4]=0xbf;m[5]=0x15;
//    this->ip_to_mac[IP_Address] = m;
//    ip_str = QString("192.168.1.3");
//    ips = ip_str.split('.');
//    IP_Address = 0;
//    for(int i=0; i<4;i++){
//        unsigned int ss = ips[i].toInt();
//        unsigned int ll = ss <<(24 - 8*i);
//        IP_Address += ll;
//    }
//    QVector<BYTE> mac(6);
//    mac[0]=0x00; mac[1]=0x0c;mac[2]=0x29;mac[3]=0x47;mac[4]=0xBF;mac[5]=0x1F;
//    this->ip_to_mac[IP_Address] = mac;

}


QVector<QString> GETINFO::dev_list()
{

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

QVector<BYTE> GETINFO::ip2mac(unsigned int ip){
//    unsigned long mac=0;
    printf("in ip2mac %s",this->iptos(ip));

    QVector<BYTE> mac(6);
//   if (ip_to_mac.contains(ip) ) {
//       return ip_to_mac[ip];
//   }
    return mac;
}



QMap<QString, unsigned int> GETINFO::get_IP_data(int i)
{
    d = alldevs;
    QMap<QString, unsigned int> result;
    for(int j=0; j<i;j++)
    {
       d = d->next;
    }
    /* IP addresses */
    pcap_addr_t* a;
    for(a=d->addresses;a;a=a->next) {
//      printf("\tAddress Family: #%d\n",a->addr->sa_family);

      switch(a->addr->sa_family)
      {
        case AF_INET: // IPV4
//          printf("\tAddress Family Name: AF_INET\n");
          if (a->addr){
//            printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
//            printf("\tAddress int %d\n",((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr);
            result["Address"] = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
          }
          if (a->netmask){
//            printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            result["Netmask"] = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
          }
          if (a->broadaddr){
//            printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            result["BroadcastAddr"] =((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr;
          }
          if (a->dstaddr){
//            printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));

            result["DestinationAddr"] = ((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr;
          }
          break;

        case AF_INET6:
//          printf("\tAddress Family Name: AF_INET6 need to be fixed here.\n");
//          if (a->addr)
//            printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
//         break;

        default:
//          printf("\tAddress Family Name: Unknownn do nothing here\n");
          break;
      }
    }
    return result;
}


char* GETINFO::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    // net
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

unsigned int IpStr_to_int(QString IpStr)
{
    QStringList ips = IpStr.split('.');
    unsigned int IP_Address = 0;
    for(int i=0; i<4;i++){
        IP_Address += ips[i].toInt()<<(24 - 8*i);
    }
    return IP_Address;
}
