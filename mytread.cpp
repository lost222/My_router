#include "mytread.h"
#include <QDebug>

MyThread::MyThread(QObject *parent) : QThread(parent)
{
    stopped = false;
    listen_dev = -1;
    p_Info = NULL;
}


void MyThread::run()
{
//    qreal i = 0;
    while (!stopped)
//        qDebug() << QString("in MyThread: %1").arg(i++);
    {
        if (this->listen_dev < 0){ continue; }
        pcap_t* dev = p_Info->open_dev(this->listen_dev);
        if (dev == NULL)
        {
            QString errstr = QString("can't open device!");
            emit stringChanged(errstr);
        }
        struct tm *ltime;
        char timestr[16];
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        time_t local_tv_sec;
        int res = 0;

        ARPFrame_t* IPPacket;
        BYTE* DESMAC;BYTE* SRCMAC;
        WORD* Frame_type;

        while((res = pcap_next_ex( dev, &header, &pkt_data)) >= 0 && !stopped){
                if(res == 0)
                    /* Timeout elapsed */
                    continue;

                IPPacket = (ARPFrame_t* ) pkt_data;
                DESMAC = IPPacket->FrameHeade.DesMAC;
                SRCMAC = IPPacket->FrameHeade.SrcMAC;
                Frame_type = &(IPPacket->FrameHeade.FrameType);
                WORD Frame_type_real = ntohs(*Frame_type);
                if (Frame_type_real == 0x0806){
                    deal_with_arp_datagram(IPPacket);
                } else if (Frame_type_real == 0x0800){
//                    printf("\t%d\n",res);
                    deal_with_other_datagram((Data_t*)pkt_data);
                }
            }
            if(res == -1){
                QString errstr = "";
                errstr.sprintf("Error reading the packets: %s\n", pcap_geterr(dev));
                emit stringChanged(errstr);
            }
    }
    stopped = false;
}

void MyThread::stop()
{
    stopped = true;
}

void MyThread::set_listen_dev(int devid)
{
    listen_dev = devid;
}


void MyThread::deal_with_arp_datagram(ARPFrame_t *IPPacket)
{
    BYTE* r_mac;
    DWORD r_ip;
    r_mac = (BYTE *)&(IPPacket->recvHa);
    bool is_ze = true;
    for(int i=0;i<6;i++){
        if(r_mac[i] != 0){is_ze = false;}
    }
    if(is_ze){return;}

    // change 2 send
    r_ip = ntohl(IPPacket->SendIP); //don't know why but no need to trans


    QVector<BYTE> mac_vec(6);
    r_mac = (BYTE *)&(IPPacket->SendHa);
    for(int i=0; i<6;i++){
        mac_vec[i] = r_mac[i];
    }
    if ( arp_table.contains(r_ip) && arp_table.value(r_ip) == mac_vec ){return;}

    arp_table[r_ip] = mac_vec;

    QString str = "";
    str.sprintf("%s  -->  %x-%x-%x-%x-%x-%x",p_Info->iptos(htonl(r_ip)),
                r_mac[0], r_mac[1], r_mac[2], r_mac[3], r_mac[4], r_mac[5]);
    emit get_arp_datagram(str);
}


void MyThread::deal_with_other_datagram(Data_t *IPPacket)
{
    unsigned int fromIP = ntohl(IPPacket->IPHeader.SrcIP);
    unsigned int toIp = ntohl(IPPacket->IPHeader.DesIP);
    QString fromIpstr = QString(p_Info->iptos(IPPacket->IPHeader.SrcIP));
    QString toIpstr = QString(p_Info->iptos(IPPacket->IPHeader.DesIP));
    QString thstr = QString(p_Info->iptos(htonl(this->listenIp)));

    // 来源IP不在我的管辖区域
    int ans = check_route_table(fromIP);
    if (ans == -1) {return ;}

    //去往IP在我的管辖范围
    int ans2 = check_route_table(toIp);
    if( ans2 != -1) {return ;}

    // 目的MAC 不是我
    if (arp_table.contains(listenIp)) {
        BYTE *desMac = IPPacket->FrameHeade.DesMAC;
        QVector<BYTE> my_MAC = arp_table.value(listenIp);
//        bool isSendToMe = true;
        for(int i=0; i<6; i++){
            if (my_MAC.at(i) != desMac[i]) {
                return ;
            }
        }
    }

    emit trans_datagram(IPPacket);
}


int MyThread::check_route_table(unsigned int ip)
{

    QVector<unsigned int> results;
    for(int i=0; i<route_table.size();i++) {
        unsigned int netId = ip&route_table[i].at(1);
        if (netId == route_table[i].at(0)) {
            results.append(i);
        }
    }
    if (results.size() == 0) {
        return -1;
    }
    int realResult = results.at(0);
    for(int i=0; i<results.size(); i++) {
        int row = results.at(i);
        if ( route_table.at(realResult).at(1) < route_table.at(row).at(1) ) {
            realResult = row ;
        }
    }
    return realResult;

}


int MyThread::find_route_info(QVector<unsigned int> &info)
{
    for(int i=0; i<route_table.size();i++) {
        QVector<unsigned int> re = route_table.at(i);
        if(re.at(0)==info.at(0) && re.at(1)==info.at(1) && re.at(2) == info.at(2)) {
            return i;
        }
    }
    return -1;
}
