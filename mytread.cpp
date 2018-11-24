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
        BYTE* r_mac;
        DWORD r_ip;

        while((res = pcap_next_ex( dev, &header, &pkt_data)) >= 0 && !stopped){
                if(res == 0)
                    /* Timeout elapsed */
                    continue;

                IPPacket = (ARPFrame_t* ) pkt_data;
                DESMAC = IPPacket->FrameHeade.DesMAC;
                SRCMAC = IPPacket->FrameHeade.SrcMAC;
                Frame_type = &(IPPacket->FrameHeade.FrameType);
                WORD Frame_type_real = ntohs(*Frame_type);
                if (Frame_type_real != 0x0806) {continue;}

                // get IP -> Mac
                QString str = "";
                r_mac = (BYTE *)&(IPPacket->recvHa);
                r_ip = IPPacket->RecvIP; //don't know why but no need to trans
                str.sprintf("%s  -->  %x-%x-%x-%x-%x-%x",p_Info->iptos(r_ip),
                            r_mac[0], r_mac[1], r_mac[2], r_mac[3], r_mac[4], r_mac[5]);
                emit stringChanged(str);
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
