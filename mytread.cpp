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
//        QString str = QString("in MyThread: %1\n").arg(i);
//        str = str + QString("listening to: ") + QString(this->listen_dev);
//               emit stringChanged(str);
//               msleep(1000);
//               i++;
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
        Data_t* IPPacket;

        BYTE* DESMAC;BYTE* SRCMAC;
        WORD* Frame_type;

        while((res = pcap_next_ex( dev, &header, &pkt_data)) >= 0 && !stopped){
                if(res == 0)
                    /* Timeout elapsed */
                    continue;

                /* convert the timestamp to readable format */
                local_tv_sec = header->ts.tv_sec;
                ltime=localtime(&local_tv_sec);
                strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
                IPPacket = (Data_t* ) pkt_data;
                DESMAC = IPPacket->FrameHeade.DesMAC;
                SRCMAC = IPPacket->FrameHeade.SrcMAC;

                Frame_type = &(IPPacket->FrameHeade.FrameType);
                WORD Frame_type_real = ntohs(*Frame_type);

                QString str = "";
                str.sprintf("%s,%.6d len:%d\nDESMAC:%x %x %x %x %x %x  "
                            "SRCMAC: %x %x %x %x %x %x\n"
                            "FRAME TYPE : %x",
                       timestr,
                       (int)header->ts.tv_usec,
                       header->len,
                       DESMAC[0],DESMAC[1],DESMAC[2],DESMAC[3],DESMAC[4],DESMAC[5],
                       SRCMAC[0],SRCMAC[1],SRCMAC[2],SRCMAC[3],SRCMAC[4],SRCMAC[5],
                       Frame_type_real
                      );
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
