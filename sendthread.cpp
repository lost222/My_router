#include "sendthread.h"

SendThread::SendThread(QObject *parent) : QThread(parent)
{

}

void SendThread::run()
{
    QMap<QString, unsigned int> ip_info = Info.get_IP_data(2);

    // send ARP INFO
    ARPFrame_t ARPFrame;
    //// FrameHeade
    BYTE* p = ARPFrame.FrameHeade.DesMAC;
    for(int i=0; i<6;i++){
        p[i] = 0xFF;
    }
    p = ARPFrame.FrameHeade.SrcMAC;
    QVector<BYTE> the_mac = p_Info->ip2mac(ip_info["Address"]);
    for(int i=0; i<6;i++){
        p[i] = the_mac[i];
    }
    ARPFrame.FrameHeade.FrameType = htons(0x0806);

    //// ARP DATA
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800); // 0x0816 ??
    ARPFrame.HLen = 6;  // MAC addr len
    ARPFrame.PLen = 4;  // IP addr len
    ARPFrame.Opareation = htons(0x0001);

    ARPFrame.SendIP = ip_info["Address"];
    p = ARPFrame.SendHa;
    for(int i=0; i<6;i++){
        p[i] = p[i] = the_mac[i];
    }

    ARPFrame.RecvIP =htonl( htonl(ip_info["Address"]) + 0x2 );
    p = ARPFrame.recvHa;
    for(int i=0; i<6;i++){
        p[i] = 0x00;
    }
    // send data
    pcap_t * dev = p_Info->open_dev(this->listen_dev);
    if ( pcap_sendpacket(dev, (u_char *)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        std::cout<<"ERR SENDING"<<std::endl;
    }else{
        std::cout<<"GOOD SEND !"<<std::endl;
    }

}
