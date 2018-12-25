#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "getinfo.h"
#include<iostream>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->label_devs->setText("Adapter1 route table");
    ui->label_desc->setText("Adapter2 route table");

//    GETINFO Info;
//    QVector<QString> dev_list = Info.dev_list();
//    for(int i=0; i<dev_list.size(); i++){
//        ui->dev_list->insertItem(i, dev_list[i]);
//    }
    out2line = 0;
    thread.p_Info = &Info;
    thread.set_listen_dev(1);
    QMap<QString, unsigned int> ip_info = Info.get_IP_data(thread.get_dev());
    thread.listenIp = ntohl(ip_info["Address"]);

    unsigned int base_mark = IpStr_to_int(QString("255.255.255.0"));
    unsigned int base_net = thread.listenIp & base_mark;


    QVector<unsigned int> routeinfo(3);
    routeinfo[0] = base_net;
    routeinfo[1] = base_mark;
    routeinfo[2] = base_net;
    thread.route_table.append(routeinfo);

    unsigned int wr_ip = IpStr_to_int(QString("206.1.3.0"));
    unsigned int next_ip = IpStr_to_int(QString("206.1.2.2"));
    QVector<unsigned int> routeinfo_wr(3);
    routeinfo_wr[0] = wr_ip;
    routeinfo_wr[1] = base_mark;
    routeinfo_wr[2] = next_ip;
    thread.route_table.append(routeinfo_wr);




    adapter2.p_Info = &Info;
    adapter2.set_listen_dev(2);
    ip_info = Info.get_IP_data(adapter2.get_dev());
    adapter2.listenIp = ntohl(ip_info["Address"]);
    unsigned int base_2_net = adapter2.listenIp & base_mark;

    QVector<unsigned int> routeinfo2(3);
    routeinfo2[0] = base_2_net;
    routeinfo2[1] = base_mark;
    routeinfo2[2] = base_2_net;
    adapter2.route_table.append(routeinfo2);


    // connect mythread to mainWindow
    connect(&thread, SIGNAL(stringChanged(QString)),
    this, SLOT(changeString(QString)));
    connect(&adapter2, SIGNAL(stringChanged(QString)),
    this, SLOT(changeString(QString)));

    connect(&thread, SIGNAL(get_arp_datagram(QString)),
    this, SLOT(changeString(QString)));
    connect(&adapter2, SIGNAL(get_arp_datagram(QString)),
    this, SLOT(changeString(QString)));

    connect(&thread, SIGNAL(trans_datagram(struct Data_t *)),
    this, SLOT(deal_trans_datagram(struct Data_t *)));
    connect(&adapter2, SIGNAL(trans_datagram(struct Data_t *)),
    this, SLOT(deal_trans_datagram(struct Data_t *)));


    thread.start();
    adapter2.start();

}



MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_dev_list_currentRowChanged(int currentRow)
{
//    QVector<QString> dev_decs = Info.desc_list();

//    //thread.set_listen_dev(currentRow);
//    QString str = QString("Listening ON DEV %1").arg(currentRow);
//    ui->info_list->insertItem(out2line++,str);

//    QMap<QString, unsigned int> ip_data = Info.get_IP_data(currentRow);
//    QString out = dev_decs[currentRow];
//    ui->desc_info->setText(out);
//    QMap<QString, unsigned int>::iterator i;
//    for(i=ip_data.begin(); i != ip_data.end(); i++){
//        out.sprintf("%s : %s", i.key().toStdString().c_str(), Info.iptos(i.value()));
//        ui->desc_info->append(out);
//    }
//    unsigned int ip_addr = ip_data["Address"];

//    QVector<BYTE> mac = Info.ip2mac(ip_addr);
//    out.sprintf("MAC : %x-%x-%x-%x-%x-%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
//    ui->desc_info->append(out);
    return ;

}

void MainWindow::sendARP_base(unsigned int sendIP, QVector<BYTE> sendMac, unsigned int recvIP, int adapterNum)
{
    //QMap<QString, unsigned int> ip_info = Info.get_IP_data(thread.get_dev());

    // send ARP INFO
    ARPFrame_t ARPFrame;
    //// ARPFrame.FrameHeade
    BYTE* p = ARPFrame.FrameHeade.DesMAC;
    for(int i=0; i<6;i++){
        p[i] = 0xFF;
    }
    p = ARPFrame.FrameHeade.SrcMAC;
//    QVector<BYTE> the_mac = Info.ip2mac(ip_info["Address"]);
    for(int i=0; i<6;i++){
        p[i] = sendMac[i];
    }
    ARPFrame.FrameHeade.FrameType = htons(0x0806);

    //// ARP DATA
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800); //
    ARPFrame.HLen = 6;  // MAC addr len
    ARPFrame.PLen = 4;  // IP addr len
    ARPFrame.Opareation = htons(0x0001);

//    ARPFrame.SendIP = ip_info["Address"];
    ARPFrame.SendIP = htonl(sendIP);

    p = ARPFrame.SendHa;
    for(int i=0; i<6;i++){
        p[i] = p[i] = sendMac[i];
    }

    ARPFrame.RecvIP =htonl(recvIP);
    p = ARPFrame.recvHa;
    for(int i=0; i<6;i++){
        p[i] = 0x00;
    }
    // send data
    pcap_t * dev = NULL;
    if (adapterNum == 1){
        dev = Info.open_dev(thread.get_dev());
    }else if (adapterNum == 2) {
        dev = Info.open_dev(adapter2.get_dev());
    }
    if ( pcap_sendpacket(dev, (u_char *)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        std::cout<<"ERR SENDING"<<std::endl;
    }else{
        std::cout<<"GOOD SEND ! WHO IS"<<Info.iptos(htonl(recvIP))<<std::endl;
    }
}

void MainWindow::sendARP(unsigned int IP_Address, int adapterNum)
{
    MyThread *send_adapter;
    if (adapterNum == 1){
        send_adapter = &thread;
    } else if (adapterNum == 2) {
        send_adapter = &adapter2;
    }

    //QMap<QString, unsigned int> ip_info = Info.get_IP_data(send_adapter->get_dev());
    //unsigned int sendIP = ip_info["Address"];
    unsigned int sendIP = send_adapter->listenIp;

    //sendIP = ntohl(sendIP);

    QVector<BYTE> send_mac_ram(6);
    for(int i=0;i<6;i++){
        send_mac_ram[i] = 0x0f;
    }

    // 判断自己的apr表里有没有自己


//    sendARP_base(IP_Address,send_mac_ram,sendIP,adapterNum);
//    sendARP_base(fake_ip,send_mac_ram,sendIP);
//    thread.run();

    while(!(send_adapter->arp_table.contains(sendIP))){
        sendARP_base(IP_Address,send_mac_ram,sendIP, adapterNum);
        Sleep(500);
        printf("busy waiting for my MAC\n");
    }
        //busy wait

    QVector<BYTE> send_mac = send_adapter->arp_table.value(sendIP);

//    sendARP_base(sendIP,send_mac, IP_Address, adapterNum);

    while(!(send_adapter->arp_table.contains(IP_Address))){
        sendARP_base(sendIP,send_mac, IP_Address, adapterNum);
        Sleep(500);
        printf("busy waiting for DesIP MAC\n");
    }

}

void MainWindow::send_data_use_ip(unsigned int IP_Address, Data_t *datagram, unsigned int lenth, int adapterNum)
{
    MyThread *send_adapter;
    if (adapterNum == 1){
        send_adapter = &thread;
    } else if (adapterNum == 2) {
        send_adapter = &adapter2;
    }


    // get my mac
    //get mac in IP_Address

    if (!send_adapter->arp_table.contains(IP_Address)) {
        sendARP(IP_Address, adapterNum);
    }



    // change datagram->FrameHeade srcMac and desMac
    QMap<QString, unsigned int> ip_info = Info.get_IP_data(send_adapter->get_dev());
    unsigned int sendIP = ip_info["Address"];
    sendIP = ntohl(sendIP);
    QVector<BYTE> sendMAC = send_adapter->arp_table.value(sendIP);
    QVector<BYTE> toMAC = send_adapter->arp_table.value(IP_Address);

    BYTE *p = datagram->FrameHeade.SrcMAC;
    for(int i=0; i<6;i++) {
        p[i] = sendMAC.at(i);
    }
    p = datagram->FrameHeade.DesMAC;
    for(int i=0; i<6; i++) {
        p[i] = toMAC.at(i);
    }
    pcap_t * dev = NULL;
    dev = Info.open_dev(send_adapter->get_dev());

    // send datagram
    if ( pcap_sendpacket(dev, (u_char *)datagram, lenth) != 0)
    {
        std::cout<<"ERR SENDING"<<std::endl;
    }else{
        std::cout<<"TRANS DATA TO"<<Info.iptos(IP_Address)<<std::endl;
        QString transInfo =QString("Trans data TO  ") + QString("").sprintf("%s use adapter %d", Info.iptos(htonl(IP_Address)), send_adapter->get_dev());
        this->ui->info_list->insertItem(out2line++,transInfo);
    }

}


void MainWindow::changeString(const QString &str)
{

    if (out2line < 100) {
        ui->info_list->insertItem(out2line++,str);

    }


}

void MainWindow::on_GetButton_clicked()
{
    QString code_str = ui->IP_input->text();
    QStringList ips = code_str.split(' ');
    if (ips[0] == QString("add") && ips.size()>3) {
        QString ip_str = ips.at(1);
        unsigned int ipnet = IpStr_to_int(ip_str);
        QString mask_str = ips.at(2);
        unsigned int mask = IpStr_to_int(mask_str);
        QString next_str = ips.at(3);
        unsigned int next_jump = IpStr_to_int(next_str);
        if (thread.check_route_table(next_jump) > -1 ) {
            QVector<unsigned int> route_info(3);
            route_info[0] = ipnet; route_info[1] = mask; route_info[2] = next_jump;
            thread.route_table.append(route_info);
        } else if (adapter2.check_route_table(next_jump) > -1) {
            QVector<unsigned int> route_info(3);
            route_info[0] = ipnet; route_info[1] = mask; route_info[2] = next_jump;
            adapter2.route_table.append(route_info);
        }

    }else if (ips[0] == QString("del") && ips.size()>3) {
        QString ip_str = ips.at(1);
        unsigned int ipnet = IpStr_to_int(ip_str);
        QString mask_str = ips.at(2);
        unsigned int mask = IpStr_to_int(mask_str);
        QString next_str = ips.at(3);
        unsigned int next_jump = IpStr_to_int(next_str);
        QVector<unsigned int> route_info(3);
        route_info[0] = ipnet; route_info[1] = mask; route_info[2] = next_jump;
        int where = thread.find_route_info(route_info);
        int where2 = adapter2.find_route_info(route_info);
        if (where > -1) {
            thread.route_table.remove(where);
        } else if (where2 > -1) {
            adapter2.route_table.remove(where);
        }

    }
    this->show_route_table();
//    ui->GetButton->setEnabled(false);
    ui->BackButton->setEnabled(true);
    if (!thread.arp_table.contains(thread.listenIp)) {
        QVector<BYTE> send_mac_ram(6);
        for(int i=0;i<6;i++){
            send_mac_ram[i] = 0x0f;
        }
        sendARP_base(ntohl(thread.listenIp+1),send_mac_ram,thread.listenIp, thread.get_dev());
        sendARP_base(ntohl(adapter2.listenIp+1),send_mac_ram,adapter2.listenIp, adapter2.get_dev());
    }


}

void MainWindow::on_BackButton_clicked()
{
    if (thread.isRunning()) {
        thread.stop();
    }
    if (adapter2.isRunning()) {
        adapter2.stop();
    }
    ui->GetButton->setEnabled(true);
    ui->BackButton->setEnabled(false);

}

//void MainWindow::when_time_out()
//{
//    this->sendARP_base();
//}

void MainWindow::Sleep(int msec)
{
    QTime dieTime = QTime::currentTime().addMSecs(msec);
    while( QTime::currentTime() < dieTime )
        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
}

//typedef struct IPHeader_t{
//    BYTE Ver_Hlen;
//    BYTE TOS;
//    WORD TotalLen;
//    WORD ID;
//    WORD Flag_Segment;
//    BYTE TTL;
//    BYTE Protocol;
//    WORD Checksum;
//    ULONG SrcIP;
//    ULONG DesIP;
//}IPHeader_t;

void MainWindow::deal_trans_datagram(Data_t *datagram)
{
    unsigned int len = ntohs(datagram->IPHeader.TotalLen) + sizeof(FrameHeader_t);
    unsigned int to_ip = ntohl(datagram->IPHeader.DesIP);
    unsigned int from_ip = ntohl(datagram->IPHeader.SrcIP);

    //

//    if (from_ip == thread.listenIp || from_ip == adapter2.listenIp ) {
//        return ;
//    }

    if (to_ip == thread.listenIp || to_ip == adapter2.listenIp ) {
//        int adpterNum = recv_adapter->get_dev();
//        send_data_use_ip(to_ip, datagram, len, adpterNum);
        return ;
    }

    MyThread * recv_adapter = (MyThread *)sender();

    QString fromIp = QString(Info.iptos(datagram->IPHeader.SrcIP));
    QString toIpstr = QString(Info.iptos(datagram->IPHeader.DesIP));
    QString fromD = QString("trans_data from ip ") +
            fromIp+
            QString(" from Adapter %0").arg(recv_adapter->get_dev());

    if (recv_adapter->get_dev() == thread.get_dev()) {
        if (out2line < 100) {
            this->ui->info_list->insertItem(out2line++,fromD);
        }
    } else if (recv_adapter->get_dev() == adapter2.get_dev()) {
        if (out2line < 100) {
            this->ui->info_list->insertItem(out2line++,fromD);
        }
    }


    // 不转发目的是本地的



    // 查表
    int where = thread.check_route_table(to_ip);
    if ( where > -1 ) {

        //是否直接投递
        if(thread.route_table[where].at(0) == thread.route_table[where].at(2) ) {

            send_data_use_ip(to_ip, datagram, len, 1);
        } else {
            // 不是直接投递
            send_data_use_ip(thread.route_table[where].at(2), datagram, len, 1);
        }
    }

    int where2 = adapter2.check_route_table(to_ip);
    if ( where2 > -1) {

        if(adapter2.route_table[where2].at(0) == adapter2.route_table[where2].at(2) ) {
            send_data_use_ip(to_ip, datagram, len, 2);
        } else {
            // 不是直接投递
            send_data_use_ip(adapter2.route_table[where2].at(2), datagram, len, 2);
        }
    }


}



void MainWindow::show_route_table()
{
    this->ui->thread_route->clear();
    this->ui->adapter2_route->clear();

    for(int i=0; i<thread.route_table.size();i++) {
        QVector<unsigned int> inf = thread.route_table.at(i);
        QString route_info = QString("").sprintf("%s    ;MASK %s;   %s",
                                                 Info.iptos(htonl(inf.at(0))),
                                                            Info.iptos(htonl(inf.at(1))),
                                                                       Info.iptos(htonl(inf.at(2))));
        this->ui->thread_route->insertItem(i,route_info);
    }
    for(int i=0; i<adapter2.route_table.size();i++) {
        QVector<unsigned int> inf = adapter2.route_table.at(i);
        QString route_info = QString("").sprintf("%s    ;MASK %s;   %s",
                                                 Info.iptos(htonl(inf.at(0))),
                                                            Info.iptos(htonl(inf.at(1))),
                                                                       Info.iptos(htonl(inf.at(2))));
        this->ui->adapter2_route->insertItem(i,route_info);
    }
}
