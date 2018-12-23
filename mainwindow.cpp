#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "getinfo.h"
#include<iostream>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->label_devs->setText("DEVS");
    ui->label_desc->setText("Describe Info");
    ui->label_ipinput->setText("INPUT IP");
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


    QVector<unsigned int> routeinfo(3);
    routeinfo[0] = IpStr_to_int(QString("192.168.2.0"));
    routeinfo[1] = IpStr_to_int(QString("255.255.255.0"));
    routeinfo[2] = IpStr_to_int(QString("192.168.2.0"));
    thread.route_table.append(routeinfo);

    adapter2.p_Info = &Info;
    adapter2.set_listen_dev(2);
    ip_info = Info.get_IP_data(adapter2.get_dev());
    adapter2.listenIp = ntohl(ip_info["Address"]);
    QVector<unsigned int> routeinfo2(3);
    routeinfo2[0] = IpStr_to_int(QString("192.168.1.0"));
    routeinfo2[1] = IpStr_to_int(QString("255.255.255.0"));
    routeinfo2[2] = IpStr_to_int(QString("192.168.1.0"));
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
        std::cout<<"GOOD SEND !"<<std::endl;
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

    QMap<QString, unsigned int> ip_info = Info.get_IP_data(send_adapter->get_dev());
    unsigned int sendIP = ip_info["Address"];
    sendIP = ntohl(sendIP);

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
        std::cout<<"GOOD SEND !"<<std::endl;
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
    QString ip_str = ui->IP_input->text();
    QStringList ips = ip_str.split('.');
    unsigned int IP_Address = 0;
    for(int i=0; i<4;i++){
        IP_Address += ips[i].toInt()<<(24 - 8*i);
    }
    std::cout<<ip_str.toStdString()<<" "<<IP_Address<<std::endl;
//    this->sendARP(IP_Address);
    ui->GetButton->setEnabled(false);
    ui->BackButton->setEnabled(true);

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
//    if (to_ip == thread.listenIp || to_ip == adapter2.listenIp ) {
//        return ;
//    }

//    if (from_ip == thread.listenIp || from_ip == adapter2.listenIp ) {
//        return ;
//    }


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
