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
    QVector<QString> dev_list = Info.dev_list();
    for(int i=0; i<dev_list.size(); i++){
        ui->dev_list->insertItem(i, dev_list[i]);
    }
    out2line = 0;
    thread.p_Info = &Info;
    // connect mythread to mainWindow
    connect(&thread, SIGNAL(stringChanged(QString)),
    this, SLOT(changeString(QString)));

}



MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_dev_list_currentRowChanged(int currentRow)
{
    QVector<QString> dev_decs = Info.desc_list();

    thread.set_listen_dev(currentRow);
    QString str = QString("Listening ON DEV %1").arg(currentRow);
    ui->info_list->insertItem(out2line++,str);

    QMap<QString, unsigned int> ip_data = Info.get_IP_data(currentRow);
    QString out = dev_decs[currentRow];
    ui->desc_info->setText(out);
    QMap<QString, unsigned int>::iterator i;
    for(i=ip_data.begin(); i != ip_data.end(); i++){
        out.sprintf("%s : %s", i.key().toStdString().c_str(), Info.iptos(i.value()));
        ui->desc_info->append(out);
    }
    unsigned int ip_addr = ip_data["Address"];
    QVector<BYTE> mac = Info.ip2mac(ip_addr);
    out.sprintf("MAC : %x-%x-%x-%x-%x-%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ui->desc_info->append(out);

}

void MainWindow::sendARP_base(unsigned int sendIP, QVector<BYTE> sendMac, unsigned int recvIP)
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
    pcap_t * dev = Info.open_dev(thread.get_dev());
    if ( pcap_sendpacket(dev, (u_char *)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        std::cout<<"ERR SENDING"<<std::endl;
    }else{
        std::cout<<"GOOD SEND !"<<std::endl;
    }
}

void MainWindow::sendARP(unsigned int IP_Address)
{
    QMap<QString, unsigned int> ip_info = Info.get_IP_data(thread.get_dev());
    unsigned int sendIP = ip_info["Address"];
    //QVector<BYTE> send_mac = Info.ip2mac(ip_info["Address"]);
    QVector<BYTE> send_mac_ram(6);
    for(int i=0;i<6;i++){
        send_mac_ram[i] = 0x0f;
    }
    sendARP_base(0xf0f00,send_mac_ram,sendIP);
    thread.start();
    while(!(this->Info.ip_to_mac.contains(sendIP))); //busy wait
    QVector<BYTE> send_mac = Info.ip_to_mac.value(sendIP);

    sendARP_base(sendIP,send_mac, IP_Address);

}

void MainWindow::changeString(const QString &str)
{

    ui->info_list->insertItem(out2line++,str);


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
    this->sendARP(IP_Address);
    ui->GetButton->setEnabled(false);
    ui->BackButton->setEnabled(true);

}

void MainWindow::on_BackButton_clicked()
{
    if (thread.isRunning()) {
        thread.stop();
        ui->GetButton->setEnabled(true);
        ui->BackButton->setEnabled(false);
    }

}
