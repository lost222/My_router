#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include"getinfo.h"
#include "mytread.h"
#include <QTime>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    GETINFO Info;
    void sendARP_base(unsigned int sendIP, QVector<BYTE> sendMac, unsigned int recvIP, int adapterNum);
    void sendARP(unsigned int IP_Address, int adapterNum);
    void send_data_use_ip(unsigned int IP_Address, Data_t* datagram, unsigned int lenth, int adapterNum);
    void show_route_table();
    void Sleep(int msec);
    ~MainWindow();

private slots:
    void on_dev_list_currentRowChanged(int currentRow);

    void on_startButton_clicked();

    void on_stopButton_clicked();

    void changeString(const QString &);

    void on_GetButton_clicked();

    void on_BackButton_clicked();

    void deal_trans_datagram(struct Data_t *);




private:
    Ui::MainWindow *ui;
    MyThread thread;
    MyThread adapter2;
    int out2line;

};

#endif // MAINWINDOW_H
