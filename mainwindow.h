#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include"getinfo.h"
#include "mytread.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    GETINFO Info;
    void sendARP_base(unsigned int sendIP, QVector<BYTE> sendMac, unsigned int recvIP);
    void sendARP(unsigned int IP_Address);
    ~MainWindow();

private slots:
    void on_dev_list_currentRowChanged(int currentRow);

    void on_startButton_clicked();

    void on_stopButton_clicked();

    void changeString(const QString &);

    void on_GetButton_clicked();

    void on_BackButton_clicked();

private:
    Ui::MainWindow *ui;
    MyThread thread;
    int out2line;
};

#endif // MAINWINDOW_H
