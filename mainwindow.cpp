#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "getinfo.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->label_devs->setText("DEVS");
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
    ui->desc_info->setText(dev_decs[currentRow]);
    thread.set_listen_dev(currentRow);
    QString str = QString("Listening ON DEV %1").arg(currentRow);
    ui->info_list->insertItem(out2line++,str);
}

void MainWindow::on_startButton_clicked()
{
    thread.start();
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

}

void MainWindow::on_stopButton_clicked()
{
    if (thread.isRunning()) {
            thread.stop();
            ui->startButton->setEnabled(true);
            ui->stopButton->setEnabled(false);
        }
}

void MainWindow::changeString(const QString &str)
{
    ui->info_list->insertItem(out2line++,str);
}
