#include "mainwindow.h"
#include "ui_mainwindow.h"
#include"getinfo.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->label1->setText("HELLOW WORLD");
    GETINFO Info;
    QVector<QString> dev_list = Info.dev_list();
    for(int i=0; i<dev_list.size(); i++){
        ui->ma_text->append(dev_list[i]);
    }
}



MainWindow::~MainWindow()
{
    delete ui;
}
