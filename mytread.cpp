#include "mytread.h"
#include <QDebug>

MyThread::MyThread(QObject *parent) : QThread(parent)
{
    stopped = false;
    listen_dev = -1;
}


void MyThread::run()
{
    qreal i = 0;
    while (!stopped)
//        qDebug() << QString("in MyThread: %1").arg(i++);
    {
        if (this->listen_dev < 0){ continue; }
        QString str = QString("in MyThread: %1\n").arg(i);
        str = str + QString("listening to: ") + QString(this->listen_dev);
               emit stringChanged(str);
               msleep(1000);
               i++;
    }
    stopped = false;
    listen_dev = -1;
}

void MyThread::stop()
{
    stopped = true;
}

void MyThread::set_listen_dev(int devid)
{
    listen_dev = devid;
}
