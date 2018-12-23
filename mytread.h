#ifndef MYTREAD_H
#define MYTREAD_H

#include <QObject>
#include <QThread>
#include "getinfo.h"

class MyThread : public QThread
{
    Q_OBJECT
public:
    explicit MyThread(QObject *parent = 0);
    void stop();
    void set_listen_dev(int devid);
    int get_dev(){return listen_dev;}
    GETINFO* p_Info;
    void run();
protected:
private:
    volatile bool stopped;
    volatile int listen_dev;

signals:
void stringChanged(const QString &);

public slots:
};

#endif // MYTREAD_H
