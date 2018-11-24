#ifndef SENDTHREAD_H
#define SENDTHREAD_H

#include <QObject>
#include "getinfo.h"
class SendThread : public QThread
{
    Q_OBJECT
public:
    explicit SendThread(QObject *parent = 0);
    void run();
    GETINFO * p_Info;
    volatile int listen_dev;

};

#endif // SENDTHREAD_H
