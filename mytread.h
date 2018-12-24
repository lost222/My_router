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
    unsigned int listenIp;
    GETINFO* p_Info;
    QMap<unsigned int, QVector<BYTE> > arp_table;
    QVector<QVector<unsigned int> > route_table;
    int check_route_table(unsigned int ip);
    int find_route_info(QVector<unsigned int> &);

protected:
    void run();
private:
    volatile bool stopped;
    volatile int listen_dev;
    void deal_with_arp_datagram(struct ARPFrame_t *);
    void deal_with_other_datagram(struct Data_t *);

signals:
void stringChanged(const QString &);
void get_arp_datagram(const QString &);
void trans_datagram(struct Data_t *);

public slots:
};

#endif // MYTREAD_H
