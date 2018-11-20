#ifndef MYTREAD_H
#define MYTREAD_H

#include <QObject>
#include <QThread>
class MyThread : public QThread
{
    Q_OBJECT
public:
    explicit MyThread(QObject *parent = 0);
    void stop();
    void set_listen_dev(int devid);
protected:
    void run();
private:
    volatile bool stopped;
    volatile int listen_dev;

signals:
void stringChanged(const QString &);

public slots:
};

#endif // MYTREAD_H
