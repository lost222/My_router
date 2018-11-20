#-------------------------------------------------
#
# Project created by QtCreator 2018-11-19T20:47:04
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qt_2
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    getinfo.cpp \
    mytread.cpp

HEADERS  += mainwindow.h \
    getinfo.h \
    mytread.h

FORMS    += mainwindow.ui

INCLUDEPATH += C:\\code\\winpcap_sdk\\WpdPack\\Include\\
LIBS += WS2_32.lib
LIBS += C:\\code\\winpcap_sdk\\WpdPack\\Lib\\wpcap.lib
LIBS += C:\\code\\winpcap_sdk\\WpdPack\\Lib\\Packet.lib
CONFIG += no_lflags_merge

DEFINES += WPCAP
DEFINES += HAVE_REMOTE

