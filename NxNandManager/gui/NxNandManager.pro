#-------------------------------------------------
#
# Project created by QtCreator 2019-02-22T12:38:11
#
#-------------------------------------------------

#QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NxNandManager
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11
CONFIG += console

SOURCES += \
    ../main.cpp \
    ../res/hex_string.cpp \
    ../res/fat32.cpp \
    ../res/utils.cpp \
    ../NxStorage.cpp \
    ../NxCrypto.cpp \
    ../NxPartition.cpp \
    ../NxHandle.cpp \
    keyset.cpp \
    mainwindow.cpp \
    properties.cpp \
    resizeuser.cpp \
    worker.cpp \
    opendrive.cpp

HEADERS += \
    ../NxNandManager.h \
    ../res/hex_string.h \
    ../res/fat32.h \
    ../res/utils.h \
    ../res/types.h \
    ../NxStorage.h \
    ../NxCrypto.h \
    keyset.h \
    mainwindow.h \
    properties.h \
    ../NxPartition.h \
    ../NxHandle.h \
    mainwindow.h \
    resizeuser.h \
    worker.h \
    opendrive.h
FORMS += \
    mainwindow.ui \
    opendrive.ui \
    keyset.ui \
    properties.ui \
    resizeuser.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    application.qrc

DISTFILES +=

QT += winextras

RC_FILE = NxNandManager.rc

#ARCH = 32
ARCH = 64

contains( ARCH, 32 ) {
    LIBS += -L$$PWD/../../../openssl-1.1.1c-win32-mingw/lib/ -lcrypto
    INCLUDEPATH += $$PWD/../../../openssl-1.1.1c-win32-mingw/include
    DEPENDPATH += $$PWD/../../../openssl-1.1.1c-win32-mingw/include
}
contains( ARCH, 64 ) {
    LIBS += -L$$PWD/../../../openssl-1.1.1c-win64-mingw/lib/ -lcrypto
    INCLUDEPATH += $$PWD/../../../openssl-1.1.1c-win64-mingw/include
    DEPENDPATH += $$PWD/../../../openssl-1.1.1c-win64-mingw/include
}

