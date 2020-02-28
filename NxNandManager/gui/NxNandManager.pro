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
CONFIG += static create_prl link_prl
CONFIG += object_parallel_to_source

SOURCES += \
    ../main.cpp \
    ../res/hex_string.cpp \
    ../res/fat32.cpp \
    ../res/mbr.cpp \
    ../res/progress_info.cpp \
    ../res/utils.cpp \
    ../NxStorage.cpp \
    ../NxCrypto.cpp \
    ../NxPartition.cpp \
    ../NxHandle.cpp \
    ../res/win_ioctl.cpp \
    emunand.cpp \
    keyset.cpp \
    mainwindow.cpp \
    properties.cpp \
    qutils.cpp \
    resizeuser.cpp \
    worker.cpp \
    opendrive.cpp \
    dump.cpp \
    progress.cpp \
    explorer.cpp \
    $$files(../lib/ZipLib/*.cpp, false) \
    $$files(../lib/ZipLib/detail/*.cpp, false) \
    $$files(../lib/ZipLib/extlibs/bzip2/*.c, false) \
    $$files(../lib/ZipLib/extlibs/lzma/*.c, false) \
    $$files(../lib/ZipLib/extlibs/zlib/*.c, false) \
    debug.cpp
HEADERS += \
    ../NxNandManager.h \
    ../res/hex_string.h \
    ../res/fat32.h \
    ../res/mbr.h \
    ../res/progress_info.h \
    ../res/utils.h \
    ../res/types.h \
    ../NxStorage.h \
    ../NxCrypto.h \
    ../res/win_ioctl.h \
    emunand.h \
    gui.h \
    keyset.h \
    mainwindow.h \
    properties.h \
    ../NxPartition.h \
    ../NxHandle.h \
    mainwindow.h \
    qutils.h \
    resizeuser.h \
    worker.h \
    opendrive.h \
    dump.h \
    progress.h \
    dump.h \
    emunand.h \
    explorer.h \
    gui.h \
    keyset.h \
    mainwindow.h \
    opendrive.h \
    progress.h \
    properties.h \
    qutils.h \
    resizeuser.h \
    worker.h \
    ../lib/ZipLib/*.h \
    ../lib/ZipLib/utils/*.h \
    ../lib/ZipLib/detail/*.h \
    ../lib/ZipLib/extlibs/bzip2/*.h \
    ../lib/ZipLib/extlibs/lzma/*.h \
    ../lib/ZipLib/extlibs/zlib/*.h \
    debug.h
FORMS += \
    emunand.ui \
    mainwindow.ui \
    opendrive.ui \
    keyset.ui \
    properties.ui \
    resizeuser.ui \
    dump.ui \
    progress.ui \
    explorer.ui \
    debug.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    application.qrc

QT += winextras

RC_FILE = NxNandManager.rc

#ARCH = 32
ARCH = 64

contains( ARCH, 32 ) {
    win32: LIBS += -L$$PWD/../../../../../mingw32/lib/ -lcrypto
    INCLUDEPATH += $$PWD/../../../../../mingw32/include
    DEPENDPATH += $$PWD/../../../../../mingw32/include
    win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../mingw32/lib/crypto.lib
    else:win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../mingw32/lib/libcrypto.a
}
contains( ARCH, 64 ) {
    win32: LIBS += -L$$PWD/../../../../../mingw64/lib/ -lcrypto
    INCLUDEPATH += $$PWD/../../../../../mingw64/include
    DEPENDPATH += $$PWD/../../../../../mingw64/include
    win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../mingw64/lib/crypto.lib
    else:win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../mingw64/lib/libcrypto.a
}
LIBS += -lpthread
#win32: LIBS += -L$$PWD/../lib/ZipLib/bin/ -lzip
#INCLUDEPATH += $$PWD/../lib/ZipLib
#DEPENDPATH += $$PWD/../lib/ZipLib
