#-------------------------------------------------
#
# Project created by QtCreator 2019-02-22T12:38:11
#
#-------------------------------------------------

QT       += core gui network

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

QMAKE_CXXFLAGS += -fpermissive -std=c++0x -pthread
LIBS += -pthread

SOURCES += \
    ../NxFile.cpp \
    ../NxSave.cpp \
    ../lib/fatfs/diskio.cpp \
    ../lib/fatfs/ff.cpp \
    ../lib/fatfs/ffsystem.cpp \
    ../lib/fatfs/ffunicode.cpp \
    ../main.cpp \
    ../res/hactool/utils.c \
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
    ../virtual_fs/filenode.cpp \
    ../virtual_fs/filenodes.cpp \
    ../virtual_fs/virtual_fs.cpp \
    ../virtual_fs/virtual_fs_helper.cpp \
    ../virtual_fs/virtual_fs_operations.cpp \
    emunand.cpp \
    explorer.cpp \
    hactoolnet.cpp \
    keyset.cpp \
    loading_widget.cpp \
    mainwindow.cpp \
    mount.cpp \
    properties.cpp \
    qutils.cpp \
    resizeuser.cpp \
    worker.cpp \
    opendrive.cpp \
    dump.cpp \
    progress.cpp \
    $$files(../lib/ZipLib/*.cpp, false) \
    $$files(../lib/ZipLib/detail/*.cpp, false) \
    $$files(../lib/ZipLib/extlibs/bzip2/*.c, false) \
    $$files(../lib/ZipLib/extlibs/lzma/*.c, false) \
    debug.cpp
HEADERS += \
    ../NxFile.h \
    ../NxNandManager.h \
    ../NxSave.h \
    ../lib/fatfs/diskio.h \
    ../lib/fatfs/ff.h \
    ../lib/fatfs/ffconf.h \
    ../res/hactool/ivfc.h \
    ../res/hactool/settings.h \
    ../res/hactool/types.h \
    ../res/hactool/utils.h \
    ../res/hex_string.h \
    ../res/fat32.h \
    ../res/mbr.h \
    ../res/progress_info.h \
    ../res/utils.h \
    ../res/types.h \
    ../NxStorage.h \
    ../NxCrypto.h \
    ../res/win_ioctl.h \
    ../virtual_fs/filenode.h \
    ../virtual_fs/filenodes.h \
    ../virtual_fs/virtual_fs.h \
    ../virtual_fs/virtual_fs_helper.h \
    ../virtual_fs/virtual_fs_operations.h \
    explorer.h \
    gui.h \
    hactoolnet.h \
    keyset.h \
    loading_widget.h \
    mainwindow.h \
    mount.h \
    properties.h \
    ../NxPartition.h \
    ../NxHandle.h \
    qutils.h \
    resizeuser.h \
    worker.h \
    opendrive.h \
    dump.h \
    progress.h \
    emunand.h \
    ../lib/ZipLib/*.h \
    ../lib/ZipLib/utils/*.h \
    ../lib/ZipLib/detail/*.h \
    ../lib/ZipLib/extlibs/bzip2/*.h \
    ../lib/ZipLib/extlibs/lzma/*.h \
    debug.h

CONFIG(STATIC) {
    HEADERS -= ../lib/ZipLib/extlibs/zlib/zconf.h
}
CONFIG(DYNAMIC) {
    SOURCES += $$files(../lib/ZipLib/extlibs/zlib/*.c, false)
    HEADERS += ../lib/ZipLib/extlibs/zlib/*.h \
}

FORMS += \
    emunand.ui \
    explorer.ui \
    loading_widget.ui \
    mainwindow.ui \
    mount.ui \
    opendrive.ui \
    keyset.ui \
    properties.ui \
    resizeuser.ui \
    dump.ui \
    progress.ui \
    debug.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    application.qrc

QT += winextras

RC_FILE = NxNandManager.rc

CONFIG(ARCH32) {
    DEFINES += ARCH32
    #OPENSSL PATH
    OPENSSL_LIB_PATH = $$PWD/../../../../../mingw32
    LIBS += -L$$PWD/../virtual_fs/dokan/x86/lib/ -ldokan1

}
CONFIG(ARCH64) {
    DEFINES += ARCH64
    #OPENSSL PATH
    OPENSSL_LIB_PATH = $$PWD/../../../../../mingw64
    LIBS += -L$$PWD/../virtual_fs/dokan/x64/lib/ -ldokan1
}

INCLUDEPATH += $$PWD/../virtual_fs/dokan/include
DEPENDPATH += $$PWD/../virtual_fs/dokan/include

win32: LIBS += -L$${OPENSSL_LIB_PATH}/lib/ -lcrypto
INCLUDEPATH += $${OPENSSL_LIB_PATH}/include
DEPENDPATH += $${OPENSSL_LIB_PATH}/include

win32:!win32-g++: PRE_TARGETDEPS += $${OPENSSL_LIB_PATH}/lib/crypto.lib
else:win32-g++: PRE_TARGETDEPS += $${OPENSSL_LIB_PATH}/lib/libcrypto.a

DISTFILES += \
    images/explorer.png
