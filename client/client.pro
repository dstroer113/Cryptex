QT       += core gui network widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17 console

# OpenSSL (MSYS2 UCRT64)
INCLUDEPATH += F:/msys64/ucrt64/include
LIBS += -LF:/msys64/ucrt64/lib -lcrypto -lssl

QMAKE_CXXFLAGS += -Wno-expansion-to-defined -pipe

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    loginwindow.cpp \
    cryptoengine.cpp \
    securitymanager.cpp \
    credentialmanager.cpp \
    src/networkclient.cpp \
    src/contactstab.cpp \
    src/transferstab.cpp \
    src/settingsdialog.cpp

HEADERS += \
    mainwindow.h \
    loginwindow.h \
    cryptoengine.h \
    securitymanager.h \
    credentialmanager.h \
    src/networkclient.h \
    src/contactstab.h \
    src/transferstab.h \
    src/settingsdialog.h \
    src/protocol.h

FORMS += \
    mainwindow.ui

RESOURCES += \
    resources.qrc

TRANSLATIONS += \
    client_ru_RU.ts
CONFIG += lrelease
CONFIG += embed_translations