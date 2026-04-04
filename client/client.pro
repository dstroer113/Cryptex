QT       += core network sql gui widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# Исправление ошибки Qt6EntryPoint (Qt 6.7+ MinGW)
CONFIG += console
win32: QMAKE_LFLAGS += -Wl,--subsystem,console

# Пути к OpenSSL (MSYS2 UCRT64)
INCLUDEPATH += F:/msys64/ucrt64/include
LIBS += -LF:/msys64/ucrt64/lib -lcrypto -lssl

RESOURCES += resources.qrc
QMAKE_CXXFLAGS += -Wno-expansion-to-defined


# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    credentialmanager.cpp \
    cryptoengine.cpp \
    loginwindow.cpp \
    main.cpp \
    mainwindow.cpp \
    securitymanager.cpp

HEADERS += \
    credentialmanager.h \
    cryptoengine.h \
    loginwindow.h \
    mainwindow.h \
    securitymanager.h

FORMS += \
    mainwindow.ui

TRANSLATIONS += \
    client_ru_RU.ts
CONFIG += lrelease
CONFIG += embed_translations

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
