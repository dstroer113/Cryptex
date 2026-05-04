QT       += core network sql

CONFIG += c++17 console

# Пути к OpenSSL (MSYS2 UCRT64)
INCLUDEPATH += F:/msys64/ucrt64/include
LIBS += -LF:/msys64/ucrt64/lib -lcrypto -lssl

QMAKE_CXXFLAGS += -Wno-expansion-to-defined -pipe

SOURCES += \
    main.cpp \
    src/cryptoserver.cpp \
    src/databasemanager.cpp \
    src/clienthandler.cpp

HEADERS += \
    src/cryptoserver.h \
    src/databasemanager.h \
    src/clienthandler.h \
    src/protocol.h

TRANSLATIONS += \
    server_ru_RU.ts
CONFIG += lrelease
CONFIG += embed_translations

DISTFILES += \
    db/01_tables.sql \
    db/02_procedures.sql \
    db/03_triggers.sql