#include "loginwindow.h"
#include "mainwindow.h"
#include "src/networkclient.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include <QDebug>
#include <QStyleFactory>
#include <QPalette>
#include <QFont>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationName("Cryptex Client");
    a.setApplicationVersion("2.0.0");

    // Глобальная тёмная тема
    a.setStyle(QStyleFactory::create("Fusion"));
    QPalette p;
    p.setColor(QPalette::Window,          QColor(26, 26, 46));
    p.setColor(QPalette::WindowText,      Qt::white);
    p.setColor(QPalette::Base,            QColor(15, 52, 96));
    p.setColor(QPalette::AlternateBase,   QColor(17, 34, 68));
    p.setColor(QPalette::ToolTipBase,     QColor(15, 52, 96));
    p.setColor(QPalette::ToolTipText,     Qt::white);
    p.setColor(QPalette::Text,            Qt::white);
    p.setColor(QPalette::Button,          QColor(15, 52, 96));
    p.setColor(QPalette::ButtonText,      Qt::white);
    p.setColor(QPalette::BrightText,      Qt::red);
    p.setColor(QPalette::Link,            QColor(76, 175, 80));
    p.setColor(QPalette::Highlight,       QColor(76, 175, 80));
    p.setColor(QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::Disabled, QPalette::Text, QColor(128, 128, 128));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(128, 128, 128));
    a.setPalette(p);

    QFont f = a.font();
    f.setPointSize(10);
    a.setFont(f);

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "client_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }

    // Создаём NetworkClient
    NetworkClient networkClient;

    // Login — поддерживаем офлайн-режим
    LoginWindow login(&networkClient);
    if (login.exec() != QDialog::Accepted) return 0;

    if (login.isOfflineMode()) {
        // Офлайн-режим: MainWindow без сетевых вкладок
        MainWindow w(&networkClient, false);
        w.show();
        return a.exec();
    }

    // Онлайн-режим
    MainWindow w(&networkClient, true);
    w.setSessionToken(login.getSessionToken());
    w.setUserId(login.getUserId());
    w.setUserName(login.getUserName());

    w.show();
    return a.exec();
}