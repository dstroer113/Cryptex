#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QLabel>

class CryptoServer;

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void onStartStopClicked();
    void onServerStarted(quint16 port);
    void onServerStopped();
    void onClientConnected(const QString &ip);
    void onClientDisconnected(const QString &ip);
    void onLogMessage(const QString &category, const QString &message);
    void onCleanupTimer();

private:
    void updateStatus(const QString &text, const QString &color);
    void appendLog(const QString &text);

    Ui::MainWindow *ui;
    CryptoServer *m_server;
    QTimer *m_cleanupTimer;
    int m_activeConnections;
    QLabel *m_statusLabel;
};

#endif // MAINWINDOW_H