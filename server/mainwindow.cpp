#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "src/cryptoserver.h"
#include "src/databasemanager.h"

#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QDateTime>
#include <QFile>
#include <QTextStream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_server(new CryptoServer(this))
    , m_cleanupTimer(new QTimer(this))
    , m_activeConnections(0)
{
    ui->setupUi(this);
    setWindowTitle("Cryptex Server");

    m_cleanupTimer->setInterval(300000); // каждые 5 минут
    connect(m_cleanupTimer, &QTimer::timeout, this, &MainWindow::onCleanupTimer);
    m_cleanupTimer->start();

    connect(m_server, &CryptoServer::serverStarted, this, &MainWindow::onServerStarted);
    connect(m_server, &CryptoServer::serverStopped, this, &MainWindow::onServerStopped);
    connect(m_server, &CryptoServer::clientConnected, this, &MainWindow::onClientConnected);
    connect(m_server, &CryptoServer::clientDisconnected, this, &MainWindow::onClientDisconnected);
    connect(m_server, &CryptoServer::logMessage, this, &MainWindow::onLogMessage);
}

MainWindow::~MainWindow()
{
    m_server->stopServer();
    delete ui;
}

void MainWindow::onStartStopClicked()
{
    if (m_server->isRunning()) {
        m_server->stopServer();
        return;
    }

    // Диалог настроек БД
    bool ok;
    QString dbHost = QInputDialog::getText(this, "DB Host", "PostgreSQL Host:", QLineEdit::Normal, "localhost", &ok);
    if (!ok) return;

    int dbPort = QInputDialog::getInt(this, "DB Port", "Port:", 5432, 1, 65535, 1, &ok);
    if (!ok) return;

    QString dbName = QInputDialog::getText(this, "DB Name", "Database name:", QLineEdit::Normal, "cryptex", &ok);
    if (!ok) return;

    QString dbUser = QInputDialog::getText(this, "DB User", "Username:", QLineEdit::Normal, "cryptex_admin", &ok);
    if (!ok) return;

    QString dbPass = QInputDialog::getText(this, "DB Password", "Password:", QLineEdit::Password, "", &ok);
    if (!ok) return;

    appendLog("Connecting to database...");
    auto &db = DatabaseManager::getInstance();
    if (!db.connect(dbHost, dbPort, dbName, dbUser, dbPass)) {
        appendLog("[ERROR] Database connection failed");
        QMessageBox::critical(this, "Error", "Failed to connect to database");
        return;
    }
    appendLog("[OK] Database connected");

    // Выбор SSL-сертификатов
    QString certPath = QFileDialog::getOpenFileName(this, "SSL Certificate", "", "PEM (*.pem *.crt)");
    if (certPath.isEmpty()) certPath = "server.crt";

    QString keyPath = QFileDialog::getOpenFileName(this, "SSL Private Key", "", "PEM (*.pem *.key)");
    if (keyPath.isEmpty()) keyPath = "server.key";

    int port = QInputDialog::getInt(this, "Server Port", "Port:", 8443, 1, 65535, 1, &ok);
    if (!ok) return;

    appendLog("Starting server on port " + QString::number(port) + "...");
    m_server->startServer("0.0.0.0", static_cast<quint16>(port), certPath, keyPath);
}

void MainWindow::onServerStarted(quint16 port)
{
    updateStatus(QString("RUNNING :%1").arg(port), "green");
    appendLog(QString("[INFO] Server started on port %1").arg(port));
}

void MainWindow::onServerStopped()
{
    updateStatus("STOPPED", "red");
    appendLog("[INFO] Server stopped");
}

void MainWindow::onClientConnected(const QString &ip)
{
    m_activeConnections++;
    updateStatus(QString("RUNNING (%1 clients)").arg(m_activeConnections), "green");
    appendLog("[CONNECT] " + ip);
}

void MainWindow::onClientDisconnected(const QString &ip)
{
    if (m_activeConnections > 0) m_activeConnections--;
    updateStatus(QString("RUNNING (%1 clients)").arg(m_activeConnections), "green");
    if (!ip.isEmpty()) appendLog("[DISCONNECT] " + ip);
}

void MainWindow::onLogMessage(const QString &category, const QString &message)
{
    appendLog(QString("[%1] %2").arg(category, message));
}

void MainWindow::onCleanupTimer()
{
    auto &db = DatabaseManager::getInstance();
    if (db.isConnected()) {
        int removed = db.cleanupExpiredSessions();
        if (removed > 0) appendLog(QString("[CLEANUP] Removed %1 expired sessions").arg(removed));
        db.cleanupExpiredTransfers();
    }
}

void MainWindow::updateStatus(const QString &text, const QString &color)
{
    Q_UNUSED(color)
    statusBar()->showMessage(text);
}

void MainWindow::appendLog(const QString &text)
{
    QString timestamp = QDateTime::currentDateTime().toString("[dd.MM.yyyy hh:mm:ss] ");
    // Вывод в statusbar и/или консоль
    qInfo().noquote() << timestamp + text;
}