#ifndef CRYPTOSERVER_H
#define CRYPTOSERVER_H

#include <QObject>
#include <QSslServer>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslConfiguration>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QElapsedTimer>
#include <QSet>

class ClientHandler;
class DatabaseManager;

class CryptoServer : public QObject
{
    Q_OBJECT

public:
    explicit CryptoServer(QObject *parent = nullptr);
    ~CryptoServer() override;

    bool startServer(const QString &host, quint16 port,
                     const QString &certPath, const QString &keyPath);
    void stopServer();
    bool isRunning() const;

    int activeThreadCount() const { QMutexLocker l(&m_activeMutex); return m_activeHandlers.size(); }

    // Rate limiting
    bool checkRateLimit(const QString &ip);
    void recordConnection(const QString &ip);

    // Кэш файлов в ОЗУ (стриминг-ретранслятор)
    void storeFileData(int transferId, int receiverId, const QString &fileName,
                       const QString &fileHash, qint64 fileSize, const QByteArray &data);
    QByteArray takeFileData(int transferId);
    ClientHandler* findHandlerByUserId(int userId) const;

signals:
    void serverStarted(quint16 port);
    void serverStopped();
    void clientConnected(const QString &ip);
    void clientDisconnected(const QString &ip);
    void logMessage(const QString &category, const QString &message);

private slots:
    void onNewConnection();
    void onClientHandlerFinished();
    void onFileUploadComplete(int transferId, int receiverId, const QString &fileName,
                              const QString &fileHash, qint64 fileSize, const QByteArray &data);
    void onFileDownloadRequest(int transferId, int userId);

private:
    void setupSslConfig(const QString &certPath, const QString &keyPath);

    QSslServer *m_sslServer;
    QSslConfiguration m_sslConfig;

    DatabaseManager *m_database;

    // Активные обработчики
    mutable QMutex m_activeMutex;
    QSet<ClientHandler*> m_activeHandlers;

    // Кэш файлов в ОЗУ (transferId -> данные + мета)
    struct CachedFile {
        int receiverId;
        QString fileName;
        QString fileHash;
        qint64 fileSize;
        QByteArray data;
    };
    mutable QMutex m_cacheMutex;
    QHash<int, CachedFile> m_fileCache;

    // Rate limiting
    mutable QMutex m_rateMutex;
    QHash<QString, QElapsedTimer> m_lastConnection;
    QHash<QString, int> m_connectionCount;
    static constexpr int MAX_CONNECTIONS_PER_SEC = 5;
    static constexpr int RATE_WINDOW_MS = 1000;
};

#endif // CRYPTOSERVER_H