#ifndef CLIENTHANDLER_H
#define CLIENTHANDLER_H

#include <QObject>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QByteArray>
#include <QJsonObject>

class DatabaseManager;
class CryptoServer;

class ClientHandler : public QObject
{
    Q_OBJECT

public:
    ClientHandler(QSslSocket *socket, QSslConfiguration sslConfig,
                  DatabaseManager *db, CryptoServer *server, QObject *parent = nullptr);
    ~ClientHandler() override;

    void start();
    int userId() const { return m_userId; }
    QString username() const { return m_username; }
    bool isAuthenticated() const { return m_authenticated; }

    /// Прямая отправка данных другому клиенту (стриминг)
    void sendRawMessage(const QJsonObject &msg);
    QSslSocket* socket() const { return m_socket; }

public slots:
    void onEncrypted();
    void onReadyRead();
    void onDisconnected();
    void onError(QAbstractSocket::SocketError error);

signals:
    void finished();
    void fileUploadComplete(int transferId, int receiverId, const QString &fileName,
                            const QString &fileHash, qint64 fileSize, const QByteArray &data);
    void fileDownloadRequest(int transferId, int userId);

private:
    // Command handlers
    void handleAuthLogin(const QJsonObject &msg);
    void handleAuthRegister(const QJsonObject &msg);
    void handleAuthSessionValid(const QJsonObject &msg);
    void handleContactAdd(const QJsonObject &msg);
    void handleContactAccept(const QJsonObject &msg);
    void handleContactReject(const QJsonObject &msg);
    void handleContactRemove(const QJsonObject &msg);
    void handleContactsList(const QJsonObject &msg);
    void handleContactRequests(const QJsonObject &msg);
    void handleUserLookup(const QJsonObject &msg);
    void handleFileSendInit(const QJsonObject &msg);
    void handleFileSendChunk(const QJsonObject &msg);
    void handleFileSendComplete(const QJsonObject &msg);
    void handleFileReceiveList(const QJsonObject &msg);
    void handleFileDownloadInit(const QJsonObject &msg);
    void handleFileCancel(const QJsonObject &msg);
    void handlePing(const QJsonObject &msg);
    void handlePasswordReset(const QJsonObject &msg);
    void handleCheckOnline(const QJsonObject &msg);

    void sendResponse(const QJsonObject &response);
    void disconnectClient();
    bool verifyPassword(const QString &username, const QString &password) const;
    QString hashPassword(const QString &password) const;
    bool checkRateLimit();
    QString clientIP() const;

    QSslConfiguration m_sslConfig;
    QSslSocket *m_socket;
    DatabaseManager *m_database;
    CryptoServer *m_server;

    // Сессия
    int m_userId;
    QString m_username;
    QByteArray m_sessionKey;
    QByteArray m_hmacKey;
    bool m_authenticated;

    // Буфер для реконструкции пакетов
    QByteArray m_readBuffer;
    static constexpr int MAX_BUFFER_SIZE = 36700160; // 35 MB

    // Файловый трансфер (upload в процессе) — только в ОЗУ
    struct PendingUpload {
        int transferId = -1;
        int receiverId = -1;
        QString fileHash;
        QString fileName;
        qint64 totalSize = 0;
        qint64 receivedBytes = 0;
        QByteArray accumulatedData;
    };
    PendingUpload m_pendingUpload;

    // Rate limiting per connection
    int m_requestCount;
    qint64 m_lastRequestTime;
    static constexpr int MAX_REQUESTS_PER_MIN = 120;
};

#endif // CLIENTHANDLER_H