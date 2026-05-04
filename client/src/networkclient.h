#ifndef NETWORKCLIENT_H
#define NETWORKCLIENT_H

#include <QObject>
#include <QSslSocket>
#include <QByteArray>
#include <QJsonObject>
#include <QTimer>
#include <QMutex>
#include <QQueue>
#include <functional>

// Forward-declare CryptexProtocol functions (shared header)
// We reuse the protocol from server/src/protocol.h
// Copy to client/src/protocol.h

class NetworkClient : public QObject
{
    Q_OBJECT

public:
    explicit NetworkClient(QObject *parent = nullptr);
    ~NetworkClient() override;

    void connectToServer(const QString &host, quint16 port);
    void disconnectFromServer();
    bool isConnected() const;

    // Auth
    void login(const QString &username, const QString &password);
    void registerUser(const QString &username, const QString &password,
                      const QString &email, const QString &publicKey);
    void validateSession(const QString &token);
    void logout();

    // Contacts
    void getContactsList();
    void sendContactRequest(const QString &targetUsername, const QString &comment);
    void acceptContactRequest(int requestId);
    void rejectContactRequest(int requestId);
    void removeContact(const QString &username);
    void getContactRequests();
    void lookupUser(const QString &username);

    // Files
    void sendFileInit(const QString &receiver, const QString &fileName,
                      const QString &fileHash, qint64 fileSize);
    void sendFileChunk(int transferId, int chunkIndex, const QByteArray &chunkData);
    void sendFileComplete(int transferId, const QString &finalHash);
    void getFileList();
    void downloadFile(int transferId);
    void cancelTransfer(int transferId);
    void checkUserOnline(const QString &username);

    // Session
    QString token() const { return m_token; }
    int userId() const { return m_userId; }
    QString username() const { return m_username; }
    bool isAuthenticated() const { return m_authenticated; }

signals:
    void connected();
    void disconnected();
    void errorOccurred(const QString &error);
    void loginSuccess(int userId, const QString &username, const QString &token);
    void loginFailed(const QString &reason);
    void registerSuccess();
    void registerFailed(const QString &reason);
    void sessionValid(bool valid, int userId, const QString &username);
    void contactsListReceived(const QJsonArray &contacts);
    void contactRequestsReceived(const QJsonArray &incoming, const QJsonArray &outgoing);
    void contactAdded();
    void contactAddFailed(const QString &reason);
    void contactAccepted();
    void contactRejected();
    void contactRemoved();
    void contactRequestSent();
    void contactRequestFailed(const QString &reason);
    void userLookupResult(int userId, const QString &username, bool isContact);
    void userLookupFailed(const QString &reason);
    void fileSendInitAck(int transferId);
    void fileSendChunkAck(int transferId, qint64 receivedBytes);
    void fileSendCompleteAck();
    void fileSendFailed(const QString &reason);
    void fileListReceived(const QJsonArray &pending, const QJsonArray &sent);
    void fileDownloadMeta(int transferId, const QString &fileName,
                          qint64 fileSize, int totalChunks, const QString &fileHash);
    void fileDownloadChunk(int transferId, int chunkIndex, int totalChunks,
                           const QByteArray &chunkData);
    void fileDownloadComplete(int transferId);
    void fileDownloadFailed(const QString &reason);
    void transferCancelled();
    void userOnlineStatus(const QString &username, bool online);
    void pingResponse(qint64 serverTime);

private slots:
    void onEncrypted();
    void onReadyRead();
    void onDisconnected();
    void onSocketError(QAbstractSocket::SocketError error);
    void onReconnectTimer();

private:
    void sendPacket(const QJsonObject &msg);
    void processMessage(const QJsonObject &msg);
    void handleAuthOk(const QJsonObject &data);
    void handleFileDownloadMeta(const QJsonObject &data);
    void handleFileDownloadChunk(const QJsonObject &data);
    void handlePong(const QJsonObject &data);

    QSslSocket *m_socket;
    QString m_host;
    quint16 m_port;
    bool m_connected;

    QByteArray m_sessionKey;
    QByteArray m_hmacKey;
    QString m_token;
    int m_userId;
    QString m_username;
    bool m_authenticated;

    QByteArray m_readBuffer;
    QTimer *m_reconnectTimer;
    QTimer *m_pingTimer;
    QTimer *m_sessionTimeout;
    QQueue<QJsonObject> m_pendingPackets;

    // Download state
    QByteArray m_downloadBuffer;
    QString m_downloadFileName;
    int m_downloadTransferId;
    int m_downloadTotalChunks;
    int m_downloadReceivedChunks;
    QString m_downloadFileHash;

    // Upload state
    int m_uploadTransferId;
    QString m_uploadFileHash;
    QString m_uploadReceiver;
    qint64 m_uploadFileSize;

    // Queue for commands during auth
    QQueue<std::function<void()>> m_pendingCommands;

    void flushPendingCommands();
};

#endif // NETWORKCLIENT_H