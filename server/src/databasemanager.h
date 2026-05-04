#ifndef SERVER_DATABASEMANAGER_H
#define SERVER_DATABASEMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QString>
#include <QDateTime>
#include <QList>
#include <QPair>
#include <QMutex>
#include <QMutexLocker>

struct UserInfo {
    int id = -1;
    QString username;
    QString email;
    QString publicKey;
    bool isActive = false;
    QDateTime createdAt;
};

struct SessionInfo {
    int id = -1;
    int userId = -1;
    QString token;
    QString ipAddress;
    QDateTime expiresAt;
    bool isRevoked = false;
};

struct ContactInfo {
    int id = -1;
    int userIdA = -1;
    int userIdB = -1;
    QString usernameA;
    QString usernameB;
    QDateTime createdAt;
};

struct ContactRequestInfo {
    int id = -1;
    int senderId = -1;
    int receiverId = -1;
    QString senderName;
    QString comment;
    QString status;
    QDateTime createdAt;
};

struct FileTransferInfo {
    int id = -1;
    int senderId = -1;
    int receiverId = -1;
    QString senderName;
    QString fileName;
    QString fileHash;
    qint64 fileSize = 0;
    QString storagePath;
    QString status;
    QDateTime createdAt;
    QDateTime expiresAt;
    int maxDownloads = 3;
    int downloadCount = 0;
};

class DatabaseManager : public QObject
{
    Q_OBJECT

public:
    static DatabaseManager& getInstance();
    bool connect(const QString &host, int port, const QString &dbName,
                 const QString &user, const QString &password);
    void disconnect();
    bool isConnected() const;

    // Пользователи
    bool createUser(const QString &username, const QString &passwordHash,
                    const QString &email, const QString &publicKey);
    UserInfo getUserByUsername(const QString &username) const;
    UserInfo getUserById(int id) const;
    bool isUsernameTaken(const QString &username) const;
    bool isEmailRegistered(const QString &email) const;
    bool verifyPassword(const QString &username, const QString &passwordHash) const;
    bool updatePassword(const QString &username, const QString &newHash);
    bool incrementFailedAttempts(const QString &username);
    bool lockUser(const QString &username, int seconds = 900);
    bool resetFailedAttempts(const QString &username);
    bool isUserLocked(const QString &username) const;

    // Сессии
    SessionInfo createSession(int userId, const QString &token,
                              const QString &ipAddress, int ttlSeconds = 3600);
    SessionInfo validateSession(const QString &token) const;
    bool revokeSession(const QString &token);
    bool revokeAllUserSessions(int userId);
    bool cleanupExpiredSessions();

    // Контакты
    bool sendContactRequest(int senderId, int receiverId, const QString &comment);
    bool acceptContactRequest(int requestId, int receiverId);
    bool rejectContactRequest(int requestId, int receiverId);
    bool removeContact(int userIdA, int userIdB);
    QList<ContactInfo> getContacts(int userId) const;
    QList<ContactRequestInfo> getIncomingRequests(int userId) const;
    QList<ContactRequestInfo> getOutgoingRequests(int userId) const;
    bool areContacts(int userIdA, int userIdB) const;

    // Файловые передачи
    int createFileTransfer(int senderId, int receiverId, const QString &fileName,
                           const QString &fileHash, qint64 fileSize,
                           const QString &storagePath, int ttlHours = 72);
    bool updateTransferStatus(int transferId, const QString &status);
    bool updateTransferProgress(int transferId, qint64 bytes);
    bool incrementDownloadCount(int transferId);
    FileTransferInfo getFileTransfer(int transferId) const;
    QList<FileTransferInfo> getPendingTransfers(int userId) const;
    QList<FileTransferInfo> getSentTransfers(int userId) const;
    bool cancelTransfer(int transferId, int userId);
    bool cleanupExpiredTransfers();

    // Аудит
    bool addAuditLog(int userId, const QString &action, const QString &tableName,
                     int recordId, const QString &details, const QString &ipAddress,
                     bool success);
    bool addAuditLogSimple(int userId, const QString &action, bool success);

    // Сброс пароля
    QString getEmailByUsername(const QString &username) const;

    // Статистика (для консольного мониторинга)
    int userCount() const;
    int contactCount() const;
    int transferCount() const;
    int activeSessionCount() const;
    QStringList getRecentAuditLog(int limit = 20) const;

    // Очистка
    int purgeOldAuditLogs(int days = 90);

private:
    explicit DatabaseManager(QObject *parent = nullptr);
    ~DatabaseManager() override;
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    QSqlDatabase m_db;
    mutable QMutex m_mutex;
    bool m_connected;
};

#endif // SERVER_DATABASEMANAGER_H