#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QObject>
#include <QString>
#include <QDateTime>
#include <QByteArray>
#include <QVector>
#include <QSqlDatabase>

struct UserInfo {
    int id = -1;
    QString username;
    QString email;
    QString publicKey;
    bool isActive = true;
    QDateTime createdAt;
};

struct FileTransferInfo {
    int id = -1;
    int senderId = -1;
    int receiverId = -1;
    QString fileName;
    QString fileHash;
    qint64 fileSize = 0;
    QString encryptionAlgorithm;
    QDateTime createdAt;
};

struct SessionInfo {
    int id = -1;
    int userId = -1;
    QString token;
    QString ipAddress;
    QDateTime expiresAt;
    QDateTime createdAt;
    bool isRevoked = false;
};

struct AuditLogEntry {
    int id = -1;
    int userId = -1;
    QString action;
    QString tableName;
    int recordId = -1;
    QString oldValues;  // JSON
    QString newValues;  // JSON
    QString ipAddress;
    QDateTime createdAt;
};

class DatabaseManager : public QObject
{
    Q_OBJECT

public:
    static DatabaseManager& getInstance();

    // Подключение
    bool connectToDatabase(const QString &host = "localhost",
                           int port = 5432,
                           const QString &dbName = "cryptex_db",
                           const QString &user = "postgres",
                           const QString &password = "1234");
    void disconnectFromDatabase();
    bool isConnected() const;

    // Users
    bool createUser(const QString &username, const QString &passwordHash,
                    const QString &email, const QString &publicKey);
    UserInfo getUserById(int userId);
    UserInfo getUserByUsername(const QString &username);
    UserInfo getUserByEmail(const QString &email);
    bool updateUserPassword(int userId, const QString &newPasswordHash);
    bool deactivateUser(int userId);
    bool activateUser(int userId);
    bool isUsernameTaken(const QString &username) const;
    bool isEmailRegistered(const QString &email) const;

    // Sessions
    SessionInfo createSession(int userId, const QString &token,
                              const QString &ipAddress, int expirySeconds = 86400);
    SessionInfo getSessionByToken(const QString &token);
    bool revokeSession(int sessionId);
    bool revokeAllUserSessions(int userId);
    QVector<SessionInfo> getActiveSessionsForUser(int userId);
    bool isSessionValid(const QString &token) const;
    void cleanupExpiredSessions();

    // Files
    bool registerFileTransfer(int senderId, int receiverId,
                              const QString &fileName, const QString &fileHash,
                              qint64 fileSize, const QString &algorithm = "AES-256-GCM");
    QVector<FileTransferInfo> getFilesSentByUser(int userId);
    QVector<FileTransferInfo> getFilesReceivedByUser(int userId);
    FileTransferInfo getFileById(int fileId);

    // Audit logs
    bool addAuditLog(int userId, const QString &action, const QString &tableName,
                     int recordId, const QString &oldValues,
                     const QString &newValues, const QString &ipAddress = "");
    QVector<AuditLogEntry> getAuditLogsForUser(int userId, int limit = 100);
    QVector<AuditLogEntry> getRecentAuditLogs(int limit = 100);

    // Общие
    bool executeQuery(const QString &sql, const QMap<QString, QVariant> &params = {});
    QString lastError() const;

private:
    explicit DatabaseManager(QObject *parent = nullptr);
    ~DatabaseManager();
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    QString m_connectionName;
    bool m_connected;

    QSqlDatabase getDatabase() const;
    QString escapeConnectionName() const;
};

#endif // DATABASEMANAGER_H