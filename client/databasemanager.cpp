#include "DatabaseManager.h"
#include <QDebug>
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>

DatabaseManager::DatabaseManager(QObject *parent)
    : QObject(parent)
    , m_connectionName("db_main")
    , m_connected(false)
{
    qDebug() << "[DB] DatabaseManager initialized";
}

DatabaseManager::~DatabaseManager()
{
    disconnectFromDatabase();
}

DatabaseManager& DatabaseManager::getInstance()
{
    static DatabaseManager instance;
    return instance;
}

QSqlDatabase DatabaseManager::getDatabase() const
{
    return QSqlDatabase::database(m_connectionName);
}

bool DatabaseManager::connectToDatabase(const QString &host, int port,
                                         const QString &dbName, const QString &user,
                                         const QString &password)
{
    if (m_connected) {
        qDebug() << "[DB] Already connected";
        return true;
    }

    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL", m_connectionName);
    db.setHostName(host);
    db.setPort(port);
    db.setDatabaseName(dbName);
    db.setUserName(user);
    db.setPassword(password);

    if (!db.open()) {
        qWarning() << "[DB] Connection failed:" << db.lastError().text();
        m_connected = false;
        return false;
    }

    m_connected = true;
    qDebug() << "[DB] Connected to" << dbName << "on" << host << ":" << port;
    return true;
}

void DatabaseManager::disconnectFromDatabase()
{
    if (m_connected) {
        QSqlDatabase::database(m_connectionName).close();
        QSqlDatabase::removeDatabase(m_connectionName);
        m_connected = false;
        qDebug() << "[DB] Disconnected";
    }
}

bool DatabaseManager::isConnected() const
{
    return m_connected;
}

QString DatabaseManager::lastError() const
{
    QSqlDatabase db = getDatabase();
    return db.isValid() ? db.lastError().text() : "No database connection";
}

// ─────────────────────────────────────────────────────────────
// Users
// ─────────────────────────────────────────────────────────────
bool DatabaseManager::createUser(const QString &username, const QString &passwordHash,
                                  const QString &email, const QString &publicKey)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("INSERT INTO public.users (username, password_hash, email, public_key) "
                  "VALUES (:username, :password_hash, :email, :public_key)");
    query.bindValue(":username", username);
    query.bindValue(":password_hash", passwordHash);
    query.bindValue(":email", email);
    query.bindValue(":public_key", publicKey);

    if (!query.exec()) {
        qWarning() << "[DB] Create user failed:" << query.lastError().text();
        return false;
    }

    qDebug() << "[DB] User created:" << username;
    return true;
}

UserInfo DatabaseManager::getUserById(int userId)
{
    UserInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, username, email, public_key, is_active, created_at "
                  "FROM public.users WHERE id = :id LIMIT 1");
    query.bindValue(":id", userId);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.username = query.value("username").toString();
        info.email = query.value("email").toString();
        info.publicKey = query.value("public_key").toString();
        info.isActive = query.value("is_active").toBool();
        info.createdAt = query.value("created_at").toDateTime();
    }

    return info;
}

UserInfo DatabaseManager::getUserByUsername(const QString &username)
{
    UserInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, username, email, public_key, is_active, created_at "
                  "FROM public.users WHERE username = :username LIMIT 1");
    query.bindValue(":username", username);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.username = query.value("username").toString();
        info.email = query.value("email").toString();
        info.publicKey = query.value("public_key").toString();
        info.isActive = query.value("is_active").toBool();
        info.createdAt = query.value("created_at").toDateTime();
    }

    return info;
}

UserInfo DatabaseManager::getUserByEmail(const QString &email)
{
    UserInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, username, email, public_key, is_active, created_at "
                  "FROM public.users WHERE email = :email LIMIT 1");
    query.bindValue(":email", email);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.username = query.value("username").toString();
        info.email = query.value("email").toString();
        info.publicKey = query.value("public_key").toString();
        info.isActive = query.value("is_active").toBool();
        info.createdAt = query.value("created_at").toDateTime();
    }

    return info;
}

bool DatabaseManager::updateUserPassword(int userId, const QString &newPasswordHash)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("UPDATE public.users SET password_hash = :hash, updated_at = CURRENT_TIMESTAMP "
                  "WHERE id = :id");
    query.bindValue(":hash", newPasswordHash);
    query.bindValue(":id", userId);

    if (!query.exec()) {
        qWarning() << "[DB] Update password failed:" << query.lastError().text();
        return false;
    }

    return query.numRowsAffected() > 0;
}

bool DatabaseManager::deactivateUser(int userId)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("UPDATE public.users SET is_active = false, updated_at = CURRENT_TIMESTAMP "
                  "WHERE id = :id");
    query.bindValue(":id", userId);

    if (!query.exec()) {
        qWarning() << "[DB] Deactivate user failed:" << query.lastError().text();
        return false;
    }

    // Revoke all sessions for this user
    revokeAllUserSessions(userId);
    return query.numRowsAffected() > 0;
}

bool DatabaseManager::activateUser(int userId)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("UPDATE public.users SET is_active = true, updated_at = CURRENT_TIMESTAMP "
                  "WHERE id = :id");
    query.bindValue(":id", userId);

    if (!query.exec()) {
        qWarning() << "[DB] Activate user failed:" << query.lastError().text();
        return false;
    }

    return query.numRowsAffected() > 0;
}

bool DatabaseManager::isUsernameTaken(const QString &username) const
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT COUNT(*) FROM public.users WHERE username = :username");
    query.bindValue(":username", username);

    if (query.exec() && query.next()) {
        return query.value(0).toInt() > 0;
    }
    return false;
}

bool DatabaseManager::isEmailRegistered(const QString &email) const
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT COUNT(*) FROM public.users WHERE email = :email");
    query.bindValue(":email", email);

    if (query.exec() && query.next()) {
        return query.value(0).toInt() > 0;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────
SessionInfo DatabaseManager::createSession(int userId, const QString &token,
                                            const QString &ipAddress, int expirySeconds)
{
    SessionInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("INSERT INTO public.sessions (user_id, token, ip_address, expires_at) "
                  "VALUES (:user_id, :token, :ip_address, "
                  "CURRENT_TIMESTAMP + make_interval(secs => :expiry)) "
                  "RETURNING id, created_at, expires_at");
    query.bindValue(":user_id", userId);
    query.bindValue(":token", token);
    query.bindValue(":ip_address", ipAddress.isEmpty() ? QVariant(QVariant::String) : ipAddress);
    query.bindValue(":expiry", expirySeconds);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.userId = userId;
        info.token = token;
        info.ipAddress = ipAddress;
        info.createdAt = query.value("created_at").toDateTime();
        info.expiresAt = query.value("expires_at").toDateTime();
        info.isRevoked = false;
        qDebug() << "[DB] Session created for user_id:" << userId;
    } else {
        qWarning() << "[DB] Create session failed:" << query.lastError().text();
    }

    return info;
}

SessionInfo DatabaseManager::getSessionByToken(const QString &token)
{
    SessionInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, user_id, token, ip_address, expires_at, created_at, is_revoked "
                  "FROM public.sessions WHERE token = :token LIMIT 1");
    query.bindValue(":token", token);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.userId = query.value("user_id").toInt();
        info.token = query.value("token").toString();
        info.ipAddress = query.value("ip_address").toString();
        info.expiresAt = query.value("expires_at").toDateTime();
        info.createdAt = query.value("created_at").toDateTime();
        info.isRevoked = query.value("is_revoked").toBool();
    }

    return info;
}

bool DatabaseManager::revokeSession(int sessionId)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("UPDATE public.sessions SET is_revoked = true WHERE id = :id");
    query.bindValue(":id", sessionId);

    if (!query.exec()) {
        qWarning() << "[DB] Revoke session failed:" << query.lastError().text();
        return false;
    }

    qDebug() << "[DB] Session revoked:" << sessionId;
    return query.numRowsAffected() > 0;
}

bool DatabaseManager::revokeAllUserSessions(int userId)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("UPDATE public.sessions SET is_revoked = true "
                  "WHERE user_id = :user_id AND is_revoked = false");
    query.bindValue(":user_id", userId);

    if (!query.exec()) {
        qWarning() << "[DB] Revoke all sessions failed:" << query.lastError().text();
        return false;
    }

    qDebug() << "[DB] All sessions revoked for user:" << userId;
    return true;
}

QVector<SessionInfo> DatabaseManager::getActiveSessionsForUser(int userId)
{
    QVector<SessionInfo> result;
    if (!m_connected) return result;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, user_id, token, ip_address, expires_at, created_at, is_revoked "
                  "FROM public.sessions WHERE user_id = :user_id AND is_revoked = false "
                  "AND expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC");
    query.bindValue(":user_id", userId);

    if (query.exec()) {
        while (query.next()) {
            SessionInfo info;
            info.id = query.value("id").toInt();
            info.userId = query.value("user_id").toInt();
            info.token = query.value("token").toString();
            info.ipAddress = query.value("ip_address").toString();
            info.expiresAt = query.value("expires_at").toDateTime();
            info.createdAt = query.value("created_at").toDateTime();
            info.isRevoked = query.value("is_revoked").toBool();
            result.append(info);
        }
    }

    return result;
}

bool DatabaseManager::isSessionValid(const QString &token) const
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT COUNT(*) FROM public.sessions WHERE token = :token "
                  "AND is_revoked = false AND expires_at > CURRENT_TIMESTAMP");
    query.bindValue(":token", token);

    if (query.exec() && query.next()) {
        return query.value(0).toInt() > 0;
    }
    return false;
}

void DatabaseManager::cleanupExpiredSessions()
{
    if (!m_connected) return;

    QSqlQuery query(getDatabase());
    query.prepare("DELETE FROM public.sessions WHERE expires_at < CURRENT_TIMESTAMP OR is_revoked = true");
    if (query.exec()) {
        qDebug() << "[DB] Expired sessions cleaned up:" << query.numRowsAffected();
    }
}

// ─────────────────────────────────────────────────────────────
// Files
// ─────────────────────────────────────────────────────────────
bool DatabaseManager::registerFileTransfer(int senderId, int receiverId,
                                            const QString &fileName, const QString &fileHash,
                                            qint64 fileSize, const QString &algorithm)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("INSERT INTO public.files (sender_id, receiver_id, file_name, file_hash, "
                  "file_size, encryption_algorithm) "
                  "VALUES (:sender_id, :receiver_id, :file_name, :file_hash, "
                  ":file_size, :algorithm)");
    query.bindValue(":sender_id", senderId);
    query.bindValue(":receiver_id", receiverId > 0 ? receiverId : QVariant(QVariant::Int));
    query.bindValue(":file_name", fileName);
    query.bindValue(":file_hash", fileHash);
    query.bindValue(":file_size", fileSize);
    query.bindValue(":algorithm", algorithm);

    if (!query.exec()) {
        qWarning() << "[DB] Register file transfer failed:" << query.lastError().text();
        return false;
    }

    qDebug() << "[DB] File transfer registered:" << fileName;
    return true;
}

QVector<FileTransferInfo> DatabaseManager::getFilesSentByUser(int userId)
{
    QVector<FileTransferInfo> result;
    if (!m_connected) return result;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, sender_id, receiver_id, file_name, file_hash, file_size, "
                  "encryption_algorithm, created_at FROM public.files "
                  "WHERE sender_id = :user_id ORDER BY created_at DESC");
    query.bindValue(":user_id", userId);

    if (query.exec()) {
        while (query.next()) {
            FileTransferInfo info;
            info.id = query.value("id").toInt();
            info.senderId = query.value("sender_id").toInt();
            info.receiverId = query.value("receiver_id").toInt();
            info.fileName = query.value("file_name").toString();
            info.fileHash = query.value("file_hash").toString();
            info.fileSize = query.value("file_size").toLongLong();
            info.encryptionAlgorithm = query.value("encryption_algorithm").toString();
            info.createdAt = query.value("created_at").toDateTime();
            result.append(info);
        }
    }

    return result;
}

QVector<FileTransferInfo> DatabaseManager::getFilesReceivedByUser(int userId)
{
    QVector<FileTransferInfo> result;
    if (!m_connected) return result;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, sender_id, receiver_id, file_name, file_hash, file_size, "
                  "encryption_algorithm, created_at FROM public.files "
                  "WHERE receiver_id = :user_id ORDER BY created_at DESC");
    query.bindValue(":user_id", userId);

    if (query.exec()) {
        while (query.next()) {
            FileTransferInfo info;
            info.id = query.value("id").toInt();
            info.senderId = query.value("sender_id").toInt();
            info.receiverId = query.value("receiver_id").toInt();
            info.fileName = query.value("file_name").toString();
            info.fileHash = query.value("file_hash").toString();
            info.fileSize = query.value("file_size").toLongLong();
            info.encryptionAlgorithm = query.value("encryption_algorithm").toString();
            info.createdAt = query.value("created_at").toDateTime();
            result.append(info);
        }
    }

    return result;
}

FileTransferInfo DatabaseManager::getFileById(int fileId)
{
    FileTransferInfo info;
    if (!m_connected) return info;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, sender_id, receiver_id, file_name, file_hash, file_size, "
                  "encryption_algorithm, created_at FROM public.files WHERE id = :id LIMIT 1");
    query.bindValue(":id", fileId);

    if (query.exec() && query.next()) {
        info.id = query.value("id").toInt();
        info.senderId = query.value("sender_id").toInt();
        info.receiverId = query.value("receiver_id").toInt();
        info.fileName = query.value("file_name").toString();
        info.fileHash = query.value("file_hash").toString();
        info.fileSize = query.value("file_size").toLongLong();
        info.encryptionAlgorithm = query.value("encryption_algorithm").toString();
        info.createdAt = query.value("created_at").toDateTime();
    }

    return info;
}

// ─────────────────────────────────────────────────────────────
// Audit logs
// ─────────────────────────────────────────────────────────────
bool DatabaseManager::addAuditLog(int userId, const QString &action, const QString &tableName,
                                   int recordId, const QString &oldValues,
                                   const QString &newValues, const QString &ipAddress)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare("INSERT INTO public.audit_logs (user_id, action, table_name, record_id, "
                  "old_values, new_values, ip_address) "
                  "VALUES (:user_id, :action, :table_name, :record_id, "
                  ":old_values::jsonb, :new_values::jsonb, :ip_address::inet)");
    query.bindValue(":user_id", userId > 0 ? userId : QVariant(QVariant::Int));
    query.bindValue(":action", action);
    query.bindValue(":table_name", tableName);
    query.bindValue(":record_id", recordId > 0 ? recordId : QVariant(QVariant::Int));
    query.bindValue(":old_values", oldValues.isEmpty() ? "null" : oldValues);
    query.bindValue(":new_values", newValues.isEmpty() ? "null" : newValues);
    query.bindValue(":ip_address", ipAddress.isEmpty() ? QVariant(QVariant::String) : ipAddress);

    if (!query.exec()) {
        qWarning() << "[DB] Add audit log failed:" << query.lastError().text();
        return false;
    }

    return true;
}

QVector<AuditLogEntry> DatabaseManager::getAuditLogsForUser(int userId, int limit)
{
    QVector<AuditLogEntry> result;
    if (!m_connected) return result;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, user_id, action, table_name, record_id, "
                  "old_values::text, new_values::text, ip_address, created_at "
                  "FROM public.audit_logs WHERE user_id = :user_id "
                  "ORDER BY created_at DESC LIMIT :limit");
    query.bindValue(":user_id", userId);
    query.bindValue(":limit", limit);

    if (query.exec()) {
        while (query.next()) {
            AuditLogEntry entry;
            entry.id = query.value("id").toInt();
            entry.userId = query.value("user_id").toInt();
            entry.action = query.value("action").toString();
            entry.tableName = query.value("table_name").toString();
            entry.recordId = query.value("record_id").toInt();
            entry.oldValues = query.value("old_values").toString();
            entry.newValues = query.value("new_values").toString();
            entry.ipAddress = query.value("ip_address").toString();
            entry.createdAt = query.value("created_at").toDateTime();
            result.append(entry);
        }
    }

    return result;
}

QVector<AuditLogEntry> DatabaseManager::getRecentAuditLogs(int limit)
{
    QVector<AuditLogEntry> result;
    if (!m_connected) return result;

    QSqlQuery query(getDatabase());
    query.prepare("SELECT id, user_id, action, table_name, record_id, "
                  "old_values::text, new_values::text, ip_address, created_at "
                  "FROM public.audit_logs ORDER BY created_at DESC LIMIT :limit");
    query.bindValue(":limit", limit);

    if (query.exec()) {
        while (query.next()) {
            AuditLogEntry entry;
            entry.id = query.value("id").toInt();
            entry.userId = query.value("user_id").toInt();
            entry.action = query.value("action").toString();
            entry.tableName = query.value("table_name").toString();
            entry.recordId = query.value("record_id").toInt();
            entry.oldValues = query.value("old_values").toString();
            entry.newValues = query.value("new_values").toString();
            entry.ipAddress = query.value("ip_address").toString();
            entry.createdAt = query.value("created_at").toDateTime();
            result.append(entry);
        }
    }

    return result;
}

// ─────────────────────────────────────────────────────────────
// Общие
// ─────────────────────────────────────────────────────────────
bool DatabaseManager::executeQuery(const QString &sql, const QMap<QString, QVariant> &params)
{
    if (!m_connected) return false;

    QSqlQuery query(getDatabase());
    query.prepare(sql);

    for (auto it = params.begin(); it != params.end(); ++it) {
        query.bindValue(it.key(), it.value());
    }

    if (!query.exec()) {
        qWarning() << "[DB] Execute query failed:" << query.lastError().text();
        return false;
    }

    return true;
}