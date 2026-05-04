#include "databasemanager.h"
#include <QSqlRecord>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>

DatabaseManager::DatabaseManager(QObject *parent)
    : QObject(parent)
    , m_connected(false)
{
}

DatabaseManager::~DatabaseManager()
{
    disconnect();
}

DatabaseManager& DatabaseManager::getInstance()
{
    static DatabaseManager instance;
    return instance;
}

// ────────────────────────────────────────────────────────────────────
bool DatabaseManager::connect(const QString &host, int port, const QString &dbName,
                              const QString &user, const QString &password)
{
    QMutexLocker locker(&m_mutex);

    if (m_connected) return true;

    m_db = QSqlDatabase::addDatabase("QPSQL", "server_connection");
    m_db.setHostName(host);
    m_db.setPort(port);
    m_db.setDatabaseName(dbName);
    m_db.setUserName(user);
    m_db.setPassword(password);

    // SSL: для production использовать sslmode=require (установить CRYPTEX_DB_SSLMODE=require)
    QString sslMode = qEnvironmentVariable("CRYPTEX_DB_SSLMODE", "prefer");
    m_db.setConnectOptions(QString("sslmode=%1").arg(sslMode));

    if (!m_db.open()) {
        qCritical() << "[DB] Connection failed:" << m_db.lastError().text();
        m_connected = false;
        return false;
    }

    // Настройка для безопасности
    QSqlQuery q(m_db);
    q.exec("SET application_name = 'cryptex_server'");
    q.exec("SET statement_timeout = '30000'");  // 30 сек максимум на запрос

    m_connected = true;
    qInfo() << "[DB] Connected to PostgreSQL" << host << port << dbName;
    return true;
}

void DatabaseManager::disconnect()
{
    QMutexLocker locker(&m_mutex);
    if (m_db.isOpen()) {
        m_db.close();
    }
    m_connected = false;
    QSqlDatabase::removeDatabase("server_connection");
}

bool DatabaseManager::isConnected() const
{
    QMutexLocker locker(&m_mutex);
    return m_connected && m_db.isOpen();
}

// ────────────────────────────────────────────────────────────────────
// ПОЛЬЗОВАТЕЛИ
// ────────────────────────────────────────────────────────────────────
bool DatabaseManager::createUser(const QString &username, const QString &passwordHash,
                                 const QString &email, const QString &publicKey)
{
    QMutexLocker locker(&m_mutex);
    if (!m_connected) return false;

    QSqlQuery q(m_db);
    q.prepare("INSERT INTO users (username, password_hash, email, public_key) "
              "VALUES (:username, :phash, :email, :pkey)");
    q.bindValue(":username", username);
    q.bindValue(":phash", passwordHash);
    q.bindValue(":email", email.toLower());
    q.bindValue(":pkey", publicKey);

    if (!q.exec()) {
        qWarning() << "[DB] createUser failed:" << q.lastError().text();
        return false;
    }

    addAuditLogSimple(-1, "USER_REGISTER: " + username, true);
    return true;
}

UserInfo DatabaseManager::getUserByUsername(const QString &username) const
{
    QMutexLocker locker(&m_mutex);
    UserInfo info;

    QSqlQuery q(m_db);
    q.prepare("SELECT id, username, email, public_key, is_active, created_at "
              "FROM users WHERE username = :uname");
    q.bindValue(":uname", username);

    if (!q.exec() || !q.next()) return info;

    info.id = q.value(0).toInt();
    info.username = q.value(1).toString();
    info.email = q.value(2).toString();
    info.publicKey = q.value(3).toString();
    info.isActive = q.value(4).toBool();
    info.createdAt = q.value(5).toDateTime();
    return info;
}

UserInfo DatabaseManager::getUserById(int id) const
{
    QMutexLocker locker(&m_mutex);
    UserInfo info;

    QSqlQuery q(m_db);
    q.prepare("SELECT id, username, email, public_key, is_active, created_at "
              "FROM users WHERE id = :id");
    q.bindValue(":id", id);

    if (!q.exec() || !q.next()) return info;

    info.id = q.value(0).toInt();
    info.username = q.value(1).toString();
    info.email = q.value(2).toString();
    info.publicKey = q.value(3).toString();
    info.isActive = q.value(4).toBool();
    info.createdAt = q.value(5).toDateTime();
    return info;
}

bool DatabaseManager::isUsernameTaken(const QString &username) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT EXISTS(SELECT 1 FROM users WHERE username = :uname)");
    q.bindValue(":uname", username);
    return q.exec() && q.next() && q.value(0).toBool();
}

bool DatabaseManager::isEmailRegistered(const QString &email) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER(:email))");
    q.bindValue(":email", email);
    return q.exec() && q.next() && q.value(0).toBool();
}

bool DatabaseManager::verifyPassword(const QString &username, const QString &passwordHash) const
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.prepare("SELECT password_hash FROM users WHERE username = :uname AND is_active = TRUE");
    q.bindValue(":uname", username);

    if (!q.exec() || !q.next()) return false;

    QString storedHash = q.value(0).toString();
    // Используем constant-time сравнение через PostgreSQL
    QSqlQuery verifyQ(m_db);
    verifyQ.prepare("SELECT crypt(:input_password, :stored_hash) = :stored_hash");
    verifyQ.bindValue(":input_password", passwordHash);
    verifyQ.bindValue(":stored_hash", storedHash);

    return verifyQ.exec() && verifyQ.next() && verifyQ.value(0).toBool();
}

bool DatabaseManager::updatePassword(const QString &username, const QString &newHash)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE users SET password_hash = :phash, updated_at = CURRENT_TIMESTAMP "
              "WHERE username = :uname");
    q.bindValue(":phash", newHash);
    q.bindValue(":uname", username);

    if (!q.exec()) return false;

    addAuditLogSimple(-1, "PASSWORD_CHANGE: " + username, true);
    return true;
}

bool DatabaseManager::incrementFailedAttempts(const QString &username)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE users SET failed_attempts = failed_attempts + 1 "
              "WHERE username = :uname");
    q.bindValue(":uname", username);
    return q.exec();
}

bool DatabaseManager::lockUser(const QString &username, int seconds)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE users SET locked_until = CURRENT_TIMESTAMP + "
              "make_interval(secs := :secs) WHERE username = :uname");
    q.bindValue(":secs", seconds);
    q.bindValue(":uname", username);

    if (!q.exec()) return false;
    addAuditLogSimple(-1, "USER_LOCKED: " + username, true);
    return true;
}

bool DatabaseManager::resetFailedAttempts(const QString &username)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE users SET failed_attempts = 0, "
              "locked_until = NULL WHERE username = :uname");
    q.bindValue(":uname", username);
    return q.exec();
}

bool DatabaseManager::isUserLocked(const QString &username) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT locked_until > CURRENT_TIMESTAMP "
              "FROM users WHERE username = :uname");
    q.bindValue(":uname", username);
    return q.exec() && q.next() && q.value(0).toBool();
}

// ────────────────────────────────────────────────────────────────────
// СЕССИИ
// ────────────────────────────────────────────────────────────────────
SessionInfo DatabaseManager::createSession(int userId, const QString &token,
                                           const QString &ipAddress, int ttlSeconds)
{
    QMutexLocker locker(&m_mutex);
    SessionInfo info;

    // Ревокируем старые сессии этого пользователя (макс 3 активных)
    QSqlQuery revokeQ(m_db);
    revokeQ.prepare("UPDATE sessions SET is_revoked = TRUE "
                    "WHERE user_id = :uid AND is_revoked = FALSE "
                    "AND id NOT IN (SELECT id FROM sessions WHERE user_id = :uid2 "
                    "AND is_revoked = FALSE ORDER BY created_at DESC LIMIT 2)");
    revokeQ.bindValue(":uid", userId);
    revokeQ.bindValue(":uid2", userId);
    revokeQ.exec();

    QSqlQuery q(m_db);
    q.prepare("INSERT INTO sessions (user_id, token, ip_address, expires_at) "
              "VALUES (:uid, :token, :ip, CURRENT_TIMESTAMP + make_interval(secs := :ttl)) "
              "RETURNING id, created_at");
    q.bindValue(":uid", userId);
    q.bindValue(":token", token);
    q.bindValue(":ip", ipAddress.isEmpty() ? QVariant() : ipAddress);
    q.bindValue(":ttl", ttlSeconds);

    if (!q.exec() || !q.next()) return info;

    info.id = q.value(0).toInt();
    info.userId = userId;
    info.token = token;
    info.ipAddress = ipAddress;
    info.expiresAt = QDateTime::currentDateTime().addSecs(ttlSeconds);
    info.isRevoked = false;

    addAuditLogSimple(userId, "SESSION_CREATE", true);
    return info;
}

SessionInfo DatabaseManager::validateSession(const QString &token) const
{
    QMutexLocker locker(&m_mutex);
    SessionInfo info;

    QSqlQuery q(m_db);
    q.prepare("SELECT s.id, s.user_id, s.ip_address, s.expires_at, "
              "s.is_revoked, u.is_active, u.locked_until "
              "FROM sessions s JOIN users u ON s.user_id = u.id "
              "WHERE s.token = :token");
    q.bindValue(":token", token);

    if (!q.exec() || !q.next()) return info;

    if (q.value(4).toBool()) return info;  // revoked
    if (!q.value(5).toBool()) return info;  // user inactive

    QDateTime lockedUntil = q.value(6).toDateTime();
    if (lockedUntil.isValid() && lockedUntil > QDateTime::currentDateTime()) return info;

    QDateTime expiresAt = q.value(3).toDateTime();
    if (expiresAt < QDateTime::currentDateTime()) return info;

    info.id = q.value(0).toInt();
    info.userId = q.value(1).toInt();
    info.token = token;
    info.ipAddress = q.value(2).toString();
    info.expiresAt = expiresAt;
    info.isRevoked = false;
    return info;
}

bool DatabaseManager::revokeSession(const QString &token)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE sessions SET is_revoked = TRUE WHERE token = :token");
    q.bindValue(":token", token);
    return q.exec();
}

bool DatabaseManager::revokeAllUserSessions(int userId)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE sessions SET is_revoked = TRUE WHERE user_id = :uid");
    q.bindValue(":uid", userId);
    if (!q.exec()) return false;

    addAuditLogSimple(userId, "ALL_SESSIONS_REVOKED", true);
    return true;
}

bool DatabaseManager::cleanupExpiredSessions()
{
    QSqlQuery q(m_db);
    return q.exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP");
}

// ────────────────────────────────────────────────────────────────────
// КОНТАКТЫ
// ────────────────────────────────────────────────────────────────────
bool DatabaseManager::sendContactRequest(int senderId, int receiverId, const QString &comment)
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO contact_requests (sender_id, receiver_id, comment) "
              "VALUES (:sid, :rid, :comment) "
              "ON CONFLICT (sender_id, receiver_id, status) DO UPDATE "
              "SET comment = :comment2, created_at = CURRENT_TIMESTAMP");
    q.bindValue(":sid", senderId);
    q.bindValue(":rid", receiverId);
    q.bindValue(":comment", comment.left(500));
    q.bindValue(":comment2", comment.left(500));

    if (!q.exec()) return false;

    addAuditLogSimple(senderId, "CONTACT_REQUEST_SENT to " + QString::number(receiverId), true);
    return true;
}

bool DatabaseManager::acceptContactRequest(int requestId, int receiverId)
{
    QMutexLocker locker(&m_mutex);
    fprintf(stderr, "[DB] acceptContactRequest ENTERED requestId=%d receiverId=%d\n", requestId, receiverId);
    fflush(stderr);

    // Шаг 1: SELECT (чистый QSqlQuery, без prepare)
    int senderId = -1;
    {
        QSqlQuery q(m_db);
        QString sql = QString("SELECT sender_id FROM contact_requests WHERE id=%1 AND receiver_id=%2 AND status='pending'")
                      .arg(requestId).arg(receiverId);
        if (!q.exec(sql) || !q.next()) {
            fprintf(stderr, "[DB] acceptContactRequest: NO PENDING ROW\n");
            fflush(stderr);
            return false;
        }
        senderId = q.value(0).toInt();
        fprintf(stderr, "[DB] acceptContactRequest: FOUND sender=%d\n", senderId);
        fflush(stderr);
    } // q уничтожен, prepared statement cache чист

    // Шаг 2: INSERT (новый QSqlQuery)
    {
        QSqlQuery q(m_db);
        QString sql = QString("INSERT INTO contacts (user_id_a,user_id_b) VALUES (LEAST(%1,%2),GREATEST(%1,%2)) ON CONFLICT DO NOTHING")
                      .arg(senderId).arg(receiverId);
        if (!q.exec(sql)) {
            fprintf(stderr, "[DB] acceptContactRequest: INSERT FAILED '%s'\n", qPrintable(q.lastError().text()));
            fflush(stderr);
            return false;
        }
        fprintf(stderr, "[DB] acceptContactRequest: INSERT OK\n");
        fflush(stderr);
    }

    // Шаг 3: UPDATE (новый QSqlQuery)
    {
        QSqlQuery q(m_db);
        QString sql = QString("UPDATE contact_requests SET status='accepted', responded_at=CURRENT_TIMESTAMP WHERE id=%1")
                      .arg(requestId);
        if (!q.exec(sql)) {
            fprintf(stderr, "[DB] acceptContactRequest: UPDATE FAILED '%s'\n", qPrintable(q.lastError().text()));
            fflush(stderr);
            return false;
        }
        fprintf(stderr, "[DB] acceptContactRequest: UPDATE OK\n");
        fflush(stderr);
    }

    fprintf(stderr, "[DB] acceptContactRequest: SUCCESS\n");
    fflush(stderr);
    addAuditLogSimple(receiverId, "CONTACT_ACCEPTED", true);
    return true;
}

bool DatabaseManager::rejectContactRequest(int requestId, int receiverId)
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.prepare("UPDATE contact_requests SET status = 'rejected', "
              "responded_at = CURRENT_TIMESTAMP "
              "WHERE id = :id AND receiver_id = :rid AND status = 'pending'");
    q.bindValue(":id", requestId);
    q.bindValue(":rid", receiverId);

    if (!q.exec()) {
        qWarning() << "[DB] rejectContactRequest exec FAILED:" << q.lastError().text();
        return false;
    }
    if (q.numRowsAffected() == 0) {
        qWarning() << "[DB] rejectContactRequest: no rows updated for id=" << requestId
                   << "receiverId=" << receiverId;
        return false;
    }
    addAuditLogSimple(receiverId, "CONTACT_REJECTED request " + QString::number(requestId), true);
    return true;
}

bool DatabaseManager::removeContact(int userIdA, int userIdB)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM contacts "
              "WHERE (user_id_a = LEAST(:a, :b) AND user_id_b = GREATEST(:a, :b))");
    q.bindValue(":a", userIdA);
    q.bindValue(":b", userIdB);

    if (!q.exec()) return false;
    addAuditLogSimple(userIdA, "CONTACT_REMOVED with " + QString::number(userIdB), true);
    return true;
}

QList<ContactInfo> DatabaseManager::getContacts(int userId) const
{
    QMutexLocker locker(&m_mutex);
    QList<ContactInfo> list;

    QSqlQuery q(m_db);
    q.prepare("SELECT c.id, c.user_id_a, c.user_id_b, "
              "ua.username, ub.username, c.created_at "
              "FROM contacts c "
              "JOIN users ua ON c.user_id_a = ua.id "
              "JOIN users ub ON c.user_id_b = ub.id "
              "WHERE c.user_id_a = :uid OR c.user_id_b = :uid2 "
              "ORDER BY c.created_at DESC");
    q.bindValue(":uid", userId);
    q.bindValue(":uid2", userId);

    if (!q.exec()) return list;

    while (q.next()) {
        ContactInfo ci;
        ci.id = q.value(0).toInt();
        ci.userIdA = q.value(1).toInt();
        ci.userIdB = q.value(2).toInt();
        ci.usernameA = q.value(3).toString();
        ci.usernameB = q.value(4).toString();
        ci.createdAt = q.value(5).toDateTime();
        list.append(ci);
    }
    return list;
}

QList<ContactRequestInfo> DatabaseManager::getIncomingRequests(int userId) const
{
    QMutexLocker locker(&m_mutex);
    QList<ContactRequestInfo> list;

    QSqlQuery q(m_db);
    q.prepare("SELECT cr.id, cr.sender_id, cr.receiver_id, u.username, "
              "cr.comment, cr.status, cr.created_at "
              "FROM contact_requests cr "
              "JOIN users u ON cr.sender_id = u.id "
              "WHERE cr.receiver_id = :uid AND cr.status = 'pending' "
              "ORDER BY cr.created_at DESC");
    q.bindValue(":uid", userId);

    if (!q.exec()) return list;

    while (q.next()) {
        ContactRequestInfo ri;
        ri.id = q.value(0).toInt();
        ri.senderId = q.value(1).toInt();
        ri.receiverId = q.value(2).toInt();
        ri.senderName = q.value(3).toString();
        ri.comment = q.value(4).toString();
        ri.status = q.value(5).toString();
        ri.createdAt = q.value(6).toDateTime();
        list.append(ri);
    }
    return list;
}

QList<ContactRequestInfo> DatabaseManager::getOutgoingRequests(int userId) const
{
    QMutexLocker locker(&m_mutex);
    QList<ContactRequestInfo> list;

    QSqlQuery q(m_db);
    q.prepare("SELECT cr.id, cr.sender_id, cr.receiver_id, u.username, "
              "cr.comment, cr.status, cr.created_at "
              "FROM contact_requests cr "
              "JOIN users u ON cr.receiver_id = u.id "
              "WHERE cr.sender_id = :uid AND cr.status = 'pending' "
              "ORDER BY cr.created_at DESC");
    q.bindValue(":uid", userId);

    if (!q.exec()) return list;

    while (q.next()) {
        ContactRequestInfo ri;
        ri.id = q.value(0).toInt();
        ri.senderId = q.value(1).toInt();
        ri.receiverId = q.value(2).toInt();
        ri.senderName = q.value(3).toString();  // это receiver name
        ri.comment = q.value(4).toString();
        ri.status = q.value(5).toString();
        ri.createdAt = q.value(6).toDateTime();
        list.append(ri);
    }
    return list;
}

bool DatabaseManager::areContacts(int userIdA, int userIdB) const
{
    QSqlQuery q(m_db);
    int lo = qMin(userIdA, userIdB);
    int hi = qMax(userIdA, userIdB);
    q.prepare("SELECT EXISTS(SELECT 1 FROM contacts "
              "WHERE user_id_a = :lo AND user_id_b = :hi)");
    q.bindValue(":lo", lo);
    q.bindValue(":hi", hi);
    bool result = q.exec() && q.next() && q.value(0).toBool();
    fprintf(stderr, "[DB] areContacts(%d,%d) lo=%d hi=%d -> %d\n", userIdA, userIdB, lo, hi, result);
    fflush(stderr);
    return result;
}

// ────────────────────────────────────────────────────────────────────
// ФАЙЛОВЫЕ ПЕРЕДАЧИ
// ────────────────────────────────────────────────────────────────────
int DatabaseManager::createFileTransfer(int senderId, int receiverId, const QString &fileName,
                                        const QString &fileHash, qint64 fileSize,
                                        const QString &storagePath, int ttlHours)
{
    QMutexLocker locker(&m_mutex);

    QSqlQuery q(m_db);
    q.prepare("INSERT INTO file_transfers "
              "(sender_id, receiver_id, file_name, file_hash, file_size, "
              "storage_path, expires_at, status) "
              "VALUES (:sid, :rid, :fname, :hash, :fsize, :spath, "
              "CURRENT_TIMESTAMP + make_interval(hours := :ttl), 'pending') "
              "RETURNING id");
    q.bindValue(":sid", senderId);
    q.bindValue(":rid", receiverId);
    q.bindValue(":fname", fileName);
    q.bindValue(":hash", fileHash);
    q.bindValue(":fsize", fileSize);
    q.bindValue(":spath", storagePath);
    q.bindValue(":ttl", ttlHours);

    if (!q.exec() || !q.next()) {
        qWarning() << "[DB] createFileTransfer failed:" << q.lastError().text();
        return -1;
    }

    int id = q.value(0).toInt();
    addAuditLogSimple(senderId, "FILE_TRANSFER_CREATED id=" + QString::number(id), true);
    return id;
}

bool DatabaseManager::updateTransferStatus(int transferId, const QString &status)
{
    QSqlQuery q(m_db);
    if (status == "completed") {
        q.prepare("UPDATE file_transfers SET status = :st, completed_at = CURRENT_TIMESTAMP "
                  "WHERE id = :id");
    } else {
        q.prepare("UPDATE file_transfers SET status = :st WHERE id = :id");
    }
    q.bindValue(":st", status);
    q.bindValue(":id", transferId);

    if (!q.exec()) return false;
    addAuditLogSimple(-1, "TRANSFER_STATUS_" + status.toUpper() + " id=" + QString::number(transferId), true);
    return true;
}

bool DatabaseManager::updateTransferProgress(int transferId, qint64 bytes)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE file_transfers SET bytes_transferred = :bytes WHERE id = :id");
    q.bindValue(":bytes", bytes);
    q.bindValue(":id", transferId);
    return q.exec();
}

bool DatabaseManager::incrementDownloadCount(int transferId)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE file_transfers SET download_count = download_count + 1 WHERE id = :id");
    q.bindValue(":id", transferId);
    return q.exec();
}

FileTransferInfo DatabaseManager::getFileTransfer(int transferId) const
{
    QMutexLocker locker(&m_mutex);
    FileTransferInfo info;

    QSqlQuery q(m_db);
    q.prepare("SELECT ft.id, ft.sender_id, ft.receiver_id, u.username, "
              "ft.file_name, ft.file_hash, ft.file_size, ft.storage_path, "
              "ft.status, ft.created_at, ft.expires_at, ft.max_downloads, "
              "ft.download_count "
              "FROM file_transfers ft "
              "JOIN users u ON ft.sender_id = u.id "
              "WHERE ft.id = :id");
    q.bindValue(":id", transferId);

    if (!q.exec() || !q.next()) return info;

    info.id = q.value(0).toInt();
    info.senderId = q.value(1).toInt();
    info.receiverId = q.value(2).toInt();
    info.senderName = q.value(3).toString();
    info.fileName = q.value(4).toString();
    info.fileHash = q.value(5).toString();
    info.fileSize = q.value(6).toLongLong();
    info.storagePath = q.value(7).toString();
    info.status = q.value(8).toString();
    info.createdAt = q.value(9).toDateTime();
    info.expiresAt = q.value(10).toDateTime();
    info.maxDownloads = q.value(11).toInt();
    info.downloadCount = q.value(12).toInt();
    return info;
}

QList<FileTransferInfo> DatabaseManager::getPendingTransfers(int userId) const
{
    QMutexLocker locker(&m_mutex);
    QList<FileTransferInfo> list;

    QSqlQuery q(m_db);
    q.prepare("SELECT ft.id, ft.sender_id, ft.receiver_id, u.username, "
              "ft.file_name, ft.file_hash, ft.file_size, ft.storage_path, "
              "ft.status, ft.created_at, ft.expires_at, ft.max_downloads, "
              "ft.download_count "
              "FROM file_transfers ft "
              "JOIN users u ON ft.sender_id = u.id "
              "WHERE ft.receiver_id = :uid AND ft.status IN ('ready', 'pending', 'uploading') "
              "AND ft.download_count < ft.max_downloads "
              "AND ft.expires_at > CURRENT_TIMESTAMP "
              "ORDER BY ft.created_at DESC");
    q.bindValue(":uid", userId);

    if (!q.exec()) return list;

    while (q.next()) {
        FileTransferInfo info;
        info.id = q.value(0).toInt();
        info.senderId = q.value(1).toInt();
        info.receiverId = q.value(2).toInt();
        info.senderName = q.value(3).toString();
        info.fileName = q.value(4).toString();
        info.fileHash = q.value(5).toString();
        info.fileSize = q.value(6).toLongLong();
        info.storagePath = q.value(7).toString();
        info.status = q.value(8).toString();
        info.createdAt = q.value(9).toDateTime();
        info.expiresAt = q.value(10).toDateTime();
        info.maxDownloads = q.value(11).toInt();
        info.downloadCount = q.value(12).toInt();
        list.append(info);
    }
    return list;
}

QList<FileTransferInfo> DatabaseManager::getSentTransfers(int userId) const
{
    QMutexLocker locker(&m_mutex);
    QList<FileTransferInfo> list;

    QSqlQuery q(m_db);
    q.prepare("SELECT ft.id, ft.sender_id, ft.receiver_id, u.username, "
              "ft.file_name, ft.file_hash, ft.file_size, ft.storage_path, "
              "ft.status, ft.created_at, ft.expires_at, ft.max_downloads, "
              "ft.download_count "
              "FROM file_transfers ft "
              "JOIN users u ON ft.receiver_id = u.id "
              "WHERE ft.sender_id = :uid "
              "ORDER BY ft.created_at DESC");
    q.bindValue(":uid", userId);

    if (!q.exec()) return list;

    while (q.next()) {
        FileTransferInfo info;
        info.id = q.value(0).toInt();
        info.senderId = q.value(1).toInt();
        info.receiverId = q.value(2).toInt();
        info.senderName = q.value(3).toString();
        info.fileName = q.value(4).toString();
        info.fileHash = q.value(5).toString();
        info.fileSize = q.value(6).toLongLong();
        info.storagePath = q.value(7).toString();
        info.status = q.value(8).toString();
        info.createdAt = q.value(9).toDateTime();
        info.expiresAt = q.value(10).toDateTime();
        info.maxDownloads = q.value(11).toInt();
        info.downloadCount = q.value(12).toInt();
        list.append(info);
    }
    return list;
}

bool DatabaseManager::cancelTransfer(int transferId, int userId)
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE file_transfers SET status = 'cancelled' "
              "WHERE id = :id AND (sender_id = :uid OR receiver_id = :uid2) "
              "AND status IN ('pending', 'uploading', 'ready')");
    q.bindValue(":id", transferId);
    q.bindValue(":uid", userId);
    q.bindValue(":uid2", userId);

    if (!q.exec()) return false;
    addAuditLogSimple(userId, "TRANSFER_CANCELLED id=" + QString::number(transferId), true);
    return true;
}

bool DatabaseManager::cleanupExpiredTransfers()
{
    QSqlQuery q(m_db);
    q.prepare("UPDATE file_transfers SET status = 'expired' "
              "WHERE expires_at < CURRENT_TIMESTAMP AND status IN ('pending', 'ready', 'uploading')");
    if (!q.exec()) return false;

    QSqlQuery del(m_db);
    return del.exec("DELETE FROM file_transfers WHERE status = 'expired' AND expires_at < CURRENT_TIMESTAMP - interval '7 days'");
}

// ────────────────────────────────────────────────────────────────────
// АУДИТ
// ────────────────────────────────────────────────────────────────────
bool DatabaseManager::addAuditLog(int userId, const QString &action,
                                  const QString &tableName, int recordId,
                                  const QString &details, const QString &ipAddress,
                                  bool success)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO audit_logs (user_id, action, table_name, record_id, "
              "details, ip_address, success) "
              "VALUES (:uid, :action, :table, :rid, :details::jsonb, :ip, :success)");
    q.bindValue(":uid", userId > 0 ? userId : QVariant());
    q.bindValue(":action", action);
    q.bindValue(":table", tableName.isEmpty() ? QVariant() : tableName);
    q.bindValue(":rid", recordId > 0 ? recordId : QVariant());
    q.bindValue(":details", details.isEmpty() ? "{}" : details);
    q.bindValue(":ip", ipAddress.isEmpty() ? QVariant() : ipAddress);
    q.bindValue(":success", success);

    return q.exec();
}

bool DatabaseManager::addAuditLogSimple(int userId, const QString &action, bool success)
{
    return addAuditLog(userId, action, QString(), -1, QString(), QString(), success);
}

QString DatabaseManager::getEmailByUsername(const QString &username) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT email FROM users WHERE username = :uname");
    q.bindValue(":uname", username);
    return q.exec() && q.next() ? q.value(0).toString() : QString();
}

int DatabaseManager::purgeOldAuditLogs(int days)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM audit_logs WHERE created_at < CURRENT_TIMESTAMP - "
              "make_interval(days := :days)");
    q.bindValue(":days", days);
    if (!q.exec()) return -1;
    return q.numRowsAffected();
}

// ────────────────────────────────────────────────────────────────────
// СТАТИСТИКА (для консольного мониторинга)
// ────────────────────────────────────────────────────────────────────
int DatabaseManager::userCount() const
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.exec("SELECT COUNT(*) FROM users WHERE is_active = true");
    return q.next() ? q.value(0).toInt() : 0;
}

int DatabaseManager::contactCount() const
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.exec("SELECT COUNT(*) FROM contacts");
    return q.next() ? q.value(0).toInt() : 0;
}

int DatabaseManager::transferCount() const
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.exec("SELECT COUNT(*) FROM file_transfers WHERE status IN ('ready', 'pending', 'uploading')");
    return q.next() ? q.value(0).toInt() : 0;
}

int DatabaseManager::activeSessionCount() const
{
    QMutexLocker locker(&m_mutex);
    QSqlQuery q(m_db);
    q.exec("SELECT COUNT(*) FROM sessions WHERE is_revoked = false AND expires_at > CURRENT_TIMESTAMP");
    return q.next() ? q.value(0).toInt() : 0;
}

QStringList DatabaseManager::getRecentAuditLog(int limit) const
{
    QMutexLocker locker(&m_mutex);
    QStringList log;
    QSqlQuery q(m_db);
    q.prepare("SELECT to_char(created_at, 'YYYY-MM-DD HH24:MI:SS'), "
              "action, success, ip_address "
              "FROM audit_logs ORDER BY created_at DESC LIMIT :lim");
    q.bindValue(":lim", limit);
    if (!q.exec()) return log;
    while (q.next()) {
        QString line = q.value(0).toString()
                       + " | " + q.value(1).toString()
                       + " | " + (q.value(2).toBool() ? "OK" : "FAIL")
                       + " | " + q.value(3).toString();
        log.append(line);
    }
    return log;
}