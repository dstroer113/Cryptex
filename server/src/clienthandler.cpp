#include "clienthandler.h"
#include "databasemanager.h"
#include "protocol.h"
#include "cryptoserver.h"

#include <QSslSocket>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDebug>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace CryptexProtocol;

ClientHandler::ClientHandler(QSslSocket *socket, QSslConfiguration sslConfig,
                             DatabaseManager *db, CryptoServer *server, QObject *parent)
    : QObject(parent)
    , m_sslConfig(std::move(sslConfig))
    , m_socket(socket)
    , m_database(db)
    , m_server(server)
    , m_userId(-1)
    , m_authenticated(false)
    , m_requestCount(0)
    , m_lastRequestTime(0)
{
    if (m_socket) {
        if (!m_socket->isEncrypted()) {
            m_socket->setSslConfiguration(m_sslConfig);
        }
        m_socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        m_socket->setParent(this);
    }
    fprintf(stderr, "[CH] Created for %s (encrypted=%d)\n",
            m_socket ? qPrintable(m_socket->peerAddress().toString()) : "N/A",
            m_socket ? m_socket->isEncrypted() : 0);
    fflush(stderr);
}

ClientHandler::~ClientHandler()
{
    if (m_socket) {
        m_socket->disconnectFromHost();
        if (m_socket->state() != QAbstractSocket::UnconnectedState)
            m_socket->waitForDisconnected(3000);
        m_socket->deleteLater();
    }
}

void ClientHandler::start()
{
    if (!m_socket || m_socket->state() != QAbstractSocket::ConnectedState) {
        fprintf(stderr, "[CH] Socket not connected, aborting\n");
        fflush(stderr);
        emit finished();
        deleteLater();
        return;
    }

    fprintf(stderr, "[CH] start() socket=%p encrypted=%d\n",
            (void*)m_socket, m_socket->isEncrypted());
    fflush(stderr);

    connect(m_socket, &QSslSocket::encrypted, this, &ClientHandler::onEncrypted);
    connect(m_socket, &QSslSocket::readyRead, this, &ClientHandler::onReadyRead);
    connect(m_socket, &QSslSocket::disconnected, this, &ClientHandler::onDisconnected);
    connect(m_socket, &QSslSocket::errorOccurred, this, &ClientHandler::onError);

    if (m_socket->isEncrypted()) {
        fprintf(stderr, "[CH] Socket already encrypted, calling onEncrypted()\n");
        fflush(stderr);
        onEncrypted();
    } else {
        fprintf(stderr, "[CH] Starting server encryption...\n");
        fflush(stderr);
        m_socket->startServerEncryption();
    }
}

void ClientHandler::onEncrypted()
{
    fprintf(stderr, "[CH] SSL handshake complete: %s\n", qPrintable(clientIP()));
    fflush(stderr);
    m_sessionKey = generateSessionKey();
    m_hmacKey = generateSessionKey();

    fprintf(stderr, "[CH] Sending SESSION_KEY to client\n");
    fflush(stderr);

    QJsonObject keyMsg = createMessage("SESSION_KEY", {
        {"session_key", QString(m_sessionKey.toHex())},
        {"hmac_key", QString(m_hmacKey.toHex())}
    });
    QByteArray packet = serializePacketPlain(keyMsg);
    if (!packet.isEmpty() && m_socket && m_socket->isOpen()) {
        m_socket->write(packet);
        fprintf(stderr, "[CH] SESSION_KEY sent (%d bytes)\n", packet.size());
        fflush(stderr);
    }
}

void ClientHandler::onReadyRead()
{
    QByteArray data = m_socket->readAll();
    m_readBuffer.append(data);
    fprintf(stderr, "[CH] onReadyRead: +%d bytes, buffer=%d bytes, encrypted=%d\n",
            data.size(), m_readBuffer.size(), m_socket->isEncrypted());
    fflush(stderr);

    if (m_readBuffer.size() > MAX_BUFFER_SIZE) {
        qWarning() << "[ClientHandler] Buffer overflow:" << clientIP();
        disconnectClient();
        return;
    }

    while (m_readBuffer.size() >= 4) {
        quint32 payloadSize = 0;
        QDataStream stream(m_readBuffer);
        stream.setByteOrder(QDataStream::BigEndian);
        stream >> payloadSize;

        if (payloadSize == 0 || payloadSize > static_cast<quint32>(MAX_MESSAGE_SIZE)) {
            qWarning() << "[ClientHandler] Invalid payload size:" << payloadSize;
            disconnectClient();
            return;
        }

        int totalSize = 4 + payloadSize + 4 + 32;
        fprintf(stderr, "[CH] expect=%d have=%d payload=%u\n", totalSize, m_readBuffer.size(), payloadSize);
        fflush(stderr);
        if (m_readBuffer.size() < totalSize) return;

        QByteArray packet = m_readBuffer.left(totalSize);
        m_readBuffer.remove(0, totalSize);

        QJsonObject msg = deserializePacket(packet, m_sessionKey, m_hmacKey);
        if (msg.isEmpty()) {
            fprintf(stderr, "[CH] deserializePacket FAILED!\n");
            fflush(stderr);
            continue;
        }
        fprintf(stderr, "[CH] CMD: %s\n", msg["cmd"].toString().toUtf8().constData());
        fflush(stderr);

        if (!checkRateLimit()) {
            sendResponse(createErrorResponse("Rate limit exceeded"));
            continue;
        }

        QString cmd = msg["cmd"].toString();
        qDebug() << "[ClientHandler] CMD:" << cmd << "user:" << m_username;

        if (!m_authenticated && cmd != Command::LOGIN && cmd != Command::REGISTER &&
            cmd != Command::SESSION_VALID && cmd != Command::PING &&
            cmd != Command::PASSWORD_RESET) {
            sendResponse(createErrorResponse("Authentication required"));
            continue;
        }

        if (cmd == Command::LOGIN) handleAuthLogin(msg);
        else if (cmd == Command::REGISTER) handleAuthRegister(msg);
        else if (cmd == Command::SESSION_VALID) handleAuthSessionValid(msg);
        else if (cmd == Command::PASSWORD_RESET) handlePasswordReset(msg);
        else if (cmd == Command::PING) handlePing(msg);
        else if (cmd == Command::CONTACT_ADD) handleContactAdd(msg);
        else if (cmd == Command::CONTACT_ACCEPT) handleContactAccept(msg);
        else if (cmd == Command::CONTACT_REJECT) handleContactReject(msg);
        else if (cmd == Command::CONTACT_REMOVE) handleContactRemove(msg);
        else if (cmd == Command::CONTACTS_LIST) handleContactsList(msg);
        else if (cmd == Command::CONTACT_REQUESTS) handleContactRequests(msg);
        else if (cmd == Command::USER_LOOKUP) handleUserLookup(msg);
        else if (cmd == Command::FILE_SEND_INIT) handleFileSendInit(msg);
        else if (cmd == Command::FILE_SEND_CHUNK) handleFileSendChunk(msg);
        else if (cmd == Command::FILE_SEND_COMPLETE) handleFileSendComplete(msg);
        else if (cmd == Command::FILE_RECEIVE_LIST) handleFileReceiveList(msg);
        else if (cmd == Command::FILE_DOWNLOAD_INIT) handleFileDownloadInit(msg);
        else if (cmd == Command::FILE_CANCEL) handleFileCancel(msg);
        else if (cmd == Command::CHECK_ONLINE) handleCheckOnline(msg);
        else {
            sendResponse(createErrorResponse("Unknown command: " + cmd));
        }
    }
}

void ClientHandler::onDisconnected()
{
    qDebug() << "[ClientHandler] Disconnected:" << m_username << clientIP();
    if (m_authenticated && !m_sessionKey.isEmpty()) {
        m_database->revokeAllUserSessions(m_userId);
    }
    emit finished();
}

void ClientHandler::onError(QAbstractSocket::SocketError error)
{
    Q_UNUSED(error)
    qWarning() << "[ClientHandler] Socket error:" << m_socket->errorString();
}

void ClientHandler::sendResponse(const QJsonObject &response)
{
    if (!m_socket || !m_socket->isOpen()) return;
    QByteArray packet = serializePacket(response, m_sessionKey, m_hmacKey);
    if (!packet.isEmpty()) {
        m_socket->write(packet);
        m_socket->flush();
    }
}

void ClientHandler::sendRawMessage(const QJsonObject &msg)
{
    if (!m_socket || !m_socket->isOpen()) return;
    // Используем сессионные ключи этого клиента
    QByteArray packet = serializePacket(msg, m_sessionKey, m_hmacKey);
    if (!packet.isEmpty()) {
        m_socket->write(packet);
        m_socket->flush();
    }
}

void ClientHandler::disconnectClient()
{
    if (m_socket) m_socket->disconnectFromHost();
}

bool ClientHandler::checkRateLimit()
{
    qint64 now = QDateTime::currentSecsSinceEpoch();
    if (now - m_lastRequestTime > 60) {
        m_requestCount = 0;
        m_lastRequestTime = now;
    }
    m_requestCount++;
    return m_requestCount <= MAX_REQUESTS_PER_MIN;
}

QString ClientHandler::clientIP() const
{
    return m_socket ? m_socket->peerAddress().toString() : QString();
}

QString ClientHandler::hashPassword(const QString &password) const
{
    Q_UNUSED(password)
    return QString();
}

bool ClientHandler::verifyPassword(const QString &username, const QString &password) const
{
    return m_database->verifyPassword(username, password);
}

// ────────────────────────────────────────────────────────────────────
// АУТЕНТИФИКАЦИЯ
// ────────────────────────────────────────────────────────────────────
void ClientHandler::handleAuthLogin(const QJsonObject &msg)
{
    QJsonObject data = msg["data"].toObject();
    QString username = data["username"].toString().trimmed();
    QString passwordHash = data["password_hash"].toString();

    fprintf(stderr, "[CH] LOGIN username='%s'\n", qPrintable(username));
    fflush(stderr);

    if (username.isEmpty() || passwordHash.isEmpty()) {
        sendResponse(createErrorResponse("Username and password required"));
        return;
    }

    if (m_database->isUserLocked(username)) {
        m_database->addAuditLogSimple(-1, "LOGIN_BLOCKED: " + username, false);
        sendResponse(createErrorResponse("Account locked. Try again later."));
        return;
    }

    bool pwOk = verifyPassword(username, passwordHash);
    if (!pwOk) {
        m_database->incrementFailedAttempts(username);
        QSqlQuery checkQ(QSqlDatabase::database("server_connection"));
        checkQ.prepare("SELECT failed_attempts FROM users WHERE username = :uname");
        checkQ.bindValue(":uname", username);
        if (checkQ.exec() && checkQ.next() && checkQ.value(0).toInt() >= 5) {
            m_database->lockUser(username, 900);
        }
        sendResponse(createErrorResponse("Invalid credentials"));
        return;
    }

    UserInfo user = m_database->getUserByUsername(username);
    if (user.id < 0 || !user.isActive) {
        sendResponse(createErrorResponse("Account not active"));
        return;
    }

    QByteArray token(32, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(token.data()), 32);
    QString tokenHex = token.toHex();

    SessionInfo session = m_database->createSession(user.id, tokenHex, clientIP(), 3600);
    if (session.id < 0) {
        sendResponse(createErrorResponse("Failed to create session"));
        return;
    }

    m_userId = user.id;
    m_username = user.username;
    m_authenticated = true;
    m_database->resetFailedAttempts(username);

    m_database->addAuditLog(user.id, "LOGIN_SUCCESS", "users", user.id,
                            "{}", clientIP(), true);

    QJsonObject respData;
    respData["token"] = tokenHex;
    respData["user_id"] = user.id;
    respData["username"] = user.username;
    respData["email"] = user.email;
    respData["public_key"] = user.publicKey;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleAuthRegister(const QJsonObject &msg)
{
    QJsonObject data = msg["data"].toObject();
    QString username = data["username"].toString().trimmed();
    QString passwordHash = data["password_hash"].toString();
    QString email = data["email"].toString().trimmed().toLower();
    QString publicKey = data["public_key"].toString();

    if (username.isEmpty() || username.length() < 3 || username.length() > 50) {
        sendResponse(createErrorResponse("Username 3-50 chars required"));
        return;
    }
    if (passwordHash.isEmpty()) {
        sendResponse(createErrorResponse("Password required"));
        return;
    }
    if (email.isEmpty() || !email.contains('@') || !email.contains('.')) {
        sendResponse(createErrorResponse("Valid email required"));
        return;
    }
    if (publicKey.isEmpty()) publicKey = "test_key";
    for (QChar c : username) {
        if (!c.isLetterOrNumber() && c != '_' && c != '-') {
            sendResponse(createErrorResponse("Username: only letters, numbers, _, -"));
            return;
        }
    }

    if (m_database->isUsernameTaken(username)) {
        sendResponse(createErrorResponse("Username already taken"));
        return;
    }
    if (m_database->isEmailRegistered(email)) {
        sendResponse(createErrorResponse("Email already registered"));
        return;
    }

    QSqlQuery hashQuery(QSqlDatabase::database("server_connection"));
    hashQuery.prepare("SELECT crypt(:pwd, gen_salt('bf', 12))");
    hashQuery.bindValue(":pwd", passwordHash);

    QString bcryptHash;
    if (hashQuery.exec() && hashQuery.next()) {
        bcryptHash = hashQuery.value(0).toString();
    } else {
        sendResponse(createErrorResponse("Internal error"));
        return;
    }

    if (m_database->createUser(username, bcryptHash, email, publicKey)) {
        m_database->addAuditLogSimple(-1, "USER_REGISTERED: " + username, true);
        sendResponse(createOkResponse("Registration successful"));
    } else {
        sendResponse(createErrorResponse("Registration failed"));
    }
}

void ClientHandler::handleAuthSessionValid(const QJsonObject &msg)
{
    QJsonObject data = msg["data"].toObject();
    QString token = data["token"].toString();

    SessionInfo session = m_database->validateSession(token);
    if (session.id < 0) {
        sendResponse(createErrorResponse("Invalid or expired session"));
        return;
    }

    m_userId = session.userId;
    m_username = m_database->getUserById(session.userId).username;
    m_authenticated = true;

    QJsonObject respData;
    respData["valid"] = true;
    respData["user_id"] = session.userId;
    respData["username"] = m_username;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handlePasswordReset(const QJsonObject &msg)
{
    QJsonObject data = msg["data"].toObject();
    QString email = data["email"].toString().trimmed().toLower();

    if (email.isEmpty()) {
        sendResponse(createErrorResponse("Email required"));
        return;
    }

    if (m_database->isEmailRegistered(email)) {
        m_database->addAuditLogSimple(-1, "PASSWORD_RESET_REQUEST: " + email, true);
        sendResponse(createOkResponse("If the email is registered, reset instructions sent"));
    } else {
        sendResponse(createOkResponse("If the email is registered, reset instructions sent"));
    }
}

void ClientHandler::handlePing(const QJsonObject &msg)
{
    Q_UNUSED(msg)
    QJsonObject data;
    data["server_time"] = QString::number(QDateTime::currentSecsSinceEpoch());
    sendResponse(createMessage(Command::PONG, data));
}

// ────────────────────────────────────────────────────────────────────
// КОНТАКТЫ
// ────────────────────────────────────────────────────────────────────
void ClientHandler::handleContactAdd(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }

    QJsonObject data = msg["data"].toObject();
    QString targetUsername = data["username"].toString().trimmed();
    QString comment = data["comment"].toString().left(500);

    if (targetUsername.isEmpty()) { sendResponse(createErrorResponse("Username required")); return; }

    UserInfo target = m_database->getUserByUsername(targetUsername);
    if (target.id < 0) { sendResponse(createErrorResponse("User not found")); return; }
    if (target.id == m_userId) { sendResponse(createErrorResponse("Cannot add yourself")); return; }
    if (m_database->areContacts(m_userId, target.id)) { sendResponse(createErrorResponse("Already contacts")); return; }

    if (m_database->sendContactRequest(m_userId, target.id, comment)) {
        sendResponse(createOkResponse("Contact request sent"));
    } else {
        sendResponse(createErrorResponse("Request already pending"));
    }
}

void ClientHandler::handleContactAccept(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    int requestId = data["request_id"].toInt();
    if (m_database->acceptContactRequest(requestId, m_userId))
        sendResponse(createOkResponse("Contact accepted"));
    else
        sendResponse(createErrorResponse("Invalid request"));
}

void ClientHandler::handleContactReject(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    int requestId = data["request_id"].toInt();
    if (m_database->rejectContactRequest(requestId, m_userId))
        sendResponse(createOkResponse("Contact rejected"));
    else
        sendResponse(createErrorResponse("Invalid request"));
}

void ClientHandler::handleContactRemove(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    QString targetUsername = data["username"].toString().trimmed();
    UserInfo target = m_database->getUserByUsername(targetUsername);
    if (target.id < 0) { sendResponse(createErrorResponse("User not found")); return; }
    if (!m_database->areContacts(m_userId, target.id)) { sendResponse(createErrorResponse("Not in contacts")); return; }
    if (m_database->removeContact(m_userId, target.id))
        sendResponse(createOkResponse("Contact removed"));
    else
        sendResponse(createErrorResponse("Failed to remove contact"));
}

void ClientHandler::handleContactsList(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    Q_UNUSED(msg)
    QList<ContactInfo> contacts = m_database->getContacts(m_userId);
    QJsonArray arr;
    for (const auto &c : contacts) {
        QJsonObject entry;
        entry["id"] = c.id;
        entry["user_id"] = (c.userIdA == m_userId) ? c.userIdB : c.userIdA;
        entry["username"] = (c.userIdA == m_userId) ? c.usernameB : c.usernameA;
        entry["created_at"] = c.createdAt.toString(Qt::ISODate);
        arr.append(entry);
    }
    QJsonObject respData;
    respData["contacts"] = arr;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleContactRequests(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    Q_UNUSED(msg)
    QList<ContactRequestInfo> incoming = m_database->getIncomingRequests(m_userId);
    QList<ContactRequestInfo> outgoing = m_database->getOutgoingRequests(m_userId);
    QJsonArray inArr, outArr;
    for (const auto &r : incoming) {
        QJsonObject entry;
        entry["id"] = r.id; entry["sender_id"] = r.senderId;
        entry["sender_name"] = r.senderName; entry["comment"] = r.comment;
        entry["created_at"] = r.createdAt.toString(Qt::ISODate); inArr.append(entry);
    }
    for (const auto &r : outgoing) {
        QJsonObject entry;
        entry["id"] = r.id; entry["receiver_id"] = r.receiverId;
        entry["receiver_name"] = r.senderName; entry["comment"] = r.comment;
        entry["created_at"] = r.createdAt.toString(Qt::ISODate); outArr.append(entry);
    }
    QJsonObject respData;
    respData["incoming"] = inArr; respData["outgoing"] = outArr;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleUserLookup(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    QString username = data["username"].toString().trimmed();
    UserInfo user = m_database->getUserByUsername(username);
    if (user.id < 0) { sendResponse(createErrorResponse("User not found")); return; }
    QJsonObject respData;
    respData["user_id"] = user.id; respData["username"] = user.username;
    respData["is_contact"] = m_database->areContacts(m_userId, user.id);
    sendResponse(createMessage(Command::OK, respData));
}

// ────────────────────────────────────────────────────────────────────
// ФАЙЛОВЫЕ ПЕРЕДАЧИ — СТРИМИНГ-РЕТРАНСЛЯТОР (без хранения на диске)
// Данные хранятся только в ОЗУ на время передачи
// ────────────────────────────────────────────────────────────────────
void ClientHandler::handleFileSendInit(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }

    QJsonObject data = msg["data"].toObject();
    QString receiverName = data["receiver"].toString().trimmed();
    QString fileName = data["file_name"].toString();
    QString fileHash = data["file_hash"].toString();
    qint64 fileSize = data["file_size"].toVariant().toLongLong();

    if (receiverName.isEmpty() || fileName.isEmpty() || fileHash.isEmpty()) {
        sendResponse(createErrorResponse("Missing required fields"));
        return;
    }
    if (fileSize <= 0 || fileSize > 31457280) { // 30 MB max in RAM
        sendResponse(createErrorResponse("File too large (max 30 MB)"));
        return;
    }
    if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
        sendResponse(createErrorResponse("Invalid file name"));
        return;
    }

    UserInfo receiver = m_database->getUserByUsername(receiverName);
    if (receiver.id < 0) { sendResponse(createErrorResponse("Receiver not found")); return; }

    bool areContactsOk = m_database->areContacts(m_userId, receiver.id);
    fprintf(stderr, "[CH] FILE_SEND_INIT sender=%d receiver=%d(%s) areContacts=%d\n",
            m_userId, receiver.id, qPrintable(receiverName), areContactsOk);
    fflush(stderr);
    if (!areContactsOk) {
        sendResponse(createErrorResponse("Receiver must be in contacts"));
        return;
    }

    int transferId = m_database->createFileTransfer(
        m_userId, receiver.id, fileName, fileHash, fileSize, "", 72);

    if (transferId < 0) { sendResponse(createErrorResponse("Failed to create transfer")); return; }

    m_pendingUpload.transferId = transferId;
    m_pendingUpload.receiverId = receiver.id;
    m_pendingUpload.fileHash = fileHash;
    m_pendingUpload.fileName = fileName;
    m_pendingUpload.totalSize = fileSize;
    m_pendingUpload.receivedBytes = 0;
    m_pendingUpload.accumulatedData.clear();
    m_pendingUpload.accumulatedData.reserve(fileSize + 1024);

    m_database->updateTransferStatus(transferId, "uploading");

    QJsonObject respData;
    respData["transfer_id"] = transferId;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleFileSendChunk(const QJsonObject &msg)
{
    if (!m_authenticated || m_pendingUpload.transferId < 0) {
        sendResponse(createErrorResponse("No active upload"));
        return;
    }

    QJsonObject data = msg["data"].toObject();
    int transferId = data["transfer_id"].toInt();
    QByteArray chunk = QByteArray::fromBase64(data["chunk_data"].toString().toUtf8());

    if (transferId != m_pendingUpload.transferId) {
        sendResponse(createErrorResponse("Wrong transfer ID"));
        return;
    }

    if (m_pendingUpload.receivedBytes + chunk.size() > m_pendingUpload.totalSize) {
        sendResponse(createErrorResponse("Chunk exceeds file size"));
        m_pendingUpload = {};
        return;
    }

    m_pendingUpload.accumulatedData.append(chunk);
    m_pendingUpload.receivedBytes += chunk.size();

    m_database->updateTransferProgress(transferId, m_pendingUpload.receivedBytes);

    QJsonObject respData;
    respData["transfer_id"] = transferId;
    respData["received_bytes"] = m_pendingUpload.receivedBytes;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleFileSendComplete(const QJsonObject &msg)
{
    if (!m_authenticated || m_pendingUpload.transferId < 0) {
        sendResponse(createErrorResponse("No active upload"));
        return;
    }

    QJsonObject data = msg["data"].toObject();
    int transferId = data["transfer_id"].toInt();
    QString finalHash = data["final_hash"].toString();

    if (transferId != m_pendingUpload.transferId) {
        sendResponse(createErrorResponse("Wrong transfer ID"));
        return;
    }

    // Верификация SHA-256: оба в hex
    unsigned char computedHash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(m_pendingUpload.accumulatedData.constData()),
           m_pendingUpload.accumulatedData.size(), computedHash);
    QByteArray computedHex = QByteArray(reinterpret_cast<const char*>(computedHash), SHA256_DIGEST_LENGTH).toHex();

    if (QString::fromUtf8(computedHex) != finalHash) {
        m_database->updateTransferStatus(transferId, "cancelled");
        m_pendingUpload = {};
        sendResponse(createErrorResponse("Hash mismatch"));
        return;
    }

    // Файл готов — сохраняем в ОЗУ через CryptoServer (сигнал)
    // Статус "ready" — получатель может скачать
    m_database->updateTransferStatus(transferId, "ready");
    m_database->addAuditLogSimple(m_userId, "FILE_UPLOADED id=" + QString::number(transferId), true);

    // Эмитируем сигнал с готовыми данными — CryptoServer заберёт их
    // Передаём данные родителю через динамическое свойство
    QByteArray fileData = m_pendingUpload.accumulatedData;
    int tid = transferId;
    int rid = m_pendingUpload.receiverId;
    QString fname = m_pendingUpload.fileName;
    QString fhash = m_pendingUpload.fileHash;
    qint64 fsize = m_pendingUpload.totalSize;

    m_pendingUpload = {};

    // Оповещаем CryptoServer о готовом файле
    QMetaObject::invokeMethod(this, [this, tid, rid, fname, fhash, fsize, fileData]() {
        emit fileUploadComplete(tid, rid, fname, fhash, fsize, fileData);
    }, Qt::QueuedConnection);

    sendResponse(createOkResponse("File uploaded successfully"));
}

void ClientHandler::handleFileReceiveList(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    Q_UNUSED(msg)

    QList<FileTransferInfo> pending = m_database->getPendingTransfers(m_userId);
    QList<FileTransferInfo> sent = m_database->getSentTransfers(m_userId);

    QJsonArray pendingArr, sentArr;
    for (const auto &t : pending) {
        QJsonObject entry;
        entry["transfer_id"] = t.id; entry["sender_name"] = t.senderName;
        entry["file_name"] = t.fileName; entry["file_size"] = t.fileSize;
        entry["status"] = t.status; entry["created_at"] = t.createdAt.toString(Qt::ISODate);
        entry["expires_at"] = t.expiresAt.toString(Qt::ISODate);
        pendingArr.append(entry);
    }
    for (const auto &t : sent) {
        QJsonObject entry;
        entry["transfer_id"] = t.id; entry["receiver_name"] = t.senderName;
        entry["file_name"] = t.fileName; entry["file_size"] = t.fileSize;
        entry["status"] = t.status; entry["created_at"] = t.createdAt.toString(Qt::ISODate);
        entry["expires_at"] = t.expiresAt.toString(Qt::ISODate);
        sentArr.append(entry);
    }

    QJsonObject respData;
    respData["pending"] = pendingArr; respData["sent"] = sentArr;
    sendResponse(createMessage(Command::OK, respData));
}

void ClientHandler::handleFileDownloadInit(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }

    QJsonObject data = msg["data"].toObject();
    int transferId = data["transfer_id"].toInt();

    // Запрашиваем данные у CryptoServer
    QMetaObject::invokeMethod(this, [this, transferId]() {
        emit fileDownloadRequest(transferId, m_userId);
    }, Qt::QueuedConnection);
}

void ClientHandler::handleFileCancel(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    int transferId = data["transfer_id"].toInt();
    if (m_database->cancelTransfer(transferId, m_userId))
        sendResponse(createOkResponse("Transfer cancelled"));
    else
        sendResponse(createErrorResponse("Cannot cancel this transfer"));
}

void ClientHandler::handleCheckOnline(const QJsonObject &msg)
{
    if (!m_authenticated) { sendResponse(createErrorResponse("Not authenticated")); return; }
    QJsonObject data = msg["data"].toObject();
    QString targetUsername = data["username"].toString().trimmed();
    if (targetUsername.isEmpty()) {
        sendResponse(createErrorResponse("Username required"));
        return;
    }
    UserInfo target = m_database->getUserByUsername(targetUsername);
    if (target.id < 0) {
        sendResponse(createErrorResponse("User not found"));
        return;
    }
    if (!m_database->areContacts(m_userId, target.id)) {
        sendResponse(createErrorResponse("Not in contacts"));
        return;
    }
    // Проверяем онлайн через CryptoServer (прямой указатель)
    bool online = m_server ? (m_server->findHandlerByUserId(target.id) != nullptr) : false;

    QJsonObject respData;
    respData["username"] = targetUsername;
    respData["user_id"] = target.id;
    respData["online"] = online;
    sendResponse(createMessage(Command::OK, respData));
}
