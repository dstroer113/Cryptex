#include "networkclient.h"
#include "protocol.h"

#include <QSslConfiguration>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDebug>
#include <openssl/sha.h>

using namespace CryptexProtocol;

NetworkClient::NetworkClient(QObject *parent)
    : QObject(parent)
    , m_socket(new QSslSocket(this))
    , m_connected(false)
    , m_userId(-1)
    , m_authenticated(false)
    , m_reconnectTimer(new QTimer(this))
    , m_pingTimer(new QTimer(this))
    , m_downloadTransferId(-1)
    , m_downloadTotalChunks(0)
    , m_downloadReceivedChunks(0)
    , m_uploadTransferId(-1)
    , m_uploadFileSize(0)
{
    connect(m_socket, &QSslSocket::encrypted, this, &NetworkClient::onEncrypted);
    connect(m_socket, &QSslSocket::readyRead, this, &NetworkClient::onReadyRead);
    connect(m_socket, &QSslSocket::disconnected, this, &NetworkClient::onDisconnected);
    connect(m_socket, &QSslSocket::errorOccurred, this, &NetworkClient::onSocketError);

    m_reconnectTimer->setSingleShot(true);
    m_reconnectTimer->setInterval(5000);
    connect(m_reconnectTimer, &QTimer::timeout, this, &NetworkClient::onReconnectTimer);

    m_sessionTimeout = new QTimer(this);
    m_sessionTimeout->setSingleShot(true);
    m_sessionTimeout->setInterval(10000); // 10 сек таймаут на получение ключа
    connect(m_sessionTimeout, &QTimer::timeout, this, [this]() {
        qWarning() << "[NetworkClient] Session key timeout — disconnecting";
        disconnectFromServer();
        emit errorOccurred("Session key timeout (server not responding)");
    });

    m_pingTimer->setInterval(30000); // пинг каждые 30 сек
    connect(m_pingTimer, &QTimer::timeout, this, [this]() {
        sendPacket(createMessage(Command::PING));
    });
}

NetworkClient::~NetworkClient()
{
    disconnectFromServer();
    delete m_socket;
}

// ────────────────────────────────────────────────────────────────────
void NetworkClient::connectToServer(const QString &host, quint16 port)
{
    m_host = host;
    m_port = port;

    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setProtocol(QSsl::TlsV1_2OrLater);
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone); // будет VerificationPeer для production
    m_socket->setSslConfiguration(sslConfig);

    m_socket->connectToHostEncrypted(m_host, port);
}

void NetworkClient::disconnectFromServer()
{
    m_reconnectTimer->stop();
    m_pingTimer->stop();
    m_socket->disconnectFromHost();
    m_connected = false;
    m_authenticated = false;
}

bool NetworkClient::isConnected() const
{
    return m_connected && m_socket->state() == QAbstractSocket::ConnectedState;
}

// ────────────────────────────────────────────────────────────────────
// SLOTS
// ────────────────────────────────────────────────────────────────────
void NetworkClient::onEncrypted()
{
    qDebug() << "[NetworkClient] SSL handshake complete";
    m_connected = true;
    m_sessionTimeout->start(); // ждём SESSION_KEY от сервера
    emit connected();
}

void NetworkClient::onReadyRead()
{
    m_readBuffer.append(m_socket->readAll());

    // Пока нет ключа — парсим plain-пакеты
    while (m_readBuffer.size() >= 4) {
        QDataStream stream(m_readBuffer);
        stream.setByteOrder(QDataStream::BigEndian);
        quint32 payloadSize = 0;
        stream >> payloadSize;

        if (payloadSize == 0 || payloadSize > static_cast<quint32>(MAX_MESSAGE_SIZE)) {
            qWarning() << "[NetworkClient] Invalid payload size:" << payloadSize;
            return;
        }

        // Разный размер для plain vs encrypted пакетов
        int totalSize;
        if (m_sessionKey.isEmpty()) {
            totalSize = 4 + payloadSize; // plain: [size][payload]
        } else {
            totalSize = 4 + payloadSize + 4 + 32; // encrypted
        }

        if (m_readBuffer.size() < totalSize) return;

        QByteArray packet = m_readBuffer.left(totalSize);
        m_readBuffer.remove(0, totalSize);

        QJsonObject msg;
        if (m_sessionKey.isEmpty()) {
            msg = deserializePacketPlain(packet);
        } else {
            msg = deserializePacket(packet, m_sessionKey, m_hmacKey);
        }

        if (msg.isEmpty()) {
            qWarning() << "[NetworkClient] Failed to deserialize";
            continue;
        }

        QString cmd = msg["cmd"].toString();
        qDebug() << "[NetworkClient] RECV:" << cmd;

        // Первое сообщение — ключи сессии
        if (cmd == "SESSION_KEY" && m_sessionKey.isEmpty()) {
            QJsonObject data = msg["data"].toObject();
            m_sessionKey = QByteArray::fromHex(data["session_key"].toString().toUtf8());
            m_hmacKey = QByteArray::fromHex(data["hmac_key"].toString().toUtf8());
            m_sessionTimeout->stop();
            m_pingTimer->start();
            qDebug() << "[NetworkClient] Session keys received, flushing" << m_pendingPackets.size() << "packet(s)";
            while (!m_pendingPackets.isEmpty()) {
                QJsonObject pkt = m_pendingPackets.dequeue();
                sendPacket(pkt);
            }
            continue;
        }

        processMessage(msg);
    }
}

void NetworkClient::onDisconnected()
{
    qDebug() << "[NetworkClient] Disconnected";
    m_connected = false;
    m_authenticated = false;
    m_pingTimer->stop();
    m_reconnectTimer->start();
    emit disconnected();
}

void NetworkClient::onSocketError(QAbstractSocket::SocketError error)
{
    Q_UNUSED(error)
    qWarning() << "[NetworkClient] Error:" << m_socket->errorString();
    emit errorOccurred(m_socket->errorString());
}

void NetworkClient::onReconnectTimer()
{
    if (!m_connected) connectToServer(m_host, m_port);
}

// ────────────────────────────────────────────────────────────────────
void NetworkClient::sendPacket(const QJsonObject &msg)
{
    if (!m_connected) {
        qDebug() << "[NetworkClient] sendPacket dropped: not connected";
        return;
    }
    // Если ключ ещё не получен — ставим в очередь
    if (m_sessionKey.isEmpty()) {
        qDebug() << "[NetworkClient] Queuing packet (no session key yet):" << msg["cmd"].toString();
        m_pendingPackets.enqueue(msg);
        // Запускаем таймаут при первом пакете
        if (!m_sessionTimeout->isActive()) m_sessionTimeout->start();
        return;
    }
    QByteArray packet = serializePacket(msg, m_sessionKey, m_hmacKey);
    if (!packet.isEmpty()) {
        qDebug() << "[NC] >>> SEND:" << msg["cmd"].toString() << "size=" << packet.size() << "bytesWritten=" << m_socket->bytesToWrite();
        m_socket->write(packet);
        bool flushed = m_socket->flush();
        qDebug() << "[NC] >>> FLUSHED:" << flushed << "bytesAfter=" << m_socket->bytesToWrite();
    } else {
        qWarning() << "[NC] >>> serializePacket returned EMPTY for cmd:" << msg["cmd"].toString();
    }
}

void NetworkClient::processMessage(const QJsonObject &msg)
{
    QString cmd = msg["cmd"].toString();
    QJsonObject data = msg["data"].toObject();

    qDebug() << "[NetworkClient] processMessage cmd:" << cmd << "keys:" << data.keys();

    if (cmd == Command::OK) {
        if (data.contains("token")) handleAuthOk(data);
        else if (data.contains("contacts")) emit contactsListReceived(data["contacts"].toArray());
        else if (data.contains("incoming")) emit contactRequestsReceived(data["incoming"].toArray(), data["outgoing"].toArray());
        else if (data.contains("pending")) emit fileListReceived(data["pending"].toArray(), data["sent"].toArray());
        else if (data.contains("received_bytes")) {
            // Ответ на FILE_SEND_CHUNK
            int tid = data["transfer_id"].toInt();
            qint64 received = data["received_bytes"].toVariant().toLongLong();
            qDebug() << "[NetworkClient] Chunk ack: transfer" << tid << "received" << received;
            emit fileSendChunkAck(tid, received);
        }
        else if (data.contains("transfer_id")) {
            int tid = data["transfer_id"].toInt();
            qDebug() << "[NetworkClient] transfer_id received:" << tid << "current uploadTransferId:" << m_uploadTransferId;
            if (m_uploadTransferId == -1) {
                m_uploadTransferId = tid;
                qDebug() << "[NetworkClient] Emitting fileSendInitAck for transfer:" << tid;
                emit fileSendInitAck(tid);
            } else {
                qDebug() << "[NetworkClient] Ignoring transfer_id (not waiting):" << tid;
            }
        }
        else if (data.contains("message")) {
            QString msgText = data["message"].toString();
            if (msgText.contains("Registration")) emit registerSuccess();
            else if (msgText.contains("accepted")) emit contactAccepted();
            else if (msgText.contains("rejected")) emit contactRejected();
            else if (msgText.contains("removed")) emit contactRemoved();
            else if (msgText.contains("Contact")) emit contactAdded();
            else if (msgText.contains("cancelled")) emit transferCancelled();
            else if (msgText.contains("File uploaded")) emit fileSendCompleteAck();
        }
        else if (data.contains("online") && data.contains("username")) {
            emit userOnlineStatus(data["username"].toString(), data["online"].toBool());
        }
    }
    else if (cmd == Command::ERROR) {
        QString errorText = data["error"].toString();
        qDebug() << "[NetworkClient] ERROR:" << errorText;
        if (errorText.contains("credentials") || errorText.contains("locked")) emit loginFailed(errorText);
        else if (errorText.contains("Contact")) emit contactAddFailed(errorText);
        else if (errorText.contains("upload") || errorText.contains("transfer") || errorText.contains("File") || errorText.contains("receiver") || errorText.contains("contacts")) emit fileSendFailed(errorText);
        else if (errorText.contains("download") || errorText.contains("not found")) emit fileDownloadFailed(errorText);
        else emit errorOccurred(errorText);
    }
    else if (cmd == "FILE_DOWNLOAD_META") handleFileDownloadMeta(data);
    else if (cmd == "FILE_DOWNLOAD_CHUNK") handleFileDownloadChunk(data);
    else if (cmd == Command::PONG) handlePong(data);
}

// ────────────────────────────────────────────────────────────────────
// AUTH
// ────────────────────────────────────────────────────────────────────
void NetworkClient::login(const QString &username, const QString &password)
{
    qDebug() << "[NetworkClient] login() called for:" << username;

    // Клиент вычисляет SHA-256(password)
    QByteArray passwordHash = QByteArray::fromRawData(password.toUtf8().constData(), password.toUtf8().size());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(passwordHash.constData()),
           passwordHash.size(), hash);
    QString passwordHashHex = QByteArray(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH).toHex();

    QJsonObject data;
    data["username"] = username;
    data["password_hash"] = passwordHashHex;
    QJsonObject msg = createMessage(Command::LOGIN, data);
    qDebug() << "[NetworkClient] Sending LOGIN packet...";
    sendPacket(msg);
}

void NetworkClient::registerUser(const QString &username, const QString &password,
                                  const QString &email, const QString &publicKey)
{
    qDebug() << "[NetworkClient] registerUser() called for:" << username;

    QByteArray passwordHash = QByteArray::fromRawData(password.toUtf8().constData(), password.toUtf8().size());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(passwordHash.constData()),
           passwordHash.size(), hash);
    QString passwordHashHex = QByteArray(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH).toHex();

    QJsonObject data;
    data["username"] = username;
    data["password_hash"] = passwordHashHex;
    data["email"] = email;
    data["public_key"] = publicKey;
    QJsonObject msg = createMessage(Command::REGISTER, data);
    qDebug() << "[NetworkClient] Sending REGISTER packet...";
    sendPacket(msg);
}

void NetworkClient::validateSession(const QString &token)
{
    QJsonObject data;
    data["token"] = token;
    sendPacket(createMessage(Command::SESSION_VALID, data));
}

void NetworkClient::logout()
{
    sendPacket(createMessage(Command::LOGOUT));
    disconnectFromServer();
}

void NetworkClient::handleAuthOk(const QJsonObject &data)
{
    m_token = data["token"].toString();
    m_userId = data["user_id"].toInt();
    m_username = data["username"].toString();
    m_authenticated = true;
    emit loginSuccess(m_userId, m_username, m_token);
    flushPendingCommands();
}

// ────────────────────────────────────────────────────────────────────
// CONTACTS
// ────────────────────────────────────────────────────────────────────
void NetworkClient::getContactsList()
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this]() { getContactsList(); }); return; }
    sendPacket(createMessage(Command::CONTACTS_LIST));
}

void NetworkClient::sendContactRequest(const QString &targetUsername, const QString &comment)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, targetUsername, comment]() { sendContactRequest(targetUsername, comment); }); return; }
    QJsonObject data;
    data["username"] = targetUsername;
    data["comment"] = comment;
    sendPacket(createMessage(Command::CONTACT_ADD, data));
}

void NetworkClient::acceptContactRequest(int requestId)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, requestId]() { acceptContactRequest(requestId); }); return; }
    QJsonObject data;
    data["request_id"] = requestId;
    sendPacket(createMessage(Command::CONTACT_ACCEPT, data));
}

void NetworkClient::rejectContactRequest(int requestId)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, requestId]() { rejectContactRequest(requestId); }); return; }
    QJsonObject data;
    data["request_id"] = requestId;
    sendPacket(createMessage(Command::CONTACT_REJECT, data));
}

void NetworkClient::removeContact(const QString &username)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, username]() { removeContact(username); }); return; }
    QJsonObject data;
    data["username"] = username;
    sendPacket(createMessage(Command::CONTACT_REMOVE, data));
}

void NetworkClient::getContactRequests()
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this]() { getContactRequests(); }); return; }
    sendPacket(createMessage(Command::CONTACT_REQUESTS));
}

void NetworkClient::lookupUser(const QString &username)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, username]() { lookupUser(username); }); return; }
    QJsonObject data;
    data["username"] = username;
    sendPacket(createMessage(Command::USER_LOOKUP, data));
}

// ────────────────────────────────────────────────────────────────────
// FILES
// ────────────────────────────────────────────────────────────────────
void NetworkClient::sendFileInit(const QString &receiver, const QString &fileName,
                                 const QString &fileHash, qint64 fileSize)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, receiver, fileName, fileHash, fileSize]() { sendFileInit(receiver, fileName, fileHash, fileSize); }); return; }
    m_uploadTransferId = -1;
    m_uploadFileHash = fileHash;
    m_uploadReceiver = receiver;
    m_uploadFileSize = fileSize;
    QJsonObject data;
    data["receiver"] = receiver;
    data["file_name"] = fileName;
    data["file_hash"] = fileHash;
    data["file_size"] = fileSize;
    sendPacket(createMessage(Command::FILE_SEND_INIT, data));
}

void NetworkClient::sendFileChunk(int transferId, int chunkIndex, const QByteArray &chunkData)
{
    QJsonObject data;
    data["transfer_id"] = transferId;
    data["chunk_index"] = chunkIndex;
    data["chunk_data"] = QString(chunkData.toBase64());
    sendPacket(createMessage(Command::FILE_SEND_CHUNK, data));
}

void NetworkClient::sendFileComplete(int transferId, const QString &finalHash)
{
    QJsonObject data;
    data["transfer_id"] = transferId;
    data["final_hash"] = finalHash;
    sendPacket(createMessage(Command::FILE_SEND_COMPLETE, data));
    m_uploadTransferId = -1;
}

void NetworkClient::getFileList()
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this]() { getFileList(); }); return; }
    sendPacket(createMessage(Command::FILE_RECEIVE_LIST));
}

void NetworkClient::downloadFile(int transferId)
{
    if (!m_authenticated) { m_pendingCommands.enqueue([this, transferId]() { downloadFile(transferId); }); return; }
    m_downloadTransferId = transferId;
    m_downloadBuffer.clear();
    m_downloadReceivedChunks = 0;
    QJsonObject data;
    data["transfer_id"] = transferId;
    sendPacket(createMessage(Command::FILE_DOWNLOAD_INIT, data));
}

void NetworkClient::cancelTransfer(int transferId)
{
    QJsonObject data;
    data["transfer_id"] = transferId;
    sendPacket(createMessage(Command::FILE_CANCEL, data));
}

void NetworkClient::checkUserOnline(const QString &username)
{
    QJsonObject data;
    data["username"] = username;
    sendPacket(createMessage(Command::CHECK_ONLINE, data));
}

void NetworkClient::handleFileDownloadMeta(const QJsonObject &data)
{
    m_downloadFileName = data["file_name"].toString();
    m_downloadTotalChunks = data["total_chunks"].toInt();
    m_downloadFileHash = data["file_hash"].toString();
    emit fileDownloadMeta(
        data["transfer_id"].toInt(),
        m_downloadFileName,
        data["file_size"].toVariant().toLongLong(),
        m_downloadTotalChunks,
        m_downloadFileHash
    );
}

void NetworkClient::handleFileDownloadChunk(const QJsonObject &data)
{
    int transferId = data["transfer_id"].toInt();
    int chunkIndex = data["chunk_index"].toInt();
    int totalChunks = data["total_chunks"].toInt();
    QByteArray chunk = QByteArray::fromBase64(data["chunk_data"].toString().toUtf8());

    m_downloadBuffer.append(chunk);
    m_downloadReceivedChunks++;

    emit fileDownloadChunk(transferId, chunkIndex, totalChunks, chunk);

    if (chunkIndex == totalChunks - 1) {
        emit fileDownloadComplete(m_downloadTransferId);
        m_downloadTransferId = -1;
    }
}

void NetworkClient::handlePong(const QJsonObject &data)
{
    emit pingResponse(data["server_time"].toString().toLongLong());
}

void NetworkClient::flushPendingCommands()
{
    while (!m_pendingCommands.isEmpty()) {
        auto cmd = m_pendingCommands.dequeue();
        cmd();
    }
}