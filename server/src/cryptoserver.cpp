#include "cryptoserver.h"
#include "clienthandler.h"
#include "databasemanager.h"
#include <QFile>
#include <QDateTime>
#include <QDebug>
#include <cstdio>

CryptoServer::CryptoServer(QObject *parent)
    : QObject(parent)
    , m_sslServer(new QSslServer(this))
    , m_database(&DatabaseManager::getInstance())
{
    connect(m_sslServer, &QSslServer::pendingConnectionAvailable,
            this, &CryptoServer::onNewConnection);
}

CryptoServer::~CryptoServer()
{
    stopServer();
}

bool CryptoServer::startServer(const QString &host, quint16 port,
                               const QString &certPath, const QString &keyPath)
{
    setupSslConfig(certPath, keyPath);
    m_sslServer->setSslConfiguration(m_sslConfig);

    if (!m_sslServer->listen(QHostAddress(host), port)) {
        qCritical() << "[Server] Failed to listen:" << m_sslServer->errorString();
        return false;
    }

    qInfo() << "[Server] Listening on" << host << port << "(RAM-only relay)";
    emit serverStarted(port);
    return true;
}

void CryptoServer::stopServer()
{
    if (m_sslServer->isListening()) {
        m_sslServer->close();
    }
    emit serverStopped();
}

bool CryptoServer::isRunning() const
{
    return m_sslServer->isListening();
}

void CryptoServer::setupSslConfig(const QString &certPath, const QString &keyPath)
{
    m_sslConfig = QSslConfiguration::defaultConfiguration();

    QSslCertificate cert;
    QSslKey key;

    {
        QFile certFile(certPath);
        if (certFile.open(QIODevice::ReadOnly)) {
            cert = QSslCertificate(&certFile, QSsl::Pem);
            certFile.close();
            if (cert.isNull()) qWarning() << "[Server] Failed to parse certificate:" << certPath;
            else qInfo() << "[Server] Certificate loaded:" << certPath;
        } else {
            qWarning() << "[Server] Cannot open certificate file:" << certPath;
        }
    }
    {
        QFile keyFile(keyPath);
        if (keyFile.open(QIODevice::ReadOnly)) {
            key = QSslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
            keyFile.close();
            if (key.isNull()) {
                keyFile.open(QIODevice::ReadOnly);
                key = QSslKey(&keyFile, QSsl::Ec, QSsl::Pem);
                keyFile.close();
            }
            if (key.isNull()) qWarning() << "[Server] Failed to parse key:" << keyPath;
            else qInfo() << "[Server] Private key loaded:" << keyPath;
        } else {
            qWarning() << "[Server] Cannot open key file:" << keyPath;
        }
    }

    if (cert.isNull() || key.isNull()) {
        qCritical() << "[Server] No valid certificate/key pair loaded";
        return;
    }

    m_sslConfig.setLocalCertificate(cert);
    m_sslConfig.setPrivateKey(key);
    m_sslConfig.setProtocol(QSsl::TlsV1_2OrLater);
    m_sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
}

void CryptoServer::onNewConnection()
{
    while (m_sslServer->hasPendingConnections()) {
        QSslSocket *clientSocket = qobject_cast<QSslSocket*>(m_sslServer->nextPendingConnection());
        if (!clientSocket) continue;

        QString ip = clientSocket->peerAddress().toString();
        fprintf(stderr, "[SRV] New connection from: %s\n", qPrintable(ip));
        fflush(stderr);

        if (!checkRateLimit(ip)) {
            fprintf(stderr, "[SRV] Rate limited: %s\n", qPrintable(ip));
            fflush(stderr);
            clientSocket->disconnectFromHost();
            clientSocket->deleteLater();
            continue;
        }

        recordConnection(ip);
        emit clientConnected(ip);

        ClientHandler *handler = new ClientHandler(clientSocket, m_sslConfig, m_database, this);

        // Подключаем сигналы файлового стриминга
        connect(handler, &ClientHandler::finished, this, &CryptoServer::onClientHandlerFinished);
        // Сигналы стриминга — используем лямбды, т.к. сигналы не объявлены в заголовке
        QObject::connect(handler, SIGNAL(fileUploadComplete(int,int,QString,QString,qint64,QByteArray)),
                         this, SLOT(onFileUploadComplete(int,int,QString,QString,qint64,QByteArray)));
        QObject::connect(handler, SIGNAL(fileDownloadRequest(int,int)),
                         this, SLOT(onFileDownloadRequest(int,int)));

        {
            QMutexLocker l(&m_activeMutex);
            m_activeHandlers.insert(handler);
        }
        handler->start();
    }
}

void CryptoServer::onClientHandlerFinished()
{
    ClientHandler *handler = qobject_cast<ClientHandler*>(sender());
    if (handler) {
        {
            QMutexLocker l(&m_activeMutex);
            m_activeHandlers.remove(handler);
        }
        emit clientDisconnected(QString());
        handler->deleteLater();
    }
}

void CryptoServer::onFileUploadComplete(int transferId, int receiverId, const QString &fileName,
                                        const QString &fileHash, qint64 fileSize, const QByteArray &data)
{
    qInfo() << "[Server] File uploaded:" << fileName << "size:" << fileSize
            << "transfer:" << transferId << "receiver:" << receiverId;
    storeFileData(transferId, receiverId, fileName, fileHash, fileSize, data);

    // Уведомляем получателя (если онлайн)
    ClientHandler *receiver = findHandlerByUserId(receiverId);
    if (receiver && receiver->isAuthenticated()) {
        QJsonObject notify;
        notify["cmd"] = "FILE_AVAILABLE";
        QJsonObject nd;
        nd["transfer_id"] = transferId;
        nd["file_name"] = fileName;
        nd["file_size"] = fileSize;
        notify["data"] = nd;
        receiver->sendRawMessage(notify);
    }
}

void CryptoServer::onFileDownloadRequest(int transferId, int userId)
{
    ClientHandler *handler = findHandlerByUserId(userId);
    if (!handler || !handler->isAuthenticated()) return;

    // Проверяем БД на права доступа
    FileTransferInfo info = m_database->getFileTransfer(transferId);
    if (info.id < 0 || info.receiverId != userId) {
        QJsonObject err = QJsonObject{{"cmd", "ERROR"}, {"data", QJsonObject{{"message", "Not your transfer"}}}};
        handler->sendRawMessage(err);
        return;
    }
    if (info.status != "ready") {
        QJsonObject err = QJsonObject{{"cmd", "ERROR"}, {"data", QJsonObject{{"message", "File not ready"}}}};
        handler->sendRawMessage(err);
        return;
    }

    // Забираем данные из кэша
    QByteArray fileData = takeFileData(transferId);
    if (fileData.isEmpty()) {
        QJsonObject err = QJsonObject{{"cmd", "ERROR"}, {"data", QJsonObject{{"message", "File expired or not found in cache"}}}};
        handler->sendRawMessage(err);
        return;
    }

    m_database->updateTransferStatus(transferId, "downloading");
    m_database->incrementDownloadCount(transferId);
    m_database->addAuditLogSimple(userId, "FILE_DOWNLOAD_START id=" + QString::number(transferId), true);

    // Стримим чанками напрямую получателю
    int chunkSize = 65536; // 64 KB
    int totalChunks = (fileData.size() + chunkSize - 1) / chunkSize;

    QJsonObject meta;
    meta["cmd"] = "FILE_DOWNLOAD_META";
    QJsonObject metaData;
    metaData["transfer_id"] = transferId;
    metaData["file_name"] = info.fileName;
    metaData["file_size"] = fileData.size();
    metaData["total_chunks"] = totalChunks;
    metaData["file_hash"] = QString(QByteArray::fromHex(info.fileHash.toUtf8()).toHex());
    meta["data"] = metaData;
    handler->sendRawMessage(meta);

    for (int i = 0; i < totalChunks; i++) {
        QByteArray chunk = fileData.mid(i * chunkSize, chunkSize);
        QJsonObject chunkMsg;
        chunkMsg["cmd"] = "FILE_DOWNLOAD_CHUNK";
        QJsonObject cd;
        cd["transfer_id"] = transferId;
        cd["chunk_index"] = i;
        cd["total_chunks"] = totalChunks;
        cd["chunk_data"] = QString(chunk.toBase64());
        chunkMsg["data"] = cd;
        handler->sendRawMessage(chunkMsg);
    }

    m_database->updateTransferStatus(transferId, "completed");
    m_database->addAuditLogSimple(userId, "FILE_DOWNLOAD_COMPLETE id=" + QString::number(transferId), true);
}

// ────────────────────────────────────────────────────────────────────
// Кэш файлов в ОЗУ
// ────────────────────────────────────────────────────────────────────
void CryptoServer::storeFileData(int transferId, int receiverId, const QString &fileName,
                                 const QString &fileHash, qint64 fileSize, const QByteArray &data)
{
    QMutexLocker l(&m_cacheMutex);
    CachedFile cf;
    cf.receiverId = receiverId;
    cf.fileName = fileName;
    cf.fileHash = fileHash;
    cf.fileSize = fileSize;
    cf.data = data;
    m_fileCache[transferId] = cf;
    qInfo() << "[Server] Cached in RAM:" << fileName << "(" << data.size() << "bytes)"
            << "transfer:" << transferId;
}

QByteArray CryptoServer::takeFileData(int transferId)
{
    QMutexLocker l(&m_cacheMutex);
    auto it = m_fileCache.find(transferId);
    if (it == m_fileCache.end()) return {};
    QByteArray data = it->data;
    m_fileCache.erase(it);
    qInfo() << "[Server] File removed from RAM cache:" << transferId;
    return data;
}

ClientHandler* CryptoServer::findHandlerByUserId(int userId) const
{
    QMutexLocker l(&m_activeMutex);
    for (ClientHandler *h : m_activeHandlers) {
        if (h->userId() == userId && h->isAuthenticated())
            return h;
    }
    return nullptr;
}

// ────────────────────────────────────────────────────────────────────
// Rate limiting
// ────────────────────────────────────────────────────────────────────
bool CryptoServer::checkRateLimit(const QString &ip)
{
    QMutexLocker locker(&m_rateMutex);
    QElapsedTimer now;
    now.start();

    auto it = m_lastConnection.find(ip);
    if (it != m_lastConnection.end() && it->elapsed() < RATE_WINDOW_MS) {
        int count = m_connectionCount.value(ip, 0);
        if (count >= MAX_CONNECTIONS_PER_SEC) return false;
    }
    return true;
}

void CryptoServer::recordConnection(const QString &ip)
{
    QMutexLocker locker(&m_rateMutex);
    auto it = m_lastConnection.find(ip);
    if (it == m_lastConnection.end() || it->elapsed() >= RATE_WINDOW_MS) {
        m_lastConnection[ip].start();
        m_connectionCount[ip] = 1;
    } else {
        m_connectionCount[ip]++;
    }
}