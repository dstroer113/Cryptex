#include "SecurityManager.h"
#include <QRegularExpression>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <QNetworkAccessManager>
#include <QSettings>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QtDebug>
#include <openssl/aes.h>
#include <openssl/sha.h>

SecurityManager::SecurityManager(QObject *parent)
    : QObject(parent)
    , m_sessionTimer(new QTimer(this))
    , m_sessionActive(false)
{
    // Настраиваем таймер
    connect(m_sessionTimer, &QTimer::timeout, this, [this]() {
        m_sessionActive = false;
    });

    // Загрузка сертификатов (без логирования)
    loadPinnedCertificates(":/certs/server_fingerprint.txt");
}

SecurityManager::~SecurityManager()
{
    stopSessionTimer();
    m_captchaCodes.clear();
    m_failedAttempts.clear();
    m_blockUntil.clear();
    m_pinnedFingerprints.clear();
}

SecurityManager& SecurityManager::getInstance()
{
    static SecurityManager instance;
    return instance;
}

QSslConfiguration SecurityManager::getSecureSslConfig() const
{
    QSslConfiguration config = QSslConfiguration::defaultConfiguration();
    config.setProtocol(QSsl::TlsV1_3);
    config.setPeerVerifyMode(QSslSocket::VerifyPeer);
    config.setCiphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    QList<QSslCertificate> caCerts = QSslCertificate::fromPath(":/certs/ca.crt");
    config.setCaCertificates(caCerts);

    QSslConfiguration::setDefaultConfiguration(config);

    return config;
}

bool SecurityManager::verifySslCertificate(const QSslCertificate &cert) const
{
    if (cert.expiryDate() < QDateTime::currentDateTime()) {
        return false;
    }

    if (!verifyPinnedCertificate(cert)) {
        return false;
    }

    return true;
}

void SecurityManager::recordFailedAttempt(const QString &username)
{
    QMutexLocker locker(&m_mutex);

    m_failedAttempts[username]++;

    if (m_failedAttempts[username] >= 5) {
        m_blockUntil[username] = QDateTime::currentDateTime().addSecs(300);
    }

    if (m_failedAttempts[username] >= 3) {
        m_captchaCodes[username] = generateCaptcha();
    }
}

bool SecurityManager::isBlocked(const QString &username) const
{
    QMutexLocker locker(&m_mutex);

    if (!m_blockUntil.contains(username)) {
        return false;
    }

    if (QDateTime::currentDateTime() < m_blockUntil[username]) {
        return true;
    }

    const_cast<SecurityManager*>(this)->resetFailedAttempts(username);
    return false;
}

void SecurityManager::resetFailedAttempts(const QString &username)
{
    QMutexLocker locker(&m_mutex);
    m_failedAttempts.remove(username);
    m_blockUntil.remove(username);
    m_captchaCodes.remove(username);
}

int SecurityManager::getRemainingAttempts(const QString &username) const
{
    QMutexLocker locker(&m_mutex);
    int attempts = m_failedAttempts.value(username, 0);
    return qMax(0, 5 - attempts);
}

QByteArray SecurityManager::hashPassword(const QString &password, const QByteArray &salt) const
{
    QCryptographicHash hash1(QCryptographicHash::Sha256);
    hash1.addData(salt);
    hash1.addData(password.toUtf8());
    QByteArray firstHash = hash1.result();

    QCryptographicHash hash2(QCryptographicHash::Sha256);
    hash2.addData(firstHash);
    hash2.addData("cryptex_server_salt_v1_2025");
    QByteArray finalHash = hash2.result();

    return finalHash.toHex();
}

QByteArray SecurityManager::generateSecureSalt() const
{
    QByteArray salt(16, 0);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1) {
        for (int i = 0; i < 16; i++) {
            salt[i] = static_cast<char>(QRandomGenerator::system()->generate() & 0xFF);
        }
    }

    return salt;
}

bool SecurityManager::verifyPassword(const QString &password, const QByteArray &salt,
                                     const QByteArray &storedHash) const
{
    QByteArray computedHash = hashPassword(password, salt);
    return constantTimeCompare(computedHash, storedHash);
}

bool SecurityManager::pinCertificate(const QByteArray &certFingerprint)
{
    QMutexLocker locker(&m_mutex);

    if (!m_pinnedFingerprints.contains(certFingerprint)) {
        m_pinnedFingerprints.append(certFingerprint);
        return true;
    }
    return false;
}

bool SecurityManager::verifyPinnedCertificate(const QSslCertificate &cert) const
{
    QMutexLocker locker(&m_mutex);

    QByteArray fingerprint = cert.digest(QCryptographicHash::Sha256).toHex();

    for (const QByteArray &pinned : m_pinnedFingerprints) {
        if (constantTimeCompare(fingerprint, pinned)) {
            return true;
        }
    }

    return false;
}

void SecurityManager::loadPinnedCertificates(const QString &path)
{
    QFile file(path);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (!line.isEmpty() && !line.startsWith("#")) {
                m_pinnedFingerprints.append(line.toUtf8());
            }
        }
        file.close();
        // Без qDebug - может вызывать краш
    }
    // Без qWarning - файл может отсутствовать
}

void SecurityManager::secureZeroMemory(void *ptr, size_t size) const
{
    volatile unsigned char *p = reinterpret_cast<volatile unsigned char *>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

void SecurityManager::secureClearString(QString &str) const
{
    if (!str.isEmpty()) {
        for (int i = 0; i < str.size(); i++) {
            str[i] = QChar(QRandomGenerator::system()->generate());
        }
        str.clear();
    }
}

void SecurityManager::secureClearByteArray(QByteArray &arr) const
{
    if (!arr.isEmpty()) {
        secureZeroMemory(arr.data(), arr.size());
        arr.clear();
    }
}

bool SecurityManager::validateUsername(const QString &username) const
{
    if (username.isEmpty() || username.length() < 3 || username.length() > 50) {
        return false;
    }

    QRegularExpression regex("^[a-zA-Z][a-zA-Z0-9_]{2,49}$");
    if (!regex.match(username).hasMatch()) {
        return false;
    }

    QStringList forbidden = {"admin", "root", "system", "null", "undefined",
                             "select", "insert", "update", "delete", "drop"};
    if (forbidden.contains(username.toLower())) {
        return false;
    }

    return true;
}

bool SecurityManager::validatePassword(const QString &password) const
{
    if (password.length() < 8 || password.length() > 128) {
        return false;
    }

    bool hasDigit = false;
    bool hasLetter = false;
    bool hasSpecial = false;
    bool hasUpper = false;

    for (const QChar &c : password) {
        if (c.isDigit()) hasDigit = true;
        else if (c.isLetter()) {
            hasLetter = true;
            if (c.isUpper()) hasUpper = true;
        }
        else hasSpecial = true;
    }

    return hasDigit && hasLetter && hasSpecial && hasUpper;
}

bool SecurityManager::validateEmail(const QString &email) const
{
    QRegularExpression regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    return regex.match(email).hasMatch() && email.length() <= 100;
}

QString SecurityManager::sanitizeInput(const QString &input) const
{
    QString sanitized = input;
    sanitized.remove(QRegularExpression("[<>\"'&;]"));
    sanitized = sanitized.trimmed();
    return sanitized;
}

QString SecurityManager::getGenericErrorMessage() const
{
    return "Неверный логин или пароль";
}

void SecurityManager::logSecurityEvent(const QString &eventType, const QString &username,
                                       const QString &details, bool success)
{
    // Отключено - может вызывать краш кучи
    Q_UNUSED(eventType);
    Q_UNUSED(username);
    Q_UNUSED(details);
    Q_UNUSED(success);
}

QByteArray SecurityManager::getEncryptedLog(const QString &logEntry) const
{
    QByteArray data = logEntry.toUtf8();
    QByteArray key = "CryptexLogKey2025SecureKey32!";

    for (int i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }

    return data.toBase64();
}

QString SecurityManager::getLogFilePath() const
{
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(path);
    return path + "/security_audit.log";
}

QString SecurityManager::getSecureStoragePath() const
{
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(path);
    return path;
}

void SecurityManager::encryptAndWriteLog(const QByteArray &encryptedLog)
{
    QFile file(getLogFilePath());
    if (file.open(QIODevice::Append | QIODevice::WriteOnly)) {
        file.write(encryptedLog);
        file.write("\n");
        file.close();
    }
}

QByteArray SecurityManager::decryptLog(const QByteArray &encryptedLog) const
{
    QByteArray data = QByteArray::fromBase64(encryptedLog);
    QByteArray key = "CryptexLogKey2025SecureKey32!";

    for (int i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }

    return data;
}

bool SecurityManager::isCaptchaRequired(const QString &username) const
{
    QMutexLocker locker(&m_mutex);
    int attempts = m_failedAttempts.value(username, 0);
    return attempts >= 3;
}

QString SecurityManager::generateCaptcha() const
{
    const QString chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    QString captcha;

    for (int i = 0; i < 6; i++) {
        captcha += chars.at(QRandomGenerator::system()->bounded(chars.length()));
    }

    return captcha;
}

bool SecurityManager::verifyCaptcha(const QString &username, const QString &captchaInput) const
{
    QMutexLocker locker(&m_mutex);

    if (!m_captchaCodes.contains(username)) {
        return false;
    }

    return constantTimeCompare(m_captchaCodes[username].toUpper().toUtf8(),
                               captchaInput.toUpper().toUtf8());
}

void SecurityManager::startSessionTimer(int timeoutMs)
{
    m_sessionTimer->start(timeoutMs);
    m_sessionActive = true;
}

void SecurityManager::stopSessionTimer()
{
    m_sessionTimer->stop();
    m_sessionActive = false;
}

bool SecurityManager::isSessionActive() const
{
    return m_sessionActive;
}

QByteArray SecurityManager::generateSecureRandom(int bytes) const
{
    QByteArray random(bytes, 0);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(random.data()), bytes) != 1) {
        for (int i = 0; i < bytes; i++) {
            random[i] = QRandomGenerator::system()->generate() & 0xFF;
        }
    }

    return random;
}

bool SecurityManager::constantTimeCompare(const QByteArray &a, const QByteArray &b) const
{
    if (a.size() != b.size()) {
        volatile unsigned char result = 1;
        for (int i = 0; i < a.size(); i++) {
            result |= a[i] ^ a[i];
        }
        return false;
    }

    volatile unsigned char result = 0;
    for (int i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }

    return result == 0;
}
