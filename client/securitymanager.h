#ifndef SECURITYMANAGER_H
#define SECURITYMANAGER_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QTimer>
#include <QHash>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QFile>
#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>
#include <QMutex>
#include <QMutexLocker>
#include <cstring>
// OpenSSL removed from header to reduce memory usage during moc compilation

class SecurityManager : public QObject
{
    Q_OBJECT

public:
    static SecurityManager& getInstance();

    QSslConfiguration getSecureSslConfig() const;
    bool verifySslCertificate(const QSslCertificate &cert) const;

    void recordFailedAttempt(const QString &username);
    bool isBlocked(const QString &username) const;
    void resetFailedAttempts(const QString &username);
    int getRemainingAttempts(const QString &username) const;

    QByteArray hashPassword(const QString &password, const QByteArray &salt) const;
    QByteArray generateSecureSalt() const;
    bool verifyPassword(const QString &password, const QByteArray &salt,
                        const QByteArray &storedHash) const;

    bool pinCertificate(const QByteArray &certFingerprint);
    bool verifyPinnedCertificate(const QSslCertificate &cert) const;
    void loadPinnedCertificates(const QString &path);

    void secureZeroMemory(void *ptr, size_t size) const;
    void secureClearString(QString &str) const;
    void secureClearByteArray(QByteArray &arr) const;

    bool validateUsername(const QString &username) const;
    bool validatePassword(const QString &password) const;
    bool validateEmail(const QString &email) const;
    QString sanitizeInput(const QString &input) const;

    QString getGenericErrorMessage() const;

    void logSecurityEvent(const QString &eventType, const QString &username,
                          const QString &details, bool success);
    QByteArray getEncryptedLog(const QString &logEntry) const;

    bool isCaptchaRequired(const QString &username) const;
    QString generateCaptcha() const;
    bool verifyCaptcha(const QString &username, const QString &captchaInput) const;

    void startSessionTimer(int timeoutMs);
    void stopSessionTimer();
    bool isSessionActive() const;

    QByteArray generateSecureRandom(int bytes) const;
    bool constantTimeCompare(const QByteArray &a, const QByteArray &b) const;

private:
    explicit SecurityManager(QObject *parent = nullptr);
    ~SecurityManager();
    SecurityManager(const SecurityManager&) = delete;
    SecurityManager& operator=(const SecurityManager&) = delete;

    QHash<QString, int> m_failedAttempts;
    QHash<QString, QDateTime> m_blockUntil;
    QHash<QString, QString> m_captchaCodes;

    QList<QByteArray> m_pinnedFingerprints;

    QTimer *m_sessionTimer;
    bool m_sessionActive;

    mutable QMutex m_mutex;

    QString getLogFilePath() const;
    QString getSecureStoragePath() const;

    void encryptAndWriteLog(const QByteArray &encryptedLog);
    QByteArray decryptLog(const QByteArray &encryptedLog) const;
};

#endif // SECURITYMANAGER_H