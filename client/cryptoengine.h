#ifndef CRYPTOENGINE_H
#define CRYPTOENGINE_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QFile>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDir>
#include <QStandardPaths>
#include <QDateTime>
#include <QMutex>
#include <QMutexLocker>
#include <QSslSocket>
#include <cstring>
// OpenSSL headers moved to .cpp to reduce moc memory usage
// Forward declare EVP_PKEY to avoid including openssl headers
struct evp_pkey_st;

class CryptoEngine : public QObject
{
    Q_OBJECT

public:
    static CryptoEngine& getInstance();

    bool encryptFile(const QString &inputPath, const QString &outputPath, const QString &password);
    bool decryptFile(const QString &inputPath, const QString &outputPath, const QString &password);

    QByteArray encryptData(const QByteArray &data);
    QByteArray decryptData(const QByteArray &encryptedData);

    QByteArray encryptWithServerKey(const QByteArray &data);
    QByteArray decryptFromServerKey(const QByteArray &encryptedData);

    QByteArray deriveKeyFromPassword(const QString &password, const QByteArray &salt, int iterations = 100000);
    QByteArray generateSecureSalt();
    QByteArray generateSecureNonce();

    QString calculateFileHash(const QString &filePath);
    bool verifyFileIntegrity(const QString &filePath, const QString &expectedHash);

    void secureZeroMemory(void *ptr, size_t size);
    void secureClearString(QString &str);
    void secureClearByteArray(QByteArray &arr);

    bool generateRSAKeyPair(int keySize = 4096);
    QByteArray rsaEncrypt(const QByteArray &data, const QByteArray &publicKey);
    QByteArray rsaDecrypt(const QByteArray &encryptedData, const QByteArray &privateKey);

    bool isOpenSSLAvailable() const;
    QString getOpenSSLVersion() const;

//private:
    explicit CryptoEngine(QObject *parent = nullptr);
    ~CryptoEngine();
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    evp_pkey_st *m_rsaPrivateKey;
    evp_pkey_st *m_rsaPublicKey;
    mutable QMutex m_mutex;

    bool encryptAES256GCM(const QByteArray &plaintext, const QByteArray &key,
                          const QByteArray &nonce, QByteArray &ciphertext, QByteArray &authTag);
    bool decryptAES256GCM(const QByteArray &ciphertext, const QByteArray &key,
                          const QByteArray &nonce, const QByteArray &authTag, QByteArray &plaintext);

    struct FileHeader {
        char magic[8];
        quint8 version;
        QByteArray salt;
        QByteArray nonce;
        QByteArray authTag;
        QByteArray originalHash;
        quint32 originalSize;
        QString originalName;
    };

    bool writeFileHeader(QFile &file, const FileHeader &header);
    bool readFileHeader(QFile &file, FileHeader &header);
};

#endif // CRYPTOENGINE_H