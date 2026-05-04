#include "CryptoEngine.h"
#include <QtDebug>
#include <QFileInfo>
#include <QDataStream>
#include <QBuffer>
#include <QRegularExpression>
#include <QSslSocket>
// OpenSSL headers included only in .cpp (not in .h) to avoid moc OOM
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

CryptoEngine::CryptoEngine(QObject *parent)
    : QObject(parent)
    , m_rsaPrivateKey(nullptr)
    , m_rsaPublicKey(nullptr)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    qDebug() << "[Crypto] CryptoEngine initialized";
    qDebug() << "[Crypto] OpenSSL version:" << getOpenSSLVersion();
}

CryptoEngine::~CryptoEngine()
{
    if (m_rsaPrivateKey) {
        EVP_PKEY_free(m_rsaPrivateKey);
        m_rsaPrivateKey = nullptr;
    }

    if (m_rsaPublicKey) {
        EVP_PKEY_free(m_rsaPublicKey);
        m_rsaPublicKey = nullptr;
    }

    EVP_cleanup();
    ERR_free_strings();

    qDebug() << "[Crypto] CryptoEngine destroyed, keys cleared";
}

CryptoEngine& CryptoEngine::getInstance()
{
    static CryptoEngine instance;
    return instance;
}

// Обёртка для совместимости с LoginWindow
QByteArray CryptoEngine::encryptWithServerKey(const QByteArray &data)
{
    return encryptData(data);
}

QByteArray CryptoEngine::decryptFromServerKey(const QByteArray &encryptedData)
{
    return decryptData(encryptedData);
}

bool CryptoEngine::encryptFile(const QString &inputPath, const QString &outputPath,
                               const QString &password)
{
    QMutexLocker locker(&m_mutex);

    qDebug() << "[Crypto] Encrypting file:" << inputPath;

    if (!QFile::exists(inputPath)) {
        qWarning() << "[Crypto] Input file not found:" << inputPath;
        return false;
    }

    if (password.length() < 8) {
        qWarning() << "[Crypto] Password too short (min 8 characters)";
        return false;
    }

    QByteArray salt = generateSecureSalt();
    QByteArray nonce = generateSecureNonce();

    QString originalHash = calculateFileHash(inputPath);

    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qWarning() << "[Crypto] Cannot open input file:" << inputFile.errorString();
        return false;
    }
    QByteArray plaintext = inputFile.readAll();
    quint32 originalSize = plaintext.size();
    inputFile.close();

    QByteArray key = deriveKeyFromPassword(password, salt, 100000);

    QByteArray ciphertext;
    QByteArray authTag;

    if (!encryptAES256GCM(plaintext, key, nonce, ciphertext, authTag)) {
        qWarning() << "[Crypto] AES encryption failed";
        secureZeroMemory(key.data(), key.size());
        return false;
    }

    secureZeroMemory(key.data(), key.size());

    QFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly)) {
        qWarning() << "[Crypto] Cannot open output file:" << outputFile.errorString();
        return false;
    }

    FileHeader header;
    std::memcpy(header.magic, "CRYPTEX01", 8);
    header.version = 1;
    header.salt = salt;
    header.nonce = nonce;
    header.authTag = authTag;
    header.originalHash = QByteArray::fromHex(originalHash.toUtf8());
    header.originalSize = originalSize;
    header.originalName = QFileInfo(inputPath).fileName();

    if (!writeFileHeader(outputFile, header)) {
        outputFile.close();
        return false;
    }

    outputFile.write(ciphertext);
    outputFile.close();

    secureZeroMemory(plaintext.data(), plaintext.size());
    secureClearByteArray(ciphertext);

    qDebug() << "[Crypto] File encrypted successfully:" << outputPath;
    return true;
}

bool CryptoEngine::decryptFile(const QString &inputPath, const QString &outputPath,
                               const QString &password)
{
    QMutexLocker locker(&m_mutex);

    qDebug() << "[Crypto] Decrypting file:" << inputPath;

    if (!QFile::exists(inputPath)) {
        qWarning() << "[Crypto] Input file not found:" << inputPath;
        return false;
    }

    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qWarning() << "[Crypto] Cannot open input file:" << inputFile.errorString();
        return false;
    }

    FileHeader header;
    if (!readFileHeader(inputFile, header)) {
        inputFile.close();
        return false;
    }

    if (std::memcmp(header.magic, "CRYPTEX01", 8) != 0) {
        qWarning() << "[Crypto] Invalid file format (wrong magic bytes)";
        inputFile.close();
        return false;
    }

    QByteArray ciphertext = inputFile.readAll();
    inputFile.close();

    QByteArray key = deriveKeyFromPassword(password, header.salt, 100000);

    QByteArray plaintext;
    if (!decryptAES256GCM(ciphertext, key, header.nonce, header.authTag, plaintext)) {
        qWarning() << "[Crypto] AES decryption failed (wrong password or corrupted data)";
        secureZeroMemory(key.data(), key.size());
        secureClearByteArray(plaintext);
        return false;
    }

    secureZeroMemory(key.data(), key.size());

    QString computedHash = QCryptographicHash::hash(plaintext, QCryptographicHash::Sha256).toHex();
    QString expectedHash = header.originalHash.toHex();

    if (computedHash != expectedHash) {
        qWarning() << "[Crypto] File integrity check failed!";
        secureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }

    QFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly)) {
        qWarning() << "[Crypto] Cannot open output file:" << outputFile.errorString();
        secureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }
    outputFile.write(plaintext);
    outputFile.close();

    secureZeroMemory(plaintext.data(), plaintext.size());

    qDebug() << "[Crypto] File decrypted successfully:" << outputPath;
    return true;
}

QByteArray CryptoEngine::encryptData(const QByteArray &data)
{
    QMutexLocker locker(&m_mutex);

    // БАГОФИКС: соль (16 байт) сохраняется в результате для возможности расшифровки.
    // Раньше ключ генерировался из случайной соли, которая нигде не сохранялась,
    // что делало decryptData неработоспособным.
    QByteArray salt = generateSecureSalt();
    QByteArray key = QCryptographicHash::hash(salt, QCryptographicHash::Sha256);

    QByteArray nonce = generateSecureNonce();
    QByteArray ciphertext;
    QByteArray authTag;

    if (!encryptAES256GCM(data, key, nonce, ciphertext, authTag)) {
        qWarning() << "[Crypto] Data encryption failed";
        secureClearByteArray(key);
        return QByteArray();
    }

    // Формат: salt(16) + nonce(12) + authTag(16) + ciphertext
    QByteArray result;
    result.append(salt);
    result.append(nonce);
    result.append(authTag);
    result.append(ciphertext);

    secureClearByteArray(key);

    return result;
}

QByteArray CryptoEngine::decryptData(const QByteArray &encryptedData)
{
    QMutexLocker locker(&m_mutex);

    // БАГОФИКС: минимальный размер с учётом соли: salt(16) + nonce(12) + authTag(16) = 44 байта
    if (encryptedData.size() < 44) {
        qWarning() << "[Crypto] Encrypted data too short";
        return QByteArray();
    }

    QByteArray salt = encryptedData.left(16);
    QByteArray nonce = encryptedData.mid(16, 12);
    QByteArray authTag = encryptedData.mid(28, 16);
    QByteArray ciphertext = encryptedData.mid(44);

    QByteArray key = QCryptographicHash::hash(salt, QCryptographicHash::Sha256);

    QByteArray plaintext;
    if (!decryptAES256GCM(ciphertext, key, nonce, authTag, plaintext)) {
        qWarning() << "[Crypto] Data decryption failed";
        secureClearByteArray(key);
        return QByteArray();
    }

    secureClearByteArray(key);

    return plaintext;
}

QByteArray CryptoEngine::deriveKeyFromPassword(const QString &password,
                                               const QByteArray &salt,
                                               int iterations)
{
    QByteArray key(32, 0);
    // БАГОФИКС: toUtf8() вызывается один раз во избежание двух временных объектов
    QByteArray passwordUtf8 = password.toUtf8();

    if (PKCS5_PBKDF2_HMAC(
            passwordUtf8.constData(),
            passwordUtf8.size(),
            reinterpret_cast<const unsigned char*>(salt.constData()),
            salt.size(),
            iterations,
            EVP_sha256(),
            key.size(),
            reinterpret_cast<unsigned char*>(key.data())
            ) != 1) {
        qWarning() << "[Crypto] PBKDF2 key derivation failed";
        return QByteArray();
    }

    qDebug() << "[Crypto] Key derived with PBKDF2, iterations:" << iterations;
    return key;
}

QByteArray CryptoEngine::generateSecureSalt()
{
    QByteArray salt(16, 0);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1) {
        for (int i = 0; i < salt.size(); i++) {
            salt[i] = static_cast<char>(QRandomGenerator::system()->generate() & 0xFF);
        }
    }

    return salt;
}

QByteArray CryptoEngine::generateSecureNonce()
{
    QByteArray nonce(12, 0);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), nonce.size()) != 1) {
        for (int i = 0; i < nonce.size(); i++) {
            nonce[i] = static_cast<char>(QRandomGenerator::system()->generate() & 0xFF);
        }
    }

    return nonce;
}

QString CryptoEngine::calculateFileHash(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[Crypto] Cannot open file for hash:" << filePath;
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);

    while (!file.atEnd()) {
        QByteArray data = file.read(65536);
        hash.addData(data);
    }

    file.close();

    return hash.result().toHex();
}

bool CryptoEngine::verifyFileIntegrity(const QString &filePath,
                                       const QString &expectedHash)
{
    QString computedHash = calculateFileHash(filePath);
    return computedHash.toLower() == expectedHash.toLower();
}

void CryptoEngine::secureZeroMemory(void *ptr, size_t size)
{
    if (ptr == nullptr || size == 0) return;

    volatile unsigned char *p = reinterpret_cast<volatile unsigned char *>(ptr);

    for (size_t i = 0; i < size; i++) p[i] = 0x00;
    for (size_t i = 0; i < size; i++) p[i] = 0xFF;
    for (size_t i = 0; i < size; i++) p[i] = 0x00;
}

void CryptoEngine::secureClearString(QString &str)
{
    if (str.isEmpty()) return;

    for (int i = 0; i < str.size(); i++) {
        str[i] = QChar(QRandomGenerator::system()->generate() & 0xFFFF);
    }
    str.clear();
}

void CryptoEngine::secureClearByteArray(QByteArray &arr)
{
    if (arr.isEmpty()) return;

    secureZeroMemory(arr.data(), arr.size());
    arr.clear();
}

bool CryptoEngine::generateRSAKeyPair(int keySize)
{
    QMutexLocker locker(&m_mutex);

    if (m_rsaPrivateKey) {
        EVP_PKEY_free(m_rsaPrivateKey);
        m_rsaPrivateKey = nullptr;
    }
    if (m_rsaPublicKey) {
        EVP_PKEY_free(m_rsaPublicKey);
        m_rsaPublicKey = nullptr;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        qWarning() << "[Crypto] RSA key generation context failed";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_keygen(ctx, &m_rsaPrivateKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    m_rsaPublicKey = EVP_PKEY_dup(m_rsaPrivateKey);

    qDebug() << "[Crypto] RSA key pair generated:" << keySize << "bits";
    return true;
}

QByteArray CryptoEngine::rsaEncrypt(const QByteArray &data, const QByteArray &publicKey)
{
    QMutexLocker locker(&m_mutex);

    BIO *bio = BIO_new_mem_buf(publicKey.constData(), publicKey.size());
    if (!bio) return QByteArray();

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        qWarning() << "[Crypto] Failed to load public key";
        return QByteArray();
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);

    if (!ctx) {
        return QByteArray();
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx, nullptr, &outlen,
                     reinterpret_cast<const unsigned char*>(data.constData()),
                     data.size());

    QByteArray encrypted(outlen, 0);

    if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(encrypted.data()),
                         &outlen,
                         reinterpret_cast<const unsigned char*>(data.constData()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    EVP_PKEY_CTX_free(ctx);
    encrypted.resize(outlen);

    return encrypted;
}

QByteArray CryptoEngine::rsaDecrypt(const QByteArray &encryptedData, const QByteArray &privateKey)
{
    QMutexLocker locker(&m_mutex);

    BIO *bio = BIO_new_mem_buf(privateKey.constData(), privateKey.size());
    if (!bio) return QByteArray();

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        qWarning() << "[Crypto] Failed to load private key";
        return QByteArray();
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);

    if (!ctx) {
        return QByteArray();
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                     reinterpret_cast<const unsigned char*>(encryptedData.constData()),
                     encryptedData.size());

    QByteArray decrypted(outlen, 0);

    if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(decrypted.data()),
                         &outlen,
                         reinterpret_cast<const unsigned char*>(encryptedData.constData()),
                         encryptedData.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return QByteArray();
    }

    EVP_PKEY_CTX_free(ctx);
    decrypted.resize(outlen);

    return decrypted;
}

bool CryptoEngine::encryptAES256GCM(const QByteArray &plaintext, const QByteArray &key,
                                    const QByteArray &nonce, QByteArray &ciphertext,
                                    QByteArray &authTag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &len, reinterpret_cast<const unsigned char*>(plaintext.constData()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // БАГОФИКС: не сужаем буфер до Final_ex — ciphertext.data() + len
    // должен указывать на валидную память, иначе UB даже при finalLen == 0.
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                            &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(len + finalLen);

    authTag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, authTag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool CryptoEngine::decryptAES256GCM(const QByteArray &ciphertext, const QByteArray &key,
                                    const QByteArray &nonce, const QByteArray &authTag,
                                    QByteArray &plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()),
                          &len, reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                          ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // БАГОФИКС: не сужаем буфер до проверки тега и Final_ex.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authTag.size(),
                            const_cast<char*>(authTag.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int finalLen = 0;
    int result = EVP_DecryptFinal_ex(ctx,
                                     reinterpret_cast<unsigned char*>(plaintext.data()) + len,
                                     &finalLen);

    EVP_CIPHER_CTX_free(ctx);

    if (result <= 0) {
        plaintext.clear();
        return false;
    }

    plaintext.resize(len + finalLen);
    return true;
}

bool CryptoEngine::writeFileHeader(QFile &file, const FileHeader &header)
{
    QDataStream out(&file);
    out.setByteOrder(QDataStream::LittleEndian);

    out.writeRawData(header.magic, 8);
    out << header.version;
    out.writeRawData(header.salt.constData(), header.salt.size());
    out.writeRawData(header.nonce.constData(), header.nonce.size());
    out.writeRawData(header.authTag.constData(), header.authTag.size());
    out.writeRawData(header.originalHash.constData(), header.originalHash.size());
    out << header.originalSize;
    out << header.originalName;

    return out.status() == QDataStream::Ok;
}

bool CryptoEngine::readFileHeader(QFile &file, FileHeader &header)
{
    QDataStream in(&file);
    in.setByteOrder(QDataStream::LittleEndian);

    in.readRawData(header.magic, 8);
    in >> header.version;

    header.salt.resize(16);
    in.readRawData(header.salt.data(), 16);

    header.nonce.resize(12);
    in.readRawData(header.nonce.data(), 12);

    header.authTag.resize(16);
    in.readRawData(header.authTag.data(), 16);

    header.originalHash.resize(32);
    in.readRawData(header.originalHash.data(), 32);

    in >> header.originalSize;
    in >> header.originalName;

    // БАГОФИКС: проверка статуса потока вместо atEnd().
    // atEnd() может вернуть true даже при ошибке чтения.
    return in.status() == QDataStream::Ok;
}

bool CryptoEngine::isOpenSSLAvailable() const
{
    return QSslSocket::supportsSsl();
}

QString CryptoEngine::getOpenSSLVersion() const
{
    return QString::fromUtf8(OpenSSL_version(OPENSSL_VERSION));
}
