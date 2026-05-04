#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <QByteArray>
#include <QString>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDataStream>
#include <cstdio>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

// ============================================
// Cryptex Protocol v2.0
// Безопасный протокол обмена поверх TLS 1.3
// Все сообщения шифруются AES-256-GCM ключом сессии
// HMAC-SHA256 для проверки целостности каждого пакета
// ============================================

namespace CryptexProtocol {

// Коды команд
namespace Command {
    // Аутентификация
    constexpr const char* LOGIN          = "AUTH_LOGIN";
    constexpr const char* REGISTER       = "AUTH_REGISTER";
    constexpr const char* LOGOUT         = "AUTH_LOGOUT";
    constexpr const char* SESSION_VALID  = "AUTH_SESSION_VALID";
    constexpr const char* PASSWORD_RESET = "AUTH_PASSWORD_RESET";

    // Контакты
    constexpr const char* CONTACTS_LIST     = "CONTACTS_LIST";
    constexpr const char* CONTACT_ADD       = "CONTACT_ADD";
    constexpr const char* CONTACT_REMOVE    = "CONTACT_REMOVE";
    constexpr const char* CONTACT_REQUESTS  = "CONTACT_REQUESTS";
    constexpr const char* CONTACT_ACCEPT    = "CONTACT_ACCEPT";
    constexpr const char* CONTACT_REJECT    = "CONTACT_REJECT";
    constexpr const char* USER_LOOKUP       = "USER_LOOKUP";

    // Файлы
    constexpr const char* FILE_SEND_INIT     = "FILE_SEND_INIT";
    constexpr const char* FILE_SEND_CHUNK    = "FILE_SEND_CHUNK";
    constexpr const char* FILE_SEND_COMPLETE = "FILE_SEND_COMPLETE";
    constexpr const char* FILE_RECEIVE_LIST  = "FILE_RECEIVE_LIST";
    constexpr const char* FILE_DOWNLOAD_INIT = "FILE_DOWNLOAD_INIT";
    constexpr const char* FILE_DOWNLOAD_CHUNK = "FILE_DOWNLOAD_CHUNK";
    constexpr const char* FILE_CANCEL       = "FILE_CANCEL";
    constexpr const char* FILE_STATUS       = "FILE_STATUS";

    // Контакты / онлайн
    constexpr const char* CHECK_ONLINE    = "CHECK_ONLINE";

    // Системные
    constexpr const char* PING     = "SYS_PING";
    constexpr const char* PONG     = "SYS_PONG";
    constexpr const char* ERROR    = "SYS_ERROR";
    constexpr const char* OK       = "SYS_OK";
}

// Размер чанка для передачи файлов (1 MB)
constexpr int FILE_CHUNK_SIZE = 1048576;

// Максимальный размер сообщения: 35 MB (файл 30 MB + заголовки + overhead)
constexpr int MAX_MESSAGE_SIZE = 36700160;

// Формат заголовка пакета (wire format):
// ┌──────────┬──────────┬──────────┬───────────────────┐
// │ Version  │ Command  │ Payload  │ HMAC-SHA256 (32B) │
// │ 1 byte   │ Length   │ Length   │                   │
// │ (0x02)   │ 1 byte   │ 4 bytes  │                   │
// └──────────┴──────────┴──────────┴───────────────────┘
// Всё, кроме Version, шифруется AES-256-GCM

/**
 * @brief Создаёт JSON-сообщение для отправки
 */
inline QJsonObject createMessage(const QString &command, const QJsonObject &data = {})
{
    QJsonObject msg;
    msg["cmd"] = command;
    msg["data"] = data.isEmpty() ? QJsonObject() : data;
    msg["ts"] = QString::number(QDateTime::currentSecsSinceEpoch());
    return msg;
}

inline QJsonObject createOkResponse(const QString &message = "OK")
{
    QJsonObject data;
    data["message"] = message;
    return createMessage(Command::OK, data);
}

inline QJsonObject createErrorResponse(const QString &error, const QString &details = "")
{
    QJsonObject data;
    data["error"] = error;
    if (!details.isEmpty()) data["details"] = details;
    return createMessage(Command::ERROR, data);
}

/**
 * @brief Шифрование данных сессионным ключом AES-256-GCM
 * Формат: nonce(12) + authTag(16) + ciphertext
 */
inline QByteArray encryptSessionPayload(const QByteArray &plaintext,
                                        const QByteArray &sessionKey)
{
    if (sessionKey.size() != 32) return QByteArray();

    QByteArray nonce(12, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), 12);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(sessionKey.constData()),
                           reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    QByteArray ciphertext(plaintext.size() + 16, 0);
    int len = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &len,
                          reinterpret_cast<const unsigned char*>(plaintext.constData()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                            &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    ciphertext.resize(len + finalLen);

    QByteArray authTag(16, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, authTag.data());
    EVP_CIPHER_CTX_free(ctx);

    // nonce(12) + authTag(16) + ciphertext
    QByteArray result;
    result.append(nonce);
    result.append(authTag);
    result.append(ciphertext);
    return result;
}

/**
 * @brief Дешифрование данных сессионным ключом
 */
inline QByteArray decryptSessionPayload(const QByteArray &encrypted,
                                         const QByteArray &sessionKey)
{
    if (sessionKey.size() != 32) return QByteArray();
    if (encrypted.size() < 28) return QByteArray(); // nonce(12) + tag(16) минимум

    QByteArray nonce = encrypted.left(12);
    QByteArray authTag = encrypted.mid(12, 16);
    QByteArray ciphertext = encrypted.mid(28);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(sessionKey.constData()),
                           reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    QByteArray plaintext(ciphertext.size(), 0);
    int len = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()),
                          &len,
                          reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                          ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                        const_cast<char*>(authTag.constData()));

    int finalLen = 0;
    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len,
                                  &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return QByteArray();

    plaintext.resize(len + finalLen);
    return plaintext;
}

/**
 * @brief Генерация сессионного ключа (256 бит)
 */
inline QByteArray generateSessionKey()
{
    QByteArray key(32, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), 32);
    return key;
}

/**
 * @brief HMAC-SHA256 для проверки целостности пакета
 */
inline QByteArray computeHMAC(const QByteArray &data, const QByteArray &hmacKey)
{
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultLen = 0;

    HMAC(EVP_sha256(),
         hmacKey.constData(), hmacKey.size(),
         reinterpret_cast<const unsigned char*>(data.constData()), data.size(),
         result, &resultLen);

    return QByteArray(reinterpret_cast<const char*>(result), resultLen);
}

inline bool verifyHMAC(const QByteArray &data, const QByteArray &hmac,
                       const QByteArray &hmacKey)
{
    QByteArray computed = computeHMAC(data, hmacKey);
    if (computed.size() != hmac.size()) return false;

    // Constant-time сравнение
    volatile unsigned char result = 0;
    for (int i = 0; i < computed.size(); i++) {
        result |= computed[i] ^ hmac[i];
    }
    return result == 0;
}

/**
 * @brief Сериализация без шифрования (для SESSION_KEY, первый обмен)
 */
inline QByteArray serializePacketPlain(const QJsonObject &message)
{
    QJsonDocument doc(message);
    QByteArray payload = doc.toJson(QJsonDocument::Compact);
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << static_cast<quint32>(payload.size());
    stream.writeRawData(payload.constData(), payload.size());
    return packet;
}

/**
 * @brief Десериализация без расшифровки (первый пакет, ключей ещё нет)
 */
inline QJsonObject deserializePacketPlain(const QByteArray &packet)
{
    if (packet.size() < 4) return {};
    QDataStream stream(packet);
    stream.setByteOrder(QDataStream::BigEndian);
    quint32 ps = 0;
    stream >> ps;
    if (ps == 0 || ps > static_cast<quint32>(MAX_MESSAGE_SIZE)) return {};
    if (packet.size() < 4 + static_cast<int>(ps)) return {};
    QByteArray payload = packet.mid(4, ps);
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(payload, &err);
    return (err.error == QJsonParseError::NoError && doc.isObject()) ? doc.object() : QJsonObject();
}

/**
 * @brief Сериализация пакета для отправки (AES-256-GCM + HMAC)
 * Wire format: [encrypted_payload][HMAC(encrypted_payload)]
 */
inline QByteArray serializePacket(const QJsonObject &message,
                                  const QByteArray &sessionKey,
                                  const QByteArray &hmacKey)
{
    QJsonDocument doc(message);
    QByteArray payload = doc.toJson(QJsonDocument::Compact);
    QByteArray encrypted = encryptSessionPayload(payload, sessionKey);

    if (encrypted.isEmpty()) return QByteArray();

    // Добавляем HMAC
    QByteArray hmac = computeHMAC(encrypted, hmacKey);

    // Wire format с длинами для парсинга
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << static_cast<quint32>(encrypted.size());
    stream.writeRawData(encrypted.constData(), encrypted.size());
    stream << static_cast<quint32>(hmac.size());
    stream.writeRawData(hmac.constData(), hmac.size());

    return packet;
}

/**
 * @brief Десериализация пакета
 * Возвращает QJsonObject{} при ошибке
 */
inline QJsonObject deserializePacket(const QByteArray &packet,
                                     const QByteArray &sessionKey,
                                     const QByteArray &hmacKey)
{
    if (packet.size() < 8) return {};

    QDataStream stream(packet);
    stream.setByteOrder(QDataStream::BigEndian);

    quint32 payloadSize = 0;
    stream >> payloadSize;

    if (payloadSize == 0 || payloadSize > static_cast<quint32>(MAX_MESSAGE_SIZE)) return {};
    if (packet.size() < 4 + payloadSize + 4 + 32) return {};

    QByteArray encrypted = packet.mid(4, payloadSize);

    // Пропускаем encrypted данные в стриме перед чтением hmacSize
    stream.skipRawData(payloadSize);

    quint32 hmacSize = 0;
    stream >> hmacSize;
    if (hmacSize != 32) return {};

    QByteArray hmac = packet.mid(4 + payloadSize + 4, 32);

    // Проверяем HMAC до расшифровки
    if (!hmacKey.isEmpty() && !verifyHMAC(encrypted, hmac, hmacKey)) {
        fprintf(stderr, "[PKT] HMAC FAIL enc=%d hmac=%d key=%d\n", encrypted.size(), hmac.size(), hmacKey.size());
        fflush(stderr);
        return {};
    }

    QByteArray payload = decryptSessionPayload(encrypted, sessionKey);
    if (payload.isEmpty()) {
        fprintf(stderr, "[PKT] AES decrypt FAIL enc=%d key=%d\n", encrypted.size(), sessionKey.size());
        fflush(stderr);
        return {};
    }

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(payload, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        fprintf(stderr, "[PKT] JSON parse FAIL err=%d payload=%.20s\n", err.error, payload.constData());
        fflush(stderr);
        return {};
    }

    return doc.object();
}

} // namespace CryptexProtocol

#endif // PROTOCOL_H