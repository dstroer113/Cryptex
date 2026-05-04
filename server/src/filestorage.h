#ifndef FILESTORAGE_H
#define FILESTORAGE_H

#include <QObject>
#include <QString>
#include <QDir>
#include <QByteArray>
#include <QMutex>
#include <QMutexLocker>

class FileStorage : public QObject
{
    Q_OBJECT

public:
    explicit FileStorage(const QString &basePath, QObject *parent = nullptr);
    ~FileStorage() override;

    bool initialize();

    // Сохраняет зашифрованный файл. Возвращает относительный путь.
    QString storeFile(int transferId, const QByteArray &encryptedData);
    QByteArray loadFile(const QString &storagePath);
    bool deleteFile(const QString &storagePath);
    bool fileExists(const QString &storagePath) const;
    qint64 fileSize(const QString &storagePath) const;

    // Абсолютный путь
    QString absolutePath(const QString &storagePath) const;

    // Очистка
    void cleanupOrphanedFiles(int olderThanDays = 7);
    qint64 totalStorageUsed() const;

    // Квота
    static constexpr qint64 MAX_FILE_SIZE = 31457280;  // 30 MB
    static constexpr qint64 MAX_USER_QUOTA = 52428800; // 50 MB

private:
    QString m_basePath;
    mutable QMutex m_mutex;

    QString sanitizePath(const QString &path) const;
};

#endif // FILESTORAGE_H