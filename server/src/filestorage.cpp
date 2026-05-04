#include "filestorage.h"
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDebug>
#include <openssl/rand.h>

FileStorage::FileStorage(const QString &basePath, QObject *parent)
    : QObject(parent), m_basePath(basePath)
{
}

FileStorage::~FileStorage() = default;

bool FileStorage::initialize()
{
    QDir dir(m_basePath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            qCritical() << "[Storage] Cannot create storage dir:" << m_basePath;
            return false;
        }
    }
    qInfo() << "[Storage] Initialized at:" << m_basePath;
    return true;
}

QString FileStorage::storeFile(int transferId, const QByteArray &encryptedData)
{
    QMutexLocker locker(&m_mutex);

    if (encryptedData.size() > MAX_FILE_SIZE) return {};

    QByteArray randomName(16, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(randomName.data()), 16);
    QString filename = randomName.toHex() + "_" + QString::number(transferId) + ".cryptex";

    QString relPath = QDateTime::currentDateTime().toString("yyyy/MM");
    QDir dir(m_basePath + "/" + relPath);
    if (!dir.exists()) dir.mkpath(".");

    QString fullPath = dir.absoluteFilePath(filename);
    QFile file(fullPath);
    if (!file.open(QIODevice::WriteOnly)) return {};
    file.write(encryptedData);
    file.close();

    return relPath + "/" + filename;
}

QByteArray FileStorage::loadFile(const QString &storagePath)
{
    QMutexLocker locker(&m_mutex);
    QString path = sanitizePath(storagePath);
    if (path.isEmpty()) return {};

    QFile file(absolutePath(path));
    if (!file.open(QIODevice::ReadOnly)) return {};
    QByteArray data = file.readAll();
    file.close();
    return data;
}

bool FileStorage::deleteFile(const QString &storagePath)
{
    QMutexLocker locker(&m_mutex);
    QString path = sanitizePath(storagePath);
    if (path.isEmpty()) return false;
    return QFile::remove(absolutePath(path));
}

bool FileStorage::fileExists(const QString &storagePath) const
{
    QMutexLocker locker(&m_mutex);
    QString path = sanitizePath(storagePath);
    return !path.isEmpty() && QFile::exists(absolutePath(path));
}

qint64 FileStorage::fileSize(const QString &storagePath) const
{
    QMutexLocker locker(&m_mutex);
    QString path = sanitizePath(storagePath);
    if (path.isEmpty()) return -1;
    QFileInfo fi(absolutePath(path));
    return fi.exists() ? fi.size() : -1;
}

QString FileStorage::absolutePath(const QString &storagePath) const
{
    return m_basePath + "/" + storagePath;
}

void FileStorage::cleanupOrphanedFiles(int olderThanDays)
{
    QMutexLocker locker(&m_mutex);
    QDateTime cutoff = QDateTime::currentDateTime().addDays(-olderThanDays);
    QDirIterator it(m_basePath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        QFileInfo fi = it.fileInfo();
        if (fi.lastModified() < cutoff && fi.suffix() == "cryptex") {
            QFile::remove(fi.absoluteFilePath());
        }
    }
}

qint64 FileStorage::totalStorageUsed() const
{
    QMutexLocker locker(&m_mutex);
    qint64 total = 0;
    QDirIterator it(m_basePath, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        total += it.fileInfo().size();
    }
    return total;
}

QString FileStorage::sanitizePath(const QString &path) const
{
    if (path.contains("..")) return {};
    if (path.contains("\\")) return {};
    QFileInfo fi(path);
    if (fi.suffix() != "cryptex") return {};
    return path;
}