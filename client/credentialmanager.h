#ifndef CREDENTIALMANAGER_H
#define CREDENTIALMANAGER_H

#include <QObject>
#include <QString>
#include <QByteArray>
// Windows headers removed from header to avoid moc crashes

class CredentialManager : public QObject
{
    Q_OBJECT

public:
    static CredentialManager& getInstance();

    bool saveCredential(const QString &serviceName, const QString &username,
                        const QString &password);
    QString loadCredential(const QString &serviceName, const QString &username);
    bool deleteCredential(const QString &serviceName, const QString &username);
    void clearAllCryptexCredentials();

private:
    explicit CredentialManager(QObject *parent = nullptr);
    ~CredentialManager();
    CredentialManager(const CredentialManager&) = delete;
    CredentialManager& operator=(const CredentialManager&) = delete;

#ifdef Q_OS_WIN
    QString readFromWindowsVault(const QString &targetName);
    bool writeToWindowsVault(const QString &targetName, const QString &username,
                             const QString &password);
    bool deleteFromWindowsVault(const QString &targetName);
#endif
};

#endif // CREDENTIALMANAGER_H