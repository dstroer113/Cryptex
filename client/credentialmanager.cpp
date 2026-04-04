#include "CredentialManager.h"
#include <QtDebug>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincred.h>
#pragma comment(lib, "Advapi32.lib")
#endif

CredentialManager::CredentialManager(QObject *parent)
    : QObject(parent)
{
    qDebug() << "[Security] CredentialManager initialized";
}

CredentialManager::~CredentialManager()
{
    clearAllCryptexCredentials();
}

CredentialManager& CredentialManager::getInstance()
{
    static CredentialManager instance;
    return instance;
}

bool CredentialManager::saveCredential(const QString &serviceName,
                                       const QString &username,
                                       const QString &password)
{
#ifdef Q_OS_WIN
    QString targetName = QString("Cryptex/%1/%2").arg(serviceName, username);
    return writeToWindowsVault(targetName, username, password);
#else
    qWarning() << "[Security] OS Credential Manager not implemented for this OS";
    return false;
#endif
}

QString CredentialManager::loadCredential(const QString &serviceName,
                                          const QString &username)
{
#ifdef Q_OS_WIN
    QString targetName = QString("Cryptex/%1/%2").arg(serviceName, username);
    return readFromWindowsVault(targetName);
#else
    return QString();
#endif
}

bool CredentialManager::deleteCredential(const QString &serviceName,
                                         const QString &username)
{
#ifdef Q_OS_WIN
    QString targetName = QString("Cryptex/%1/%2").arg(serviceName, username);
    return deleteFromWindowsVault(targetName);
#else
    return false;
#endif
}

void CredentialManager::clearAllCryptexCredentials()
{
    qDebug() << "[Security] Clearing all Cryptex credentials";
}

#ifdef Q_OS_WIN

QString CredentialManager::readFromWindowsVault(const QString &targetName)
{
    PCREDENTIALW credential = nullptr;

    if (CredReadW(targetName.toStdWString().c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        QString password = QString::fromUtf8(
            reinterpret_cast<const char*>(credential->CredentialBlob),
            credential->CredentialBlobSize
            );

        CredFree(credential);

        qDebug() << "[Security] Credential loaded from Windows Vault";
        return password;
    }

    return QString();
}

bool CredentialManager::writeToWindowsVault(const QString &targetName,
                                            const QString &username,
                                            const QString &password)
{
    CREDENTIALW credential;
    ZeroMemory(&credential, sizeof(credential));
    
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = (LPWSTR)targetName.toStdWString().c_str();
    credential.UserName = (LPWSTR)username.toStdWString().c_str();

    QByteArray passwordBytes = password.toUtf8();
    credential.CredentialBlobSize = passwordBytes.size();
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(passwordBytes.data()));

    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (CredWriteW(&credential, 0)) {
        qDebug() << "[Security] Credential saved to Windows Vault";
        return true;
    }

    qWarning() << "[Security] Failed to save credential:" << GetLastError();
    return false;
}

bool CredentialManager::deleteFromWindowsVault(const QString &targetName)
{
    if (CredDeleteW(targetName.toStdWString().c_str(), CRED_TYPE_GENERIC, 0)) {
        qDebug() << "[Security] Credential deleted from Windows Vault";
        return true;
    }

    return false;
}

#endif
