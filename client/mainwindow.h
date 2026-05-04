/**
 * @file MainWindow.h
 * @brief Главное окно приложения Cryptex
 * @version 2.0
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileInfo>

#include "CryptoEngine.h"
#include "SecurityManager.h"

class NetworkClient;
class ContactsTab;
class TransfersTab;
class SettingsDialog;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(NetworkClient *client, bool online, QWidget *parent = nullptr);
    ~MainWindow() override;

    void setSessionToken(const QString &token);
    void setUserId(int id);
    void setUserName(const QString &name);
    NetworkClient* networkClient() const { return m_networkClient; }
    bool isOnline() const { return m_online; }

public slots:
    void switchToOnlineMode(const QString &username, int userId, const QString &token);

private slots:
    // Шифрование
    void onEncryptFile();
    void onDecryptFile();
    void onSelectInputFile();
    void onSelectInputDir();
    void onSelectOutputFile();

    // Сеть
    void onServerConnected();
    void onServerDisconnected();
    void onConnectClicked();

    // Журнал
    void onRefreshLogs();
    void onClearLogs();

    // Навигация
    void onOpenSettings();
    void onLogout();

private:
    // UI построение
    void setupUI();
    QWidget* createDashboardTab();
    QWidget* createCryptoTab();
    QWidget* createLogTab();
    void applyDarkTheme();
    void updateSessionInfo();
    void updateNetworkTabs();

    // Логирование
    void addLogEntry(const QString &event, const QString &details, bool success);
    void saveLogsToFile();
    void loadLogsFromFile();
    void clearLogFile();
    QString getLogFilePath() const;

    // Вспомогательные
    void setProcessingState(bool processing);
    void clearCryptoFields();
    void showSuccessNotification(const QString &title, const QString &filePath);
    bool isCryptexEncryptedFile(const QString &path) const;
    void processFileList(const QStringList &files, bool encrypt);

    // UI компоненты — шапка
    QLabel *m_labelUser;
    QLabel *m_labelUserId;
    QPushButton *m_btnLogout;
    QPushButton *m_btnSettings;

    // UI — вкладка шифрования
    QTabWidget *m_tabWidget;
    QLineEdit *m_editInput;
    QLineEdit *m_editOutput;
    QLineEdit *m_editPassword;
    QPushButton *m_btnInput;
    QPushButton *m_btnInputDir;
    QPushButton *m_btnOutput;
    QPushButton *m_btnEncrypt;
    QPushButton *m_btnDecrypt;
    QCheckBox *m_chkDeleteSource;
    QLabel *m_labelMode;

    // UI — вкладка журнала
    QTableWidget *m_tableLogs;
    QPushButton *m_btnRefresh;
    QPushButton *m_btnClearLogs;

    // Сетевые компоненты
    NetworkClient *m_networkClient;
    ContactsTab *m_contactsTab;
    TransfersTab *m_transfersTab;
    bool m_online;

    // Данные
    QString m_sessionToken;
    int m_userId;
    QString m_userName;
    bool m_isProcessing;
    QStringList m_selectedFiles;      // для множественного выбора

    // Движки
    CryptoEngine &m_crypto;
    SecurityManager &m_security;
};

#endif // MAINWINDOW_H