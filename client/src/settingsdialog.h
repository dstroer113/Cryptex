/**
 * @file settingsdialog.h
 * @brief Диалог настроек Cryptex Client
 * @version 2.0
 */
#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QFormLayout>

class NetworkClient;

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(NetworkClient *client, QWidget *parent = nullptr);
    ~SettingsDialog() override = default;

private slots:
    void onChangePassword();
    void onExportKeys();
    void onClearLocalData();
    void onSaveSettings();

private:
    void setupUI();
    void applyStyles();
    QWidget* createSecurityTab();
    QWidget* createNetworkTab();
    QWidget* createAboutTab();

    NetworkClient *m_networkClient;
    QTabWidget *m_tabWidget;

    // Безопасность
    QLineEdit *m_editOldPassword;
    QLineEdit *m_editNewPassword;
    QLineEdit *m_editConfirmPassword;

    // Сеть
    QLabel *m_labelCertInfo;
    QLabel *m_labelConnectionStatus;
};

#endif // SETTINGSDIALOG_H