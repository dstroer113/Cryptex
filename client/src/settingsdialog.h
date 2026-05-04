/**
 * @file settingsdialog.h
 * @brief Диалог настроек Cryptex Client
 * @version 2.1
 */
#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QGroupBox>

class NetworkClient;

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(NetworkClient *client, QWidget *parent = nullptr);
    ~SettingsDialog() override = default;

    /**
     * @brief Применяет сохранённые настройки (вызывается из mainwindow при старте)
     */
    static void applyStoredSettings(NetworkClient *client);

private slots:
    void onChangePassword();
    void onExportKeys();
    void onClearLocalData();
    void onTestConnection();
    void onSaveSettings();

private:
    void setupUI();
    void applyStyles();
    void loadSettings();
    void saveSettings();

    QWidget* createSecurityTab();
    QWidget* createConnectionTab();
    QWidget* createAboutTab();

    NetworkClient *m_networkClient;
    QTabWidget *m_tabWidget;

    // Безопасность
    QLineEdit *m_editOldPassword;
    QLineEdit *m_editNewPassword;
    QLineEdit *m_editConfirmPassword;

    // Подключение
    QLineEdit *m_editServerHost;
    QSpinBox  *m_spinServerPort;
    QLineEdit *m_editCertPath;
    QPushButton *m_btnBrowseCert;
    QCheckBox *m_checkVerifyCert;
    QLabel    *m_labelConnectionStatus;
    QPushButton *m_btnTestConnection;
};

#endif // SETTINGSDIALOG_H