#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>

class NetworkClient;

class LoginWindow : public QDialog
{
    Q_OBJECT

public:
    explicit LoginWindow(NetworkClient *client, QWidget *parent = nullptr);
    ~LoginWindow() override;

    QString getSessionToken() const { return m_sessionToken; }
    int getUserId() const { return m_userId; }
    QString getUserName() const { return m_userName; }
    bool isOfflineMode() const { return m_offlineMode; }

private slots:
    void onLoginButtonClicked();
    void onRegisterButtonClicked();
    void onForgotPasswordClicked();
    void onOfflineModeClicked();

    void onLoginSuccess(int userId, const QString &username, const QString &token);
    void onLoginFailed(const QString &reason);
    void onRegisterSuccess();
    void onRegisterFailed(const QString &reason);

private:
    void setupUI();
    void setupStyles();
    void switchToRegistration();
    void switchToLogin();

    NetworkClient *m_networkClient;

    QLabel *m_logoLabel;
    QLineEdit *m_usernameEdit;
    QLineEdit *m_passwordEdit;
    QLineEdit *m_emailEdit;
    QLabel *m_statusLabel;
    QPushButton *m_loginButton;
    QPushButton *m_registerButton;
    QPushButton *m_forgotPasswordButton;
    QPushButton *m_switchModeButton;
    QPushButton *m_offlineButton;

    QString m_sessionToken;
    int m_userId;
    QString m_userName;
    bool m_isRegistrationMode;
    bool m_offlineMode;
};

#endif // LOGINWINDOW_H