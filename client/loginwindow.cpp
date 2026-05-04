#include "loginwindow.h"
#include "src/networkclient.h"

#include <QMessageBox>
#include <QInputDialog>
#include <QDebug>
#include <QFont>

LoginWindow::LoginWindow(NetworkClient *client, QWidget *parent)
    : QDialog(parent)
    , m_networkClient(client)
    , m_offlineButton(nullptr)
    , m_userId(-1)
    , m_isRegistrationMode(false)
    , m_offlineMode(false)
{
    setupUI();
    setupStyles();
    switchToLogin();

    connect(m_networkClient, &NetworkClient::loginSuccess, this, &LoginWindow::onLoginSuccess);
    connect(m_networkClient, &NetworkClient::loginFailed, this, &LoginWindow::onLoginFailed);
    connect(m_networkClient, &NetworkClient::registerSuccess, this, &LoginWindow::onRegisterSuccess);
    connect(m_networkClient, &NetworkClient::registerFailed, this, &LoginWindow::onRegisterFailed);
}

LoginWindow::~LoginWindow() = default;

void LoginWindow::setupUI()
{
    setWindowTitle("Cryptex — Авторизация");
    setFixedSize(420, m_isRegistrationMode ? 500 : 420);
    setModal(true);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(40, 30, 40, 30);
    mainLayout->setSpacing(15);

    // Логотип
    m_logoLabel = new QLabel("🔐 Cryptex", this);
    m_logoLabel->setAlignment(Qt::AlignCenter);
    QFont f = m_logoLabel->font();
    f.setPointSize(22);
    f.setBold(true);
    m_logoLabel->setFont(f);
    m_logoLabel->setStyleSheet("color: #4CAF50;");
    mainLayout->addWidget(m_logoLabel);
    mainLayout->addSpacing(10);

    // Логин
    QLabel *loginLabel = new QLabel("Логин:", this);
    loginLabel->setStyleSheet("color: #fff; font-size: 13px; font-weight: bold;");
    mainLayout->addWidget(loginLabel);

    m_usernameEdit = new QLineEdit(this);
    m_usernameEdit->setPlaceholderText("Имя пользователя");
    m_usernameEdit->setFixedHeight(44);
    m_usernameEdit->setStyleSheet("padding: 10px 14px; font-size: 15px;");
    mainLayout->addWidget(m_usernameEdit);

    // Пароль
    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setPlaceholderText("Пароль");
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setFixedHeight(44);
    m_passwordEdit->setStyleSheet("padding: 10px 14px; font-size: 15px;");
    mainLayout->addWidget(m_passwordEdit);

    // Email (только для регистрации)
    m_emailEdit = new QLineEdit(this);
    m_emailEdit->setPlaceholderText("Email (только для регистрации)");
    m_emailEdit->setFixedHeight(44);
    m_emailEdit->setStyleSheet("padding: 10px 14px; font-size: 15px;");
    m_emailEdit->hide();
    mainLayout->addWidget(m_emailEdit);

    // Статус
    m_statusLabel = new QLabel("", this);
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
    mainLayout->addWidget(m_statusLabel);

    // Кнопки
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(10);

    m_loginButton = new QPushButton("Войти", this);
    m_loginButton->setFixedHeight(42);
    m_loginButton->setCursor(Qt::PointingHandCursor);
    btnLayout->addWidget(m_loginButton);

    m_registerButton = new QPushButton("Регистрация", this);
    m_registerButton->setFixedHeight(42);
    m_registerButton->setCursor(Qt::PointingHandCursor);
    btnLayout->addWidget(m_registerButton);

    mainLayout->addLayout(btnLayout);

    m_forgotPasswordButton = new QPushButton("Забыли пароль?", this);
    m_forgotPasswordButton->setFixedHeight(36);
    m_forgotPasswordButton->setCursor(Qt::PointingHandCursor);
    mainLayout->addWidget(m_forgotPasswordButton);

    // Офлайн-режим
    m_offlineButton = new QPushButton("🔌 Офлайн-режим", this);
    m_offlineButton->setFixedHeight(36);
    m_offlineButton->setCursor(Qt::PointingHandCursor);
    m_offlineButton->setToolTip("Шифрование и журнал без подключения к серверу");
    mainLayout->addWidget(m_offlineButton);

    m_switchModeButton = new QPushButton("← Назад ко входу", this);
    m_switchModeButton->setFixedHeight(36);
    m_switchModeButton->setCursor(Qt::PointingHandCursor);
    m_switchModeButton->hide();
    mainLayout->addWidget(m_switchModeButton);

    // Сигналы
    connect(m_loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginButtonClicked);
    connect(m_registerButton, &QPushButton::clicked, this, &LoginWindow::onRegisterButtonClicked);
    connect(m_forgotPasswordButton, &QPushButton::clicked, this, &LoginWindow::onForgotPasswordClicked);
    connect(m_offlineButton, &QPushButton::clicked, this, &LoginWindow::onOfflineModeClicked);
    connect(m_switchModeButton, &QPushButton::clicked, this, &LoginWindow::switchToLogin);
}

void LoginWindow::setupStyles()
{
    setStyleSheet(
        "QDialog { background-color: #1a1a2e; } "
        "QLabel { color: #fff; font-size: 13px; } "
        "QLineEdit { background: #0f3460; color: #fff; border: 1px solid #4CAF50; "
        "border-radius: 4px; padding: 8px; font-size: 14px; } "
        "QLineEdit:focus { border-color: #45a049; } "
        "QLineEdit::placeholder { color: #888; } "
        "QPushButton { border: none; border-radius: 4px; font-weight: bold; font-size: 14px; } "
        "QPushButton:hover { opacity: 0.9; } "
        "#m_loginButton, #m_registerButton { background: #4CAF50; color: #fff; padding: 10px; } "
        "#m_loginButton:hover, #m_registerButton:hover { background: #45a049; } "
        "#m_forgotPasswordButton, #m_switchModeButton { background: transparent; color: #888; "
        "border: 1px solid #555; padding: 8px; } "
        "#m_forgotPasswordButton:hover, #m_switchModeButton:hover { color: #4CAF50; border-color: #4CAF50; } "
        "#m_offlineButton { background: transparent; color: #4CAF50; "
        "border: 1px solid #4CAF50; padding: 8px; } "
        "#m_offlineButton:hover { background: #4CAF50; color: #fff; } "
    );

    m_loginButton->setObjectName("m_loginButton");
    m_registerButton->setObjectName("m_registerButton");
    m_forgotPasswordButton->setObjectName("m_forgotPasswordButton");
    m_switchModeButton->setObjectName("m_switchModeButton");
    m_offlineButton->setObjectName("m_offlineButton");
}

void LoginWindow::switchToRegistration()
{
    m_isRegistrationMode = true;
    setFixedHeight(540);
    m_emailEdit->show();
    m_loginButton->hide();
    m_forgotPasswordButton->hide();
    m_offlineButton->hide();
    m_registerButton->setText("Создать аккаунт");
    m_switchModeButton->show();
    m_statusLabel->clear();
    setWindowTitle("Cryptex — Регистрация");
}

void LoginWindow::switchToLogin()
{
    m_isRegistrationMode = false;
    setFixedHeight(420);
    m_emailEdit->hide();
    m_loginButton->show();
    m_forgotPasswordButton->show();
    m_offlineButton->show();
    m_registerButton->setText("Регистрация");
    m_switchModeButton->hide();
    m_statusLabel->clear();
    setWindowTitle("Cryptex — Авторизация");
}

void LoginWindow::onLoginButtonClicked()
{
    QString username = m_usernameEdit->text().trimmed();
    QString password = m_passwordEdit->text();

    if (username.isEmpty() || password.isEmpty()) {
        m_statusLabel->setText("Заполните все поля");
        return;
    }

    m_statusLabel->setStyleSheet("color: #4CAF50; font-size: 13px;");
    m_statusLabel->setText("Подключение к серверу...");

    // Подключаемся к серверу (если ещё не подключены)
    if (!m_networkClient->isConnected()) {
        m_networkClient->connectToServer("127.0.0.1", 8443);
        // Ждём подключения, потом логин
        QMetaObject::Connection *conn = new QMetaObject::Connection();
        *conn = connect(m_networkClient, &NetworkClient::connected, this, [this, username, password, conn]() {
            disconnect(*conn);
            delete conn;
            m_statusLabel->setText("Авторизация...");
            m_networkClient->login(username, password);
        });
    } else {
        m_networkClient->login(username, password);
    }
}

void LoginWindow::onRegisterButtonClicked()
{
    if (!m_isRegistrationMode) {
        switchToRegistration();
        return;
    }

    QString username = m_usernameEdit->text().trimmed();
    QString password = m_passwordEdit->text();
    QString email = m_emailEdit->text().trimmed().toLower();

    if (username.isEmpty() || password.isEmpty() || email.isEmpty()) {
        m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
        m_statusLabel->setText("Заполните все поля (логин, пароль, email)");
        return;
    }

    if (username.length() < 3) {
        m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
        m_statusLabel->setText("Имя пользователя: минимум 3 символа");
        return;
    }
    if (password.length() < 8) {
        m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
        m_statusLabel->setText("Пароль: минимум 8 символов");
        return;
    }
    if (!email.contains('@') || !email.contains('.')) {
        m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
        m_statusLabel->setText("Введите корректный email");
        return;
    }

    m_statusLabel->setStyleSheet("color: #4CAF50; font-size: 13px;");
    m_statusLabel->setText("Подключение к серверу...");

    if (!m_networkClient->isConnected()) {
        QMetaObject::Connection *conn = new QMetaObject::Connection();
        *conn = connect(m_networkClient, &NetworkClient::connected, this, [this, username, password, email, conn]() {
            disconnect(*conn);
            delete conn;
            m_statusLabel->setText("Регистрация...");
            m_networkClient->registerUser(username, password, email, "");
        });
        m_networkClient->connectToServer("127.0.0.1", 8443);
    } else {
        m_networkClient->registerUser(username, password, email, "");
    }
}

void LoginWindow::onForgotPasswordClicked()
{
    QInputDialog dialog(this);
    dialog.setWindowTitle("Сброс пароля");
    dialog.setLabelText("Введите email, указанный при регистрации:");
    dialog.setInputMode(QInputDialog::TextInput);
    dialog.setStyleSheet(
        "QInputDialog { background-color: #1a1a2e; } "
        "QLabel { color: #fff; font-size: 14px; } "
        "QLineEdit { background: #0f3460; color: #fff; border: 1px solid #4CAF50; "
        "border-radius: 4px; padding: 10px; font-size: 14px; } "
        "QPushButton { background-color: #4CAF50; color: #fff; border: none; "
        "border-radius: 6px; padding: 10px 24px; font-weight: bold; font-size: 14px; } "
        "QPushButton:hover { background-color: #45a049; } "
        "QPushButton:pressed { background-color: #3d8b40; } "
        "QPushButton:last-child { background-color: #555; } "
        "QPushButton:last-child:hover { background-color: #666; } "
    );
    if (dialog.exec() != QDialog::Accepted) return;
    QString email = dialog.textValue().trimmed();
    if (email.isEmpty()) return;

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Сброс пароля");
    msgBox.setText("Инструкции по сбросу пароля отправлены на указанный email.\n\n"
                   "Если email не зарегистрирован, вы не получите письмо.");
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStyleSheet(
        "QMessageBox { background-color: #1a1a2e; } "
        "QLabel { color: #fff; font-size: 14px; } "
        "QPushButton { background-color: #4CAF50; color: #fff; border: none; "
        "border-radius: 6px; padding: 10px 24px; font-weight: bold; font-size: 14px; } "
        "QPushButton:hover { background-color: #45a049; } "
    );
    msgBox.exec();
}

void LoginWindow::onOfflineModeClicked()
{
    m_offlineMode = true;
    m_userName = "Офлайн";
    m_statusLabel->setStyleSheet("color: #4CAF50; font-size: 14px; font-weight: bold;");
    m_statusLabel->setText("🔌 Офлайн-режим (шифрование и журнал)");
    accept();
}

void LoginWindow::onLoginSuccess(int userId, const QString &username, const QString &token)
{
    m_userId = userId;
    m_userName = username;
    m_sessionToken = token;
    m_offlineMode = false;
    m_statusLabel->setStyleSheet("color: #4CAF50; font-size: 14px; font-weight: bold;");
    m_statusLabel->setText("✅ Авторизация успешна");
    accept();
}

void LoginWindow::onLoginFailed(const QString &reason)
{
    m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
    m_statusLabel->setText("❌ " + reason);
}

void LoginWindow::onRegisterSuccess()
{
    QMessageBox::information(this, "Регистрация",
                             "Аккаунт успешно создан!\n\n"
                             "Теперь вы можете войти.");
    switchToLogin();
}

void LoginWindow::onRegisterFailed(const QString &reason)
{
    m_statusLabel->setStyleSheet("color: #ff4444; font-size: 13px;");
    m_statusLabel->setText("❌ " + reason);
}