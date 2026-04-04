/**
 * @file LoginWindow.cpp
 * @brief Реализация окна авторизации и регистрации с подключением к PostgreSQL
 *
 * @author Студент ГБПОУ РО "РКСИ"
 * @date 2025
 * @version 1.0
 *
 * Меры безопасности:
 * - Хеширование паролей SHA-256
 * - Параметризованные SQL-запросы (защита от SQL-инъекций)
 * - Безопасное управление соединениями с БД
 * - Очистка чувствительных данных из памяти
 */

#include "LoginWindow.h"
#include "MainWindow.h"

#include <QDateTime>
#include <QTimer>
#include <QCryptographicHash>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

/**
 * @brief Конструктор окна авторизации
 * @param parent Родительский виджет
 */
LoginWindow::LoginWindow(QWidget *parent)
    : QDialog(parent)
    , m_logoLabel(nullptr)
    , m_usernameLabel(nullptr)
    , m_usernameEdit(nullptr)
    , m_passwordLabel(nullptr)
    , m_passwordEdit(nullptr)
    , m_statusLabel(nullptr)
    , m_loginButton(nullptr)
    , m_registerButton(nullptr)
    , m_mainLayout(nullptr)
    , m_buttonLayout(nullptr)
    , m_userId(-1)
{
    setWindowTitle("Cryptex - Вход в систему");
    setFixedSize(450, 550);
    setModal(true);

    setupUI();
    setupStyles();
    connectSignals();
}

/**
 * @brief Деструктор окна авторизации
 * Очищает чувствительные данные из памяти
 */
LoginWindow::~LoginWindow()
{
    // Безопасная очистка токена сессии
    m_sessionToken.clear();
    m_sessionToken.squeeze();
}

/**
 * @brief Настройка пользовательского интерфейса
 * Создает и размещает все элементы управления
 */
void LoginWindow::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(15);
    m_mainLayout->setContentsMargins(40, 30, 40, 30);

    // Логотип
    m_logoLabel = new QLabel("🔐 Cryptex", this);
    m_logoLabel->setAlignment(Qt::AlignCenter);
    QFont logoFont = m_logoLabel->font();
    logoFont.setPointSize(28);
    logoFont.setBold(true);
    m_logoLabel->setFont(logoFont);
    m_mainLayout->addWidget(m_logoLabel);

    m_mainLayout->addSpacing(20);

    // Поле ввода логина
    m_usernameLabel = new QLabel("Логин:", this);
    QFont labelFont = m_usernameLabel->font();
    labelFont.setPointSize(12);
    m_usernameLabel->setFont(labelFont);
    m_mainLayout->addWidget(m_usernameLabel);

    m_usernameEdit = new QLineEdit(this);
    m_usernameEdit->setPlaceholderText("Введите логин");
    m_usernameEdit->setMaxLength(50);
    m_usernameEdit->setFixedHeight(40);
    m_mainLayout->addWidget(m_usernameEdit);

    // Поле ввода пароля
    m_passwordLabel = new QLabel("Пароль:", this);
    m_passwordLabel->setFont(labelFont);
    m_mainLayout->addWidget(m_passwordLabel);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setPlaceholderText("Введите пароль");
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setMaxLength(128);
    m_passwordEdit->setFixedHeight(40);
    m_mainLayout->addWidget(m_passwordEdit);

    // Метка статуса
    m_statusLabel = new QLabel("", this);
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_statusLabel->setVisible(false);
    m_statusLabel->setWordWrap(true);
    m_mainLayout->addWidget(m_statusLabel);

    m_mainLayout->addSpacing(10);

    // Кнопки
    m_buttonLayout = new QHBoxLayout();
    m_buttonLayout->setSpacing(15);

    m_loginButton = new QPushButton("Войти", this);
    m_loginButton->setFixedHeight(45);
    m_loginButton->setCursor(Qt::PointingHandCursor);
    m_buttonLayout->addWidget(m_loginButton);

    m_registerButton = new QPushButton("Регистрация", this);
    m_registerButton->setFixedHeight(45);
    m_registerButton->setCursor(Qt::PointingHandCursor);
    m_buttonLayout->addWidget(m_registerButton);

    m_mainLayout->addLayout(m_buttonLayout);
    m_mainLayout->addStretch();

    setLayout(m_mainLayout);
}

/**
 * @brief Настройка стилей интерфейса (QSS)
 * Применяет тёмную тему для снижения утомляемости глаз
 */
void LoginWindow::setupStyles()
{
    setStyleSheet(
        "QDialog { background-color: #1a1a2e; } "
        "QLabel { color: #ffffff; font-size: 14px; } "
        "QLineEdit { padding: 10px; border: 2px solid #4CAF50; "
        "border-radius: 5px; background-color: #16213e; "
        "color: #ffffff; font-size: 14px; } "
        "QLineEdit:focus { border: 2px solid #00ff88; } "
        "QPushButton { background-color: #4CAF50; color: white; "
        "padding: 12px; border-radius: 5px; font-size: 14px; "
        "font-weight: bold; } "
        "QPushButton:hover { background-color: #45a049; } "
        "QPushButton:disabled { background-color: #666666; } "
        );
}

/**
 * @brief Подключение сигналов и слотов
 */
void LoginWindow::connectSignals()
{
    connect(m_loginButton, &QPushButton::clicked,
            this, &LoginWindow::onLoginButtonClicked);

    connect(m_registerButton, &QPushButton::clicked,
            this, &LoginWindow::onRegisterButtonClicked);
}

/**
 * @brief Хеширование пароля алгоритмом SHA-256
 * @param password Пароль для хеширования
 * @return Хеш пароля в шестнадцатеричном формате
 */
QString LoginWindow::hashPassword(const QString &password) const
{
    QByteArray hash = QCryptographicHash::hash(
        password.toUtf8(),
        QCryptographicHash::Sha256
    );
    return QString::fromUtf8(hash.toHex());
}

/**
 * @brief Создание подключения к базе данных
 * @param connectionName Имя соединения
 * @return Объект подключения к БД
 */
static QSqlDatabase createDatabaseConnection(const QString &connectionName)
{
    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL", connectionName);
    db.setHostName("localhost");
    db.setPort(5432);
    db.setDatabaseName("postgres");
    db.setUserName("postgres");
    db.setPassword("1234");
    return db;
}

/**
 * @brief Безопасное закрытие и удаление соединения с БД
 * @param connectionName Имя соединения
 */
static void closeDatabaseConnection(const QString &connectionName)
{
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    if (db.isOpen()) {
        db.close();
    }
    QSqlDatabase::removeDatabase(connectionName);
}

/**
 * @brief Аутентификация пользователя через PostgreSQL
 * @param username Имя пользователя
 * @param password Пароль
 * @return true при успешной аутентификации, false иначе
 */
bool LoginWindow::authenticateWithDatabase(const QString &username, const QString &password)
{
    const QString connectionName = "login_connection";
    bool success = false;

    {
        QSqlDatabase db = createDatabaseConnection(connectionName);

        if (!db.open()) {
            m_statusLabel->setText("Ошибка подключения к БД");
            m_statusLabel->setVisible(true);
            closeDatabaseConnection(connectionName);
            return false;
        }

        // Параметризованный запрос для защиты от SQL-инъекций
        QSqlQuery query(db);
        query.prepare("SELECT id, password_hash FROM users WHERE username = :username LIMIT 1");
        query.bindValue(":username", username);

        if (query.exec() && query.next()) {
            const int userId = query.value(0).toInt();
            const QString storedHash = query.value(1).toString();

            // Вычисляем хеш введённого пароля
            const QString inputHash = hashPassword(password);

            // Сравнение хешей
            if (inputHash == storedHash) {
                m_userId = userId;
                success = true;
            }
        }

        db.close();
    }

    closeDatabaseConnection(connectionName);
    return success;
}

/**
 * @brief Регистрация нового пользователя в базе данных
 * @param username Имя пользователя
 * @param password Пароль
 * @param email Электронная почта
 * @return true при успешной регистрации, false иначе
 */
bool LoginWindow::registerUser(const QString &username, const QString &password, const QString &email)
{
    const QString connectionName = "register_connection";
    bool success = false;

    {
        QSqlDatabase db = createDatabaseConnection(connectionName);

        if (!db.open()) {
            m_statusLabel->setText("Ошибка подключения к БД");
            m_statusLabel->setVisible(true);
            closeDatabaseConnection(connectionName);
            return false;
        }

        // Хешируем пароль перед сохранением
        const QString passwordHash = hashPassword(password);

        // Параметризованный запрос для защиты от SQL-инъекций
        QSqlQuery query(db);
        query.prepare("INSERT INTO users (username, password_hash, email, public_key) "
                      "VALUES (:username, :password_hash, :email, :public_key)");
        query.bindValue(":username", username);
        query.bindValue(":password_hash", passwordHash);
        query.bindValue(":email", email);
        query.bindValue(":public_key", ""); // Публичный ключ будет добавлен позже

        if (query.exec()) {
            success = true;
        } else {
            // Обработка ошибок (например, дубликат username или email)
            const QString errorText = query.lastError().text();
            if (errorText.contains("duplicate key") || errorText.contains("already exists")) {
                m_statusLabel->setText("Пользователь с таким логином или email уже существует");
            } else {
                m_statusLabel->setText("Ошибка регистрации: " + errorText);
            }
            m_statusLabel->setVisible(true);
        }

        db.close();
    }

    closeDatabaseConnection(connectionName);
    return success;
}

/**
 * @brief Обработчик нажатия кнопки входа
 */
void LoginWindow::onLoginButtonClicked()
{
    const QString username = m_usernameEdit->text().trimmed();
    const QString password = m_passwordEdit->text();

    // Валидация ввода
    if (username.isEmpty() || password.isEmpty()) {
        m_statusLabel->setText("Введите логин и пароль");
        m_statusLabel->setVisible(true);
        m_statusLabel->setStyleSheet("color: #ffaa00;");
        return;
    }

    // Блокировка кнопки на время запроса
    m_loginButton->setEnabled(false);
    m_statusLabel->setText("Проверка учётных данных...");
    m_statusLabel->setVisible(true);
    m_statusLabel->setStyleSheet("color: #4CAF50;");

    // Аутентификация через БД
    if (authenticateWithDatabase(username, password)) {
        // Успешный вход - генерация токена сессии
        m_sessionToken = "TOKEN_" + QString::number(m_userId) + "_" +
                        QString::number(QDateTime::currentMSecsSinceEpoch());

        m_statusLabel->setText("Успешный вход! Переход...");
        m_statusLabel->setStyleSheet("color: #4CAF50;");

        // Закрытие окна с кодом успеха
        QTimer::singleShot(500, this, [this]() {
            this->accept();
        });
    } else {
        // Неудачная попытка
        m_statusLabel->setText("Неверный логин или пароль");
        m_statusLabel->setStyleSheet("color: #ff4444;");
        m_loginButton->setEnabled(true);

        // Очистка поля пароля для безопасности
        m_passwordEdit->clear();
        m_passwordEdit->setFocus();
    }
}

/**
 * @brief Обработчик кнопки регистрации
 */
void LoginWindow::onRegisterButtonClicked()
{
    const QString username = m_usernameEdit->text().trimmed();
    const QString password = m_passwordEdit->text();
    const QString email = username + "@cryptex.local"; // Генерация email из логина

    // Валидация ввода
    if (username.isEmpty() || password.isEmpty()) {
        m_statusLabel->setText("Введите логин и пароль для регистрации");
        m_statusLabel->setVisible(true);
        m_statusLabel->setStyleSheet("color: #ffaa00;");
        return;
    }

    // Проверка длины пароля
    if (password.length() < 6) {
        m_statusLabel->setText("Пароль должен быть не менее 6 символов");
        m_statusLabel->setVisible(true);
        m_statusLabel->setStyleSheet("color: #ffaa00;");
        return;
    }

    // Блокировка кнопки на время запроса
    m_registerButton->setEnabled(false);
    m_statusLabel->setText("Регистрация...");
    m_statusLabel->setVisible(true);
    m_statusLabel->setStyleSheet("color: #4CAF50;");

    // Регистрация пользователя
    if (registerUser(username, password, email)) {
        m_statusLabel->setText("Регистрация успешна! Теперь войдите.");
        m_statusLabel->setStyleSheet("color: #4CAF50;");
        m_passwordEdit->clear();
    }

    m_registerButton->setEnabled(true);
}
