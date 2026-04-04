/**
 * @file LoginWindow.h
 * @brief Заголовочный файл окна авторизации и регистрации
 *
 * @author Студент ГБПОУ РО "РКСИ"
 * @date 2025
 * @version 1.0
 */

#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QCryptographicHash>

/**
 * @class LoginWindow
 * @brief Окно авторизации и регистрации пользователей
 *
 * Обеспечивает безопасную аутентификацию через PostgreSQL
 * с хешированием паролей алгоритмом SHA-256.
 */
class LoginWindow : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Конструктор окна авторизации
     * @param parent Родительский виджет
     */
    explicit LoginWindow(QWidget *parent = nullptr);

    /**
     * @brief Деструктор окна авторизации
     * Очищает чувствительные данные из памяти
     */
    ~LoginWindow() override;

    /**
     * @brief Получить токен сессии
     * @return Токен сессии
     */
    [[nodiscard]] QString getSessionToken() const { return m_sessionToken; }

    /**
     * @brief Получить идентификатор пользователя
     * @return Идентификатор пользователя
     */
    [[nodiscard]] int getUserId() const { return m_userId; }

private slots:
    /// Обработчик нажатия кнопки входа
    void onLoginButtonClicked();

    /// Обработчик нажатия кнопки регистрации
    void onRegisterButtonClicked();

private:
    // UI элементы
    QLabel *m_logoLabel;
    QLabel *m_usernameLabel;
    QLineEdit *m_usernameEdit;
    QLabel *m_passwordLabel;
    QLineEdit *m_passwordEdit;
    QLabel *m_statusLabel;
    QPushButton *m_loginButton;
    QPushButton *m_registerButton;
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_buttonLayout;

    // Данные сессии
    QString m_sessionToken;
    int m_userId;

    // Методы инициализации
    void setupUI();
    void setupStyles();
    void connectSignals();

    // Методы безопасности
    [[nodiscard]] QString hashPassword(const QString &password) const;
    [[nodiscard]] bool authenticateWithDatabase(const QString &username, const QString &password);
    [[nodiscard]] bool registerUser(const QString &username, const QString &password, const QString &email);
};

#endif // LOGINWINDOW_H
