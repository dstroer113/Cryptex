/**
 * @file main.cpp
 * @brief Точка входа в приложение Cryptex Client
 *
 * @author Студент ГБПОУ РО "РКСИ"
 * @date 2025
 * @version 1.0
 */

#include <QApplication>
#include <QMessageBox>

#include "LoginWindow.h"
#include "MainWindow.h"

/**
 * @brief Точка входа в приложение
 * @param argc Количество аргументов командной строки
 * @param argv Массив аргументов командной строки
 * @return Код завершения приложения
 */
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Cryptex");
    app.setOrganizationName("Cryptex");

    // Создаем и показываем окно авторизации
    // Проверка драйвера будет выполнена при подключении к БД
    LoginWindow login;
    login.setWindowTitle("Cryptex - Вход");

    if (login.exec() == QDialog::Accepted) {
        MainWindow mainWin;
        mainWin.setSessionToken(login.getSessionToken());
        mainWin.setUserId(login.getUserId());
        mainWin.show();

        return app.exec();
    }

    return 0;
}
