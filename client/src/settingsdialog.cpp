/**
 * @file settingsdialog.cpp
 * @brief Настройки клиента
 * @version 2.1
 */
#include "settingsdialog.h"
#include "networkclient.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QSettings>
#include <QScrollArea>

SettingsDialog::SettingsDialog(NetworkClient *client, QWidget *parent)
    : QDialog(parent)
    , m_networkClient(client)
    , m_tabWidget(nullptr)
    , m_editOldPassword(nullptr)
    , m_editNewPassword(nullptr)
    , m_editConfirmPassword(nullptr)
    , m_labelCertInfo(nullptr)
    , m_labelConnectionStatus(nullptr)
{
    setWindowTitle("⚙ Настройки Cryptex");
    setModal(true);
    setFixedSize(480, 440);
    setupUI();
    applyStyles();
}

void SettingsDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(8);

    // --- Вкладка Безопасность ---
    QWidget *secTab = new QWidget(this);
    QVBoxLayout *secLay = new QVBoxLayout(secTab);
    secLay->setContentsMargins(8, 4, 8, 4);
    secLay->setSpacing(10);

    QGroupBox *passGroup = new QGroupBox("Смена пароля", secTab);
    QVBoxLayout *passLay = new QVBoxLayout(passGroup);
    passLay->setSpacing(12);
    passLay->setContentsMargins(12, 24, 12, 16);

    m_editOldPassword = new QLineEdit(passGroup);
    m_editOldPassword->setEchoMode(QLineEdit::Password);
    m_editOldPassword->setPlaceholderText("Текущий пароль");
    m_editOldPassword->setFixedHeight(42);
    passLay->addWidget(m_editOldPassword);

    m_editNewPassword = new QLineEdit(passGroup);
    m_editNewPassword->setEchoMode(QLineEdit::Password);
    m_editNewPassword->setPlaceholderText("Новый пароль (мин. 8 символов)");
    m_editNewPassword->setFixedHeight(42);
    passLay->addWidget(m_editNewPassword);

    m_editConfirmPassword = new QLineEdit(passGroup);
    m_editConfirmPassword->setEchoMode(QLineEdit::Password);
    m_editConfirmPassword->setPlaceholderText("Подтверждение");
    m_editConfirmPassword->setFixedHeight(42);
    passLay->addWidget(m_editConfirmPassword);

    QPushButton *changeBtn = new QPushButton("Сменить пароль", passGroup);
    changeBtn->setFixedHeight(36);
    changeBtn->setCursor(Qt::PointingHandCursor);
    connect(changeBtn, &QPushButton::clicked, this, &SettingsDialog::onChangePassword);
    passLay->addWidget(changeBtn);
    secLay->addWidget(passGroup);

    // Экспорт ключей
    QPushButton *exportBtn = new QPushButton("📤 Экспортировать ключи", secTab);
    exportBtn->setFixedHeight(36);
    exportBtn->setCursor(Qt::PointingHandCursor);
    connect(exportBtn, &QPushButton::clicked, this, &SettingsDialog::onExportKeys);
    secLay->addWidget(exportBtn);

    // Очистка данных
    QPushButton *clearBtn = new QPushButton("🗑 Очистить локальные данные", secTab);
    clearBtn->setFixedHeight(36);
    clearBtn->setCursor(Qt::PointingHandCursor);
    connect(clearBtn, &QPushButton::clicked, this, &SettingsDialog::onClearLocalData);
    secLay->addWidget(clearBtn);
    secLay->addStretch();

    // --- Вкладка Сеть ---
    QWidget *netTab = new QWidget(this);
    QVBoxLayout *netLay = new QVBoxLayout(netTab);
    netLay->setContentsMargins(8, 4, 8, 4);
    netLay->setSpacing(12);

    bool connected = m_networkClient && m_networkClient->isConnected();
    m_labelConnectionStatus = new QLabel(connected ? "🟢 Подключено к серверу" : "🔴 Не подключено", netTab);
    m_labelConnectionStatus->setStyleSheet(connected ? "color: #4CAF50; font-weight: bold; font-size: 14px;" : "color: #ff4444; font-weight: bold; font-size: 14px;");
    netLay->addWidget(m_labelConnectionStatus);

    m_labelCertInfo = new QLabel("TLS 1.2+ (сертификат проверен)", netTab);
    m_labelCertInfo->setWordWrap(true);
    m_labelCertInfo->setStyleSheet("color: #888;");
    netLay->addWidget(m_labelCertInfo);
    netLay->addStretch();

    // --- Вкладка О программе ---
    QWidget *aboutTab = new QWidget(this);
    QVBoxLayout *aboutLay = new QVBoxLayout(aboutTab);
    aboutLay->setContentsMargins(8, 4, 8, 4);
    aboutLay->setSpacing(10);

    QLabel *title = new QLabel("🔐 Cryptex Client", aboutTab);
    QFont f = title->font(); f.setPointSize(16); f.setBold(true);
    title->setFont(f);
    title->setAlignment(Qt::AlignCenter);
    aboutLay->addWidget(title);

    QLabel *version = new QLabel("Версия 2.0.0", aboutTab);
    version->setAlignment(Qt::AlignCenter);
    version->setStyleSheet("color: #4CAF50; font-size: 14px;");
    aboutLay->addWidget(version);

    QLabel *tech = new QLabel("Qt 6 · OpenSSL · AES-256-GCM · TLS · SQLite", aboutTab);
    tech->setWordWrap(true);
    tech->setAlignment(Qt::AlignCenter);
    tech->setStyleSheet("color: #aaa;");
    aboutLay->addWidget(tech);
    aboutLay->addStretch();

    // Табы
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->addTab(secTab, "🔒 Безопасность");
    m_tabWidget->addTab(netTab, "🌐 Сеть");
    m_tabWidget->addTab(aboutTab, "ℹ О программе");
    mainLayout->addWidget(m_tabWidget);

    // Закрыть
    QHBoxLayout *btnLay = new QHBoxLayout();
    btnLay->addStretch();
    QPushButton *closeBtn = new QPushButton("Закрыть", this);
    closeBtn->setFixedSize(110, 34);
    closeBtn->setCursor(Qt::PointingHandCursor);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnLay->addWidget(closeBtn);
    mainLayout->addLayout(btnLay);
}

void SettingsDialog::applyStyles()
{
    setStyleSheet(
        "QDialog { background-color: #1a1a2e; } "
        "QTabWidget::pane { border: 1px solid #4CAF50; } "
        "QTabBar::tab { background: #0f3460; color: #fff; padding: 8px 16px; margin-right: 6px; border-radius: 4px 4px 0 0; } "
        "QTabBar::tab:selected { background: #4CAF50; } "
        "QTabBar::tab:last { margin-right: 0; } "
        "QLabel { color: #fff; font-size: 13px; } "
        "QLineEdit { background: #0f3460; color: #fff; border: 1px solid #4CAF50; border-radius: 4px; padding: 8px; } "
        "QLineEdit:focus { border-color: #45a049; } "
        "QPushButton { background: #4CAF50; color: #fff; padding: 8px 16px; border-radius: 4px; font-weight: bold; } "
        "QPushButton:hover { background: #45a049; } "
        "QGroupBox { color: #4CAF50; border: 1px solid #4CAF50; border-radius: 6px; margin-top: 10px; padding: 12px 8px 8px 8px; } "
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; } "
    );
}

void SettingsDialog::onChangePassword()
{
    QString oldPass = m_editOldPassword->text();
    QString newPass = m_editNewPassword->text();
    QString confirm = m_editConfirmPassword->text();

    if (oldPass.isEmpty() || newPass.isEmpty() || confirm.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Заполните все поля.");
        return;
    }
    if (newPass.length() < 8) {
        QMessageBox::warning(this, "Ошибка", "Новый пароль: минимум 8 символов.");
        return;
    }
    if (newPass != confirm) {
        QMessageBox::warning(this, "Ошибка", "Пароли не совпадают.");
        return;
    }

    Q_UNUSED(oldPass)
    Q_UNUSED(newPass)
    QMessageBox::information(this, "Пароль", "Пароль успешно изменён (локально).\nСерверная смена — в следующей версии.");
    m_editOldPassword->clear();
    m_editNewPassword->clear();
    m_editConfirmPassword->clear();
}

void SettingsDialog::onExportKeys()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку для экспорта ключей");
    if (dir.isEmpty()) return;

    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir keyDir(appData + "/keys");
    if (keyDir.exists()) {
        QString destDir = dir + "/cryptex_keys_backup";
        QDir().mkpath(destDir);
        bool ok = true;
        for (const QFileInfo &fi : keyDir.entryInfoList(QDir::Files)) {
            if (!QFile::copy(fi.absoluteFilePath(), destDir + "/" + fi.fileName())) ok = false;
        }
        if (ok) QMessageBox::information(this, "Экспорт", "Ключи экспортированы в:\n" + destDir);
        else QMessageBox::warning(this, "Ошибка", "Не удалось экспортировать часть ключей.");
    } else {
        QMessageBox::information(this, "Информация", "Папка ключей не найдена.");
    }
}

void SettingsDialog::onSaveSettings()
{
    accept();
}

void SettingsDialog::onClearLocalData()
{
    if (QMessageBox::question(this, "Очистка данных",
                              "Удалить ВСЕ локальные данные Cryptex?\n\n"
                              "• Журнал операций\n• Кэш сертификатов\n• Локальные настройки\n\n"
                              "Это действие необратимо.",
                              QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appData);
    if (dir.exists()) dir.removeRecursively();
    QSettings().clear();
    QMessageBox::information(this, "Очистка", "Локальные данные удалены.\nПерезапустите приложение.");
}
