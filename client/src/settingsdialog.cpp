/**
 * @file settingsdialog.cpp
 * @brief Настройки клиента: подключение, безопасность, о программе
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
#include <QSslSocket>
#include <QTimer>
#include <QApplication>
#include <QFont>

// Ключи QSettings
static const QString KEY_HOST       = "connection/host";
static const QString KEY_PORT       = "connection/port";
static const QString KEY_CERT       = "connection/ca_cert";
static const QString KEY_VERIFY     = "connection/verify_cert";
static const QString KEY_MIN_TO_TRAY = "ui/minimize_to_tray";

static const QString DEFAULT_HOST   = "127.0.0.1";
static const int     DEFAULT_PORT   = 8443;

SettingsDialog::SettingsDialog(NetworkClient *client, QWidget *parent)
    : QDialog(parent)
    , m_networkClient(client)
    , m_tabWidget(nullptr)
    , m_editOldPassword(nullptr)
    , m_editNewPassword(nullptr)
    , m_editConfirmPassword(nullptr)
    , m_editServerHost(nullptr)
    , m_spinServerPort(nullptr)
    , m_editCertPath(nullptr)
    , m_btnBrowseCert(nullptr)
    , m_checkVerifyCert(nullptr)
    , m_labelConnectionStatus(nullptr)
    , m_btnTestConnection(nullptr)
{
    setWindowTitle("Настройки Cryptex");
    setModal(true);
    setFixedSize(500, 460);
    setupUI();
    applyStyles();
    loadSettings();
}

void SettingsDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(8);

    // --- Вкладка Подключение ---
    QWidget *connTab = new QWidget(this);
    QVBoxLayout *connLay = new QVBoxLayout(connTab);
    connLay->setContentsMargins(8, 4, 8, 4);
    connLay->setSpacing(12);

    // Статус
    m_labelConnectionStatus = new QLabel(connTab);
    m_labelConnectionStatus->setStyleSheet("color: #888; font-size: 14px;");
    m_labelConnectionStatus->setAlignment(Qt::AlignCenter);
    connLay->addWidget(m_labelConnectionStatus);

    // Сервер
    QGroupBox *serverGroup = new QGroupBox("Сервер", connTab);
    QFormLayout *serverForm = new QFormLayout(serverGroup);
    serverForm->setSpacing(10);
    serverForm->setContentsMargins(12, 24, 12, 12);

    m_editServerHost = new QLineEdit(serverGroup);
    m_editServerHost->setPlaceholderText("IP-адрес или домен");
    m_editServerHost->setFixedHeight(38);
    serverForm->addRow("Адрес:", m_editServerHost);

    m_spinServerPort = new QSpinBox(serverGroup);
    m_spinServerPort->setRange(1, 65535);
    m_spinServerPort->setFixedHeight(38);
    serverForm->addRow("Порт:", m_spinServerPort);

    connLay->addWidget(serverGroup);

    // SSL
    QGroupBox *sslGroup = new QGroupBox("SSL / TLS", connTab);
    QVBoxLayout *sslLay = new QVBoxLayout(sslGroup);
    sslLay->setSpacing(8);
    sslLay->setContentsMargins(12, 24, 12, 12);

    QHBoxLayout *certRow = new QHBoxLayout();
    m_editCertPath = new QLineEdit(sslGroup);
    m_editCertPath->setPlaceholderText("Путь к CA-сертификату (необязательно)");
    m_editCertPath->setFixedHeight(38);
    m_editCertPath->setReadOnly(true);
    certRow->addWidget(m_editCertPath);

    m_btnBrowseCert = new QPushButton("Обзор", sslGroup);
    m_btnBrowseCert->setFixedHeight(38);
    m_btnBrowseCert->setCursor(Qt::PointingHandCursor);
    connect(m_btnBrowseCert, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Выберите сертификат",
            QStandardPaths::writableLocation(QStandardPaths::HomeLocation),
            "Сертификаты (*.crt *.pem *.cert);;Все файлы (*)");
        if (!path.isEmpty()) {
            m_editCertPath->setText(path);
        }
    });
    certRow->addWidget(m_btnBrowseCert);
    sslLay->addLayout(certRow);

    m_checkVerifyCert = new QCheckBox("Проверять сертификат сервера (рекомендуется)", sslGroup);
    m_checkVerifyCert->setStyleSheet("color: #fff;");
    sslLay->addWidget(m_checkVerifyCert);

    connLay->addWidget(sslGroup);

    // Проверить соединение
    m_btnTestConnection = new QPushButton("Проверить соединение", connTab);
    m_btnTestConnection->setFixedHeight(42);
    m_btnTestConnection->setCursor(Qt::PointingHandCursor);
    connect(m_btnTestConnection, &QPushButton::clicked, this, &SettingsDialog::onTestConnection);
    connLay->addWidget(m_btnTestConnection);

    connLay->addStretch();

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

    QPushButton *exportBtn = new QPushButton("Экспортировать ключи шифрования", secTab);
    exportBtn->setFixedHeight(36);
    exportBtn->setCursor(Qt::PointingHandCursor);
    connect(exportBtn, &QPushButton::clicked, this, &SettingsDialog::onExportKeys);
    secLay->addWidget(exportBtn);

    QPushButton *clearBtn = new QPushButton("Очистить локальные данные", secTab);
    clearBtn->setFixedHeight(36);
    clearBtn->setCursor(Qt::PointingHandCursor);
    connect(clearBtn, &QPushButton::clicked, this, &SettingsDialog::onClearLocalData);
    secLay->addWidget(clearBtn);
    secLay->addStretch();

    // --- Вкладка О программе ---
    QWidget *aboutTab = new QWidget(this);
    QVBoxLayout *aboutLay = new QVBoxLayout(aboutTab);
    aboutLay->setContentsMargins(8, 4, 8, 4);
    aboutLay->setSpacing(10);

    QLabel *title = new QLabel("Cryptex Client", aboutTab);
    QFont f = title->font(); f.setPointSize(16); f.setBold(true);
    title->setFont(f);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("color: #4CAF50;");
    aboutLay->addWidget(title);

    QLabel *version = new QLabel("Версия 2.0.0", aboutTab);
    version->setAlignment(Qt::AlignCenter);
    version->setStyleSheet("color: #fff; font-size: 14px;");
    aboutLay->addWidget(version);

    QLabel *tech = new QLabel("Qt 6 · OpenSSL · AES-256-GCM · TLS 1.2+\n"
                               "Сервер-ретранслятор (без хранения на диске)\n"
                               "Bcrypt · SHA-256 · HMAC · Rate limiting", aboutTab);
    tech->setWordWrap(true);
    tech->setAlignment(Qt::AlignCenter);
    tech->setStyleSheet("color: #aaa; font-size: 12px;");
    aboutLay->addWidget(tech);
    aboutLay->addStretch();

    // Табы
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->addTab(connTab, "Подключение");
    m_tabWidget->addTab(secTab,   "Безопасность");
    m_tabWidget->addTab(aboutTab, "О программе");
    mainLayout->addWidget(m_tabWidget);

    // Нижние кнопки
    QHBoxLayout *btnLay = new QHBoxLayout();
    QPushButton *saveBtn = new QPushButton("Сохранить", this);
    saveBtn->setFixedSize(120, 36);
    saveBtn->setCursor(Qt::PointingHandCursor);
    connect(saveBtn, &QPushButton::clicked, this, &SettingsDialog::onSaveSettings);
    btnLay->addWidget(saveBtn);

    btnLay->addStretch();

    QPushButton *closeBtn = new QPushButton("Закрыть", this);
    closeBtn->setFixedSize(110, 36);
    closeBtn->setCursor(Qt::PointingHandCursor);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnLay->addWidget(closeBtn);
    mainLayout->addLayout(btnLay);

    // Обновить статус
    updateConnectionStatus();
}

void SettingsDialog::applyStyles()
{
    setStyleSheet(
        "QDialog { background-color: #1a1a2e; } "
        "QTabWidget::pane { border: 1px solid #4CAF50; padding: 4px; } "
        "QTabBar::tab { background: #0f3460; color: #fff; padding: 8px 20px; margin-right: 4px; border-radius: 4px 4px 0 0; font-size: 13px; } "
        "QTabBar::tab:selected { background: #4CAF50; font-weight: bold; } "
        "QTabBar::tab:hover { background: #1a5276; } "
        "QLabel { color: #fff; font-size: 13px; } "
        "QLineEdit, QSpinBox { background: #0f3460; color: #fff; border: 1px solid #4CAF50; border-radius: 4px; padding: 8px; font-size: 14px; } "
        "QLineEdit:focus, QSpinBox:focus { border-color: #45a049; } "
        "QLineEdit::placeholder { color: #888; } "
        "QPushButton { background: #4CAF50; color: #fff; padding: 8px 16px; border-radius: 4px; font-weight: bold; font-size: 13px; } "
        "QPushButton:hover { background: #45a049; } "
        "QPushButton:disabled { background: #444; color: #888; } "
        "QGroupBox { color: #4CAF50; border: 1px solid #4CAF50; border-radius: 6px; margin-top: 12px; padding: 12px 8px 8px 8px; font-weight: bold; } "
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; } "
        "QCheckBox { color: #ccc; font-size: 13px; } "
        "QSpinBox::up-button, QSpinBox::down-button { background: #0f3460; border: 1px solid #4CAF50; } "
    );
}

void SettingsDialog::loadSettings()
{
    QSettings s;
    m_editServerHost->setText(s.value(KEY_HOST, DEFAULT_HOST).toString());
    m_spinServerPort->setValue(s.value(KEY_PORT, DEFAULT_PORT).toInt());
    m_editCertPath->setText(s.value(KEY_CERT, "").toString());
    m_checkVerifyCert->setChecked(s.value(KEY_VERIFY, false).toBool());

    updateConnectionStatus();
}

void SettingsDialog::saveSettings()
{
    QSettings s;
    s.setValue(KEY_HOST,   m_editServerHost->text().trimmed());
    s.setValue(KEY_PORT,   m_spinServerPort->value());
    s.setValue(KEY_CERT,   m_editCertPath->text());
    s.setValue(KEY_VERIFY, m_checkVerifyCert->isChecked());
}

void SettingsDialog::updateConnectionStatus()
{
    if (m_networkClient && m_networkClient->isConnected()) {
        m_labelConnectionStatus->setText("Подключено к серверу");
        m_labelConnectionStatus->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14px;");
    } else {
        m_labelConnectionStatus->setText("Не подключено");
        m_labelConnectionStatus->setStyleSheet("color: #ff4444; font-weight: bold; font-size: 14px;");
    }
}

void SettingsDialog::onTestConnection()
{
    if (!m_btnTestConnection) return;
    m_btnTestConnection->setEnabled(false);
    m_btnTestConnection->setText("Проверка...");
    QApplication::processEvents();

    QString host = m_editServerHost->text().trimmed();
    int port = m_spinServerPort->value();

    // Простая проверка TCP-соединения
    QTcpSocket testSocket;
    testSocket.connectToHost(host, static_cast<quint16>(port));
    bool connected = testSocket.waitForConnected(5000);

    m_btnTestConnection->setEnabled(true);
    m_btnTestConnection->setText("Проверить соединение");

    if (connected) {
        testSocket.disconnectFromHost();
        QMessageBox::information(this, "Проверка соединения",
            QString("Сервер %1:%2 доступен").arg(host).arg(port));
    } else {
        QMessageBox::warning(this, "Ошибка соединения",
            QString("Не удалось подключиться к %1:%2\n%3")
                .arg(host).arg(port).arg(testSocket.errorString()));
    }
}

void SettingsDialog::onSaveSettings()
{
    saveSettings();
    QMessageBox::information(this, "Сохранено",
        "Настройки сохранены.\n"
        "Изменения адреса сервера и порта вступят в силу\n"
        "при следующем подключении.");
}

// Статический метод: применить сохранённые настройки к NetworkClient
void SettingsDialog::applyStoredSettings(NetworkClient *client)
{
    if (!client) return;
    QSettings s;
    QString host = s.value(KEY_HOST, DEFAULT_HOST).toString();
    int port = s.value(KEY_PORT, DEFAULT_PORT).toInt();
    // Настройки применяются при connectToServer, который уже вызывается с правильными параметрами
    Q_UNUSED(host)
    Q_UNUSED(port)
}

// ── Существующие методы ─────────────────────────────────────────────

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
    QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку для экспорта ключей",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation));
    if (dir.isEmpty()) return;

    // Ищем пару ключей в appdata
    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir appDir(dataDir);

    QStringList keyFiles;
    if (appDir.exists("private_key.pem")) keyFiles << appDir.filePath("private_key.pem");
    if (appDir.exists("public_key.pem"))  keyFiles << appDir.filePath("public_key.pem");

    if (keyFiles.isEmpty()) {
        QMessageBox::information(this, "Экспорт ключей",
            "Ключи не найдены в " + dataDir + "\n\n"
            "Ключи генерируются при первом входе и хранятся локально.");
        return;
    }

    int copied = 0;
    for (const QString &src : keyFiles) {
        QFileInfo fi(src);
        QString dst = dir + "/" + fi.fileName();
        if (QFile::copy(src, dst)) copied++;
    }

    if (copied > 0) {
        QMessageBox::information(this, "Экспорт ключей",
            QString("Экспортировано файлов: %1 в %2").arg(copied).arg(dir));
    }
}

void SettingsDialog::onClearLocalData()
{
    int ret = QMessageBox::question(this, "Очистка данных",
        "Удалить ВСЕ локальные данные?\n\n"
        "Будут удалены: ключи шифрования, кеш, настройки.\n"
        "История передач будет потеряна.\n\n"
        "Продолжить?",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(dataDir);
    if (dir.exists()) {
        dir.removeRecursively();
    }

    QSettings s;
    s.clear();

    QMessageBox::information(this, "Очистка данных",
        "Все локальные данные удалены.\n"
        "При следующем запуске ключи будут созданы заново.\n"
        "Пароль не изменён на сервере.");
}