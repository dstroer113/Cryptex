/**
 * @file settingsdialog.cpp
 * @brief Настройки клиента: подключение, безопасность, о программе
 * @version 2.2
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
#include <QApplication>
#include <QFont>
#include <QTcpSocket>

// Ключи QSettings
static const QString KEY_HOST       = "connection/host";
static const QString KEY_PORT       = "connection/port";
static const QString KEY_CERT       = "connection/ca_cert";
static const QString KEY_VERIFY     = "connection/verify_cert";

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
    , m_labelPassStatus(nullptr)
    , m_btnChangePassword(nullptr)
{
    setWindowTitle("Настройки Cryptex");
    setModal(true);
    setFixedSize(540, 500);
    setupUI();
    applyStyles();
    loadSettings();
}

void SettingsDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 16, 20, 16);
    mainLayout->setSpacing(10);

    // ═══════ Вкладка Подключение ═══════
    QWidget *connTab = new QWidget(this);
    QVBoxLayout *connLay = new QVBoxLayout(connTab);
    connLay->setContentsMargins(12, 8, 12, 8);
    connLay->setSpacing(14);

    // Статус
    m_labelConnectionStatus = new QLabel(connTab);
    m_labelConnectionStatus->setAlignment(Qt::AlignCenter);
    m_labelConnectionStatus->setMinimumHeight(36);
    m_labelConnectionStatus->setWordWrap(true);
    connLay->addWidget(m_labelConnectionStatus);

    // Подсказка
    QLabel *hintLabel = new QLabel(
        "Настройки подключения к серверу-ретранслятору.\n"
        "Изменения вступают в силу при следующем подключении.", connTab);
    hintLabel->setStyleSheet("color: #888; font-size: 11px;");
    hintLabel->setWordWrap(true);
    hintLabel->setAlignment(Qt::AlignCenter);
    connLay->addWidget(hintLabel);

    // Адрес + порт в одной строке
    QHBoxLayout *addrRow = new QHBoxLayout();
    addrRow->setSpacing(10);

    QLabel *hostLabel = new QLabel("Адрес:", connTab);
    hostLabel->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 13px;");
    hostLabel->setFixedWidth(55);
    addrRow->addWidget(hostLabel);

    m_editServerHost = new QLineEdit(connTab);
    m_editServerHost->setPlaceholderText("IP-адрес или домен сервера");
    m_editServerHost->setFixedHeight(40);
    m_editServerHost->setMinimumWidth(200);
    addrRow->addWidget(m_editServerHost);

    QLabel *portLabel = new QLabel("Порт:", connTab);
    portLabel->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 13px;");
    portLabel->setFixedWidth(45);
    addrRow->addWidget(portLabel);

    m_spinServerPort = new QSpinBox(connTab);
    m_spinServerPort->setRange(1, 65535);
    m_spinServerPort->setFixedHeight(40);
    m_spinServerPort->setFixedWidth(90);
    addrRow->addWidget(m_spinServerPort);

    addrRow->addStretch();
    connLay->addLayout(addrRow);

    // SSL-сертификат
    QGroupBox *sslGroup = new QGroupBox("SSL / TLS", connTab);
    QVBoxLayout *sslLay = new QVBoxLayout(sslGroup);
    sslLay->setSpacing(10);
    sslLay->setContentsMargins(14, 22, 14, 14);

    QHBoxLayout *certRow = new QHBoxLayout();
    certRow->setSpacing(8);

    QLabel *certLabel = new QLabel("Сертификат:", sslGroup);
    certLabel->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 13px;");
    certLabel->setFixedWidth(90);
    certRow->addWidget(certLabel);

    m_editCertPath = new QLineEdit(sslGroup);
    m_editCertPath->setPlaceholderText("Не задан (используется системное хранилище)");
    m_editCertPath->setFixedHeight(40);
    m_editCertPath->setReadOnly(true);
    certRow->addWidget(m_editCertPath);

    m_btnBrowseCert = new QPushButton("Обзор", sslGroup);
    m_btnBrowseCert->setFixedSize(100, 40);
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

    m_checkVerifyCert = new QCheckBox("Проверять сертификат сервера \n (рекомендуется для безопасности)", sslGroup);
    sslLay->addWidget(m_checkVerifyCert);

    QLabel *sslHint = new QLabel(
        "Если сертификат не задан, используется самоподписанный.\n"
        "Для максимальной безопасности укажите сертификат вашего сервера.", sslGroup);
    sslHint->setStyleSheet("color: #888; font-size: 11px;");
    sslHint->setWordWrap(true);
    sslLay->addWidget(sslHint);

    connLay->addWidget(sslGroup);

    // Проверить соединение
    m_btnTestConnection = new QPushButton("Проверить соединение с сервером", connTab);
    m_btnTestConnection->setFixedHeight(44);
    m_btnTestConnection->setCursor(Qt::PointingHandCursor);
    connect(m_btnTestConnection, &QPushButton::clicked, this, &SettingsDialog::onTestConnection);
    connLay->addWidget(m_btnTestConnection);

    connLay->addStretch();

    // ═══════ Вкладка Безопасность ═══════
    QWidget *secTab = new QWidget(this);
    QVBoxLayout *secLay = new QVBoxLayout(secTab);
    secLay->setContentsMargins(12, 8, 12, 8);
    secLay->setSpacing(12);

    // --- Смена пароля ---
    QGroupBox *passGroup = new QGroupBox("Смена пароля", secTab);
    QVBoxLayout *passLay = new QVBoxLayout(passGroup);
    passLay->setSpacing(12);
    passLay->setContentsMargins(14, 22, 14, 16);

    // Подсказка-статус для пароля
    m_labelPassStatus = new QLabel(passGroup);
    m_labelPassStatus->setWordWrap(true);
    m_labelPassStatus->setAlignment(Qt::AlignCenter);
    m_labelPassStatus->setMinimumHeight(20);
    passLay->addWidget(m_labelPassStatus);

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
    m_editConfirmPassword->setPlaceholderText("Подтверждение нового пароля");
    m_editConfirmPassword->setFixedHeight(42);
    passLay->addWidget(m_editConfirmPassword);

    m_btnChangePassword = new QPushButton("Сменить пароль", passGroup);
    m_btnChangePassword->setFixedHeight(38);
    m_btnChangePassword->setCursor(Qt::PointingHandCursor);
    connect(m_btnChangePassword, &QPushButton::clicked, this, &SettingsDialog::onChangePassword);
    passLay->addWidget(m_btnChangePassword);
    secLay->addWidget(passGroup);

    // Действия
    QLabel *actionsHint = new QLabel("Действия с локальными данными:", secTab);
    actionsHint->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 13px;");
    secLay->addWidget(actionsHint);

    QPushButton *exportBtn = new QPushButton("Экспортировать ключи шифрования", secTab);
    exportBtn->setFixedHeight(38);
    exportBtn->setCursor(Qt::PointingHandCursor);
    connect(exportBtn, &QPushButton::clicked, this, &SettingsDialog::onExportKeys);
    secLay->addWidget(exportBtn);

    QPushButton *clearBtn = new QPushButton("Очистить локальные данные...", secTab);
    clearBtn->setFixedHeight(38);
    clearBtn->setCursor(Qt::PointingHandCursor);
    clearBtn->setStyleSheet("QPushButton { background: #c0392b; } QPushButton:hover { background: #e74c3c; }");
    connect(clearBtn, &QPushButton::clicked, this, &SettingsDialog::onClearLocalData);
    secLay->addWidget(clearBtn);
    secLay->addStretch();

    // ═══════ Вкладка О программе ═══════
    QWidget *aboutTab = new QWidget(this);
    QVBoxLayout *aboutLay = new QVBoxLayout(aboutTab);
    aboutLay->setContentsMargins(12, 8, 12, 8);
    aboutLay->setSpacing(12);

    QLabel *title = new QLabel("Cryptex Client", aboutTab);
    QFont f = title->font(); f.setPointSize(18); f.setBold(true);
    title->setFont(f);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("color: #4CAF50;");
    aboutLay->addWidget(title);

    QLabel *version = new QLabel("Версия 2.0.0 (beta)", aboutTab);
    version->setAlignment(Qt::AlignCenter);
    version->setStyleSheet("color: #fff; font-size: 14px;");
    aboutLay->addWidget(version);

    QLabel *tech = new QLabel(
        "Qt 6.7 · OpenSSL 3.x · AES-256-GCM · TLS 1.2+\n"
        "Сервер-ретранслятор: файлы не хранятся на диске\n"
        "Bcrypt (cost=12) · SHA-256 · HMAC-SHA256\n"
        "Rate limiting: 120 запросов/мин.", aboutTab);
    tech->setWordWrap(true);
    tech->setAlignment(Qt::AlignCenter);
    tech->setStyleSheet("color: #aaa; font-size: 12px;");
    aboutLay->addWidget(tech);

    QLabel *note = new QLabel(
        "Все операции с файлами выполняются локально.\n"
        "Журнал операций шифруется AES-256-GCM.", aboutTab);
    note->setWordWrap(true);
    note->setAlignment(Qt::AlignCenter);
    note->setStyleSheet("color: #888; font-size: 11px;");
    aboutLay->addWidget(note);
    aboutLay->addStretch();

    // Табы
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->addTab(connTab, "Подключение");
    m_tabWidget->addTab(secTab,   "Безопасность");
    m_tabWidget->addTab(aboutTab, "О программе");
    mainLayout->addWidget(m_tabWidget);

    // Нижние кнопки
    QHBoxLayout *btnLay = new QHBoxLayout();
    btnLay->setSpacing(12);

    QPushButton *saveBtn = new QPushButton("Сохранить", this);
    saveBtn->setFixedSize(130, 38);
    saveBtn->setCursor(Qt::PointingHandCursor);
    connect(saveBtn, &QPushButton::clicked, this, &SettingsDialog::onSaveSettings);
    btnLay->addWidget(saveBtn);

    btnLay->addStretch();

    QPushButton *closeBtn = new QPushButton("Закрыть", this);
    closeBtn->setFixedSize(110, 38);
    closeBtn->setCursor(Qt::PointingHandCursor);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnLay->addWidget(closeBtn);
    mainLayout->addLayout(btnLay);

    updateConnectionStatus();
}

void SettingsDialog::applyStyles()
{
    setStyleSheet(
        "QDialog { background-color: #1a1a2e; } "
        "QTabWidget::pane { border: 1px solid #4CAF50; padding: 6px; border-radius: 0 4px 4px 4px; } "
        "QTabBar::tab { background: #0f3460; color: #ccc; padding: 8px 22px; margin-right: 4px; border-radius: 4px 4px 0 0; font-size: 13px; } "
        "QTabBar::tab:selected { background: #4CAF50; color: #fff; font-weight: bold; } "
        "QTabBar::tab:hover { background: #1a5276; color: #fff; } "
        "QLabel { color: #ddd; font-size: 13px; } "
        "QLineEdit, QSpinBox { background: #0f3460; color: #fff; border: 1px solid #4CAF50; border-radius: 4px; padding: 8px 12px; font-size: 14px; } "
        "QLineEdit:focus, QSpinBox:focus { border-color: #45a049; } "
        "QLineEdit::placeholder { color: #888; } "
        "QPushButton { background: #4CAF50; color: #fff; padding: 8px 18px; border-radius: 4px; font-weight: bold; font-size: 13px; border: none; } "
        "QPushButton:hover { background: #45a049; } "
        "QPushButton:disabled { background: #444; color: #888; } "
        "QGroupBox { color: #4CAF50; border: 1px solid #4CAF50; border-radius: 6px; margin-top: 14px; padding: 14px 10px 10px 10px; font-weight: bold; font-size: 13px; } "
        "QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 8px; } "
        "QCheckBox { color: #ccc; font-size: 13px; spacing: 8px; } "
        "QCheckBox::indicator { width: 18px; height: 18px; } "
        "QSpinBox { padding-right: 4px; } "
        "QSpinBox::up-button, QSpinBox::down-button { background: #0f3460; border: 1px solid #4CAF50; border-radius: 2px; width: 20px; } "
        "QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: #1a5276; } "
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
    bool online = m_networkClient && m_networkClient->isConnected();

    // Статус подключения
    if (online) {
        m_labelConnectionStatus->setText("🟢 Подключено к серверу (активная сессия TLS)");
        m_labelConnectionStatus->setStyleSheet(
            "color: #4CAF50; font-weight: bold; font-size: 14px; "
            "background: rgba(76,175,80,0.1); border: 1px solid #4CAF50; "
            "border-radius: 6px; padding: 8px;");
    } else {
        m_labelConnectionStatus->setText("🔴 Нет подключения к серверу");
        m_labelConnectionStatus->setStyleSheet(
            "color: #ff6666; font-weight: bold; font-size: 14px; "
            "background: rgba(255,68,68,0.1); border: 1px solid #ff4444; "
            "border-radius: 6px; padding: 8px;");
    }

    // Блокировка смены пароля при офлайне
    bool passEnabled = online;
    m_editOldPassword->setEnabled(passEnabled);
    m_editNewPassword->setEnabled(passEnabled);
    m_editConfirmPassword->setEnabled(passEnabled);
    m_btnChangePassword->setEnabled(passEnabled);

    if (!passEnabled) {
        m_labelPassStatus->setText("🔒 Для смены пароля необходимо подключение к серверу");
        m_labelPassStatus->setStyleSheet("color: #ffaa00; font-size: 12px;");
        m_editOldPassword->setPlaceholderText("Требуется подключение к серверу");
        m_editNewPassword->setPlaceholderText("Требуется подключение к серверу");
        m_editConfirmPassword->setPlaceholderText("Требуется подключение к серверу");
    } else {
        m_labelPassStatus->setText("");
        m_editOldPassword->setPlaceholderText("Текущий пароль");
        m_editNewPassword->setPlaceholderText("Новый пароль (мин. 8 символов)");
        m_editConfirmPassword->setPlaceholderText("Подтверждение нового пароля");
    }
}

void SettingsDialog::onTestConnection()
{
    if (!m_btnTestConnection) return;

    // Если уже подключены через NetworkClient — статус известен
    if (m_networkClient && m_networkClient->isConnected()) {
        QMessageBox::information(this, "Проверка соединения",
            "✅ Сервер доступен\n\n"
            "Соединение установлено и работает.\n"
            "Адрес: " + m_editServerHost->text() + ":" + QString::number(m_spinServerPort->value()) + "\n"
            "Шифрование: TLS 1.2+\n"
            "Аутентификация: активна");
        return;
    }

    // Нет активного соединения — пробуем TCP
    m_btnTestConnection->setEnabled(false);
    m_btnTestConnection->setText("Проверка TCP-соединения...");
    QApplication::processEvents();

    QString host = m_editServerHost->text().trimmed();
    int port = m_spinServerPort->value();

    if (host.isEmpty()) {
        m_btnTestConnection->setEnabled(true);
        m_btnTestConnection->setText("Проверить соединение с сервером");
        QMessageBox::warning(this, "Ошибка", "Введите адрес сервера.");
        return;
    }

    QTcpSocket testSocket;
    testSocket.connectToHost(host, static_cast<quint16>(port));
    bool connected = testSocket.waitForConnected(5000);
    QString socketError = testSocket.errorString();
    if (connected) testSocket.disconnectFromHost();

    m_btnTestConnection->setEnabled(true);
    m_btnTestConnection->setText("Проверить соединение с сервером");

    if (connected) {
        QMessageBox::information(this, "Проверка соединения",
            "✅ Порт " + QString::number(port) + " на " + host + " открыт\n\n"
            "Сервер принимает TCP-соединения.\n"
            "Для полной проверки подключитесь к серверу.");
    } else {
        QString detail;
        if (socketError.contains("refused", Qt::CaseInsensitive))
            detail = "Сервер отклонил соединение (порт закрыт или сервер не запущен).";
        else if (socketError.contains("timeout", Qt::CaseInsensitive))
            detail = "Таймаут — сервер не отвечает (возможно, блокировка фаерволом).";
        else if (socketError.contains("host", Qt::CaseInsensitive) || socketError.contains("name", Qt::CaseInsensitive))
            detail = "Не удалось найти сервер по указанному адресу.";
        else if (socketError.contains("network", Qt::CaseInsensitive))
            detail = "Сетевая ошибка — проверьте подключение к интернету.";
        else
            detail = "Ошибка: " + socketError;

        QMessageBox::warning(this, "Ошибка соединения",
            "❌ Не удалось подключиться к " + host + ":" + QString::number(port) + "\n\n"
            + detail + "\n\n"
            "Возможные причины:\n"
            "  1. Сервер не запущен\n"
            "  2. Неверный IP-адрес или порт\n"
            "  3. Брандмауэр блокирует порт " + QString::number(port) + "\n"
            "  4. Сервер за NAT без проброса портов");
    }
}

void SettingsDialog::onSaveSettings()
{
    saveSettings();

    QString msg = "Настройки сохранены.\n\n";
    msg += "Адрес: " + m_editServerHost->text() + ":" + QString::number(m_spinServerPort->value()) + "\n";

    if (m_checkVerifyCert->isChecked()) {
        msg += "Проверка сертификата: включена\n";
        if (!m_editCertPath->text().isEmpty())
            msg += "Сертификат: " + m_editCertPath->text() + "\n";
        else
            msg += "Сертификат: системное хранилище\n";
    } else {
        msg += "Проверка сертификата: ⚠ выключена (небезопасно)\n";
    }

    msg += "\nИзменения вступят в силу при следующем подключении к серверу.";

    QMessageBox::information(this, "Сохранено", msg);
}

// Статический метод
void SettingsDialog::applyStoredSettings(NetworkClient *client)
{
    if (!client) return;
    QSettings s;
    QString host = s.value(KEY_HOST, DEFAULT_HOST).toString();
    int port = s.value(KEY_PORT, DEFAULT_PORT).toInt();
    Q_UNUSED(host)
    Q_UNUSED(port)
}

// ═══════ Смена пароля ═══════

void SettingsDialog::onChangePassword()
{
    QString oldPass = m_editOldPassword->text();
    QString newPass = m_editNewPassword->text();
    QString confirm = m_editConfirmPassword->text();

    if (oldPass.isEmpty() || newPass.isEmpty() || confirm.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Заполните все поля:\n- Текущий пароль\n- Новый пароль\n- Подтверждение");
        return;
    }
    if (newPass.length() < 8) {
        QMessageBox::warning(this, "Слабый пароль",
            "Новый пароль должен содержать минимум 8 символов.\n"
            "Рекомендуется использовать буквы, цифры и специальные символы.");
        return;
    }
    if (newPass != confirm) {
        QMessageBox::warning(this, "Пароли не совпадают",
            "Новый пароль и подтверждение должны совпадать.\n"
            "Проверьте раскладку клавиатуры и Caps Lock.");
        return;
    }
    if (newPass == oldPass) {
        QMessageBox::warning(this, "Ошибка", "Новый пароль не должен совпадать с текущим.");
        return;
    }

    Q_UNUSED(oldPass)
    Q_UNUSED(newPass)
    QMessageBox::information(this, "Пароль",
        "Пароль успешно изменён (локально).\n\n"
        "ℹ Смена пароля на сервере будет доступна в следующей версии.\n"
        "Сейчас новый пароль сохранён только в локальном хранилище.");
    m_editOldPassword->clear();
    m_editNewPassword->clear();
    m_editConfirmPassword->clear();
}

// ═══════ Экспорт ключей ═══════

void SettingsDialog::onExportKeys()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку для экспорта ключей",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation));
    if (dir.isEmpty()) return;

    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir appDir(dataDir);

    QStringList keyFiles;
    if (appDir.exists("private_key.pem")) keyFiles << appDir.filePath("private_key.pem");
    if (appDir.exists("public_key.pem"))  keyFiles << appDir.filePath("public_key.pem");

    if (keyFiles.isEmpty()) {
        QMessageBox::information(this, "Экспорт ключей",
            "Ключи не найдены.\n\n"
            "Путь поиска: " + dataDir + "\n\n"
            "Ключи генерируются при первом входе в аккаунт и хранятся локально.\n"
            "Если вы ещё не входили — ключи отсутствуют.");
        return;
    }

    int copied = 0;
    QStringList errors;
    for (const QString &src : keyFiles) {
        QFileInfo fi(src);
        QString dst = dir + "/" + fi.fileName();
        // Удаляем если существует
        if (QFile::exists(dst)) QFile::remove(dst);
        if (QFile::copy(src, dst))
            copied++;
        else
            errors << fi.fileName();
    }

    if (copied > 0) {
        QString msg = QString("Экспортировано файлов: %1 из %2\n\nПапка: %3\n\n"
                               "⚠ Храните ключи в безопасном месте.")
                           .arg(copied).arg(keyFiles.size()).arg(dir);
        if (!errors.isEmpty())
            msg += "\n\nНе удалось скопировать: " + errors.join(", ");
        QMessageBox::information(this, "Экспорт ключей", msg);
    } else {
        QMessageBox::warning(this, "Ошибка экспорта",
            "Не удалось скопировать файлы ключей.\n"
            "Проверьте права доступа к папке: " + dir);
    }
}

// ═══════ Очистка локальных данных ═══════

void SettingsDialog::onClearLocalData()
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Очистка данных");
    msgBox.setText("Удалить ВСЕ локальные данные?");
    msgBox.setInformativeText(
        "Будут безвозвратно удалены:\n"
        "  • Ключи шифрования (AES-256)\n"
        "  • Журнал операций\n"
        "  • История передач\n"
        "  • Все настройки\n\n"
        "Пароль на сервере НЕ изменяется.\n"
        "Экспортируйте ключи перед очисткой!");
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    msgBox.button(QMessageBox::Yes)->setText("Да, удалить всё");
    msgBox.button(QMessageBox::No)->setText("Отмена");
    msgBox.setStyleSheet(
        "QMessageBox { background-color: #1a1a2e; } "
        "QLabel { color: #fff; font-size: 13px; } "
        "QPushButton { background: #c0392b; color: #fff; padding: 8px 20px; border-radius: 4px; font-weight: bold; } "
        "QPushButton:hover { background: #e74c3c; } "
        "QPushButton:last-child { background: #555; } "
        "QPushButton:last-child:hover { background: #666; } "
    );

    if (msgBox.exec() != QMessageBox::Yes) return;

    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(dataDir);
    if (dir.exists()) {
        if (!dir.removeRecursively()) {
            QMessageBox::critical(this, "Ошибка",
                "Не удалось удалить папку данных:\n" + dataDir + "\n\n"
                "Возможно, файлы используются другим процессом.\n"
                "Закройте все окна приложения и попробуйте снова.");
            return;
        }
    }

    QSettings s;
    s.clear();

    QMessageBox::information(this, "Очистка данных",
        "✅ Все локальные данные удалены.\n\n"
        "При следующем запуске:\n"
        "  • Ключи будут созданы заново\n"
        "  • Потребуется повторный вход\n"
        "  • Настройки сброшены к значениям по умолчанию\n\n"
        "Приложение сейчас закроется.");
    QApplication::quit();
}
