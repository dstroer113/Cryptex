/**
 * @file MainWindow.cpp
 * @brief Реализация главного окна Cryptex Client
 * @version 2.0
 */
#include "MainWindow.h"
#include "loginwindow.h"
#include "src/networkclient.h"
#include "src/contactstab.h"
#include "src/transferstab.h"
#include "src/settingsdialog.h"

#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QDebug>
#include <QApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QDir>
#include <QStandardPaths>
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QProcess>
#include <QInputDialog>

MainWindow::MainWindow(NetworkClient *client, bool online, QWidget *parent)
    : QMainWindow(parent)
    , m_labelUser(nullptr)
    , m_labelUserId(nullptr)
    , m_btnLogout(nullptr)
    , m_btnSettings(nullptr)
    , m_tabWidget(nullptr)
    , m_editInput(nullptr)
    , m_editOutput(nullptr)
    , m_editPassword(nullptr)
    , m_btnInput(nullptr)
    , m_btnInputDir(nullptr)
    , m_btnOutput(nullptr)
    , m_btnEncrypt(nullptr)
    , m_btnDecrypt(nullptr)
    , m_chkDeleteSource(nullptr)
    , m_labelMode(nullptr)
    , m_tableLogs(nullptr)
    , m_btnRefresh(nullptr)
    , m_btnClearLogs(nullptr)
    , m_networkClient(nullptr)
    , m_contactsTab(nullptr)
    , m_transfersTab(nullptr)
    , m_online(online)
    , m_userId(-1)
    , m_isProcessing(false)
    , m_crypto(CryptoEngine::getInstance())
    , m_security(SecurityManager::getInstance())
{
    qDebug() << "[MainWindow] Инициализация, online =" << online;
    resize(960, 660);
    setWindowTitle("Cryptex Client");
    setMinimumSize(800, 550);

    // Сетевой клиент
    m_networkClient = client;
    if (m_networkClient) {
        connect(m_networkClient, &NetworkClient::connected, this, &MainWindow::onServerConnected);
        connect(m_networkClient, &NetworkClient::disconnected, this, &MainWindow::onServerDisconnected);
        connect(m_networkClient, &NetworkClient::loginSuccess, this,
            [this](int uid, const QString &uname, const QString &token) {
                setUserId(uid);
                setUserName(uname);
                setSessionToken(token);
                addLogEntry("Вход на сервер", uname + " (токен: ..." + token.right(8) + ")", true);
            });
    }

    // Вкладки контактов и трансферов (только для онлайна)
    if (m_online && m_networkClient) {
        m_contactsTab = new ContactsTab(m_networkClient, this);
        m_transfersTab = new TransfersTab(m_networkClient, this);
        connect(m_contactsTab, &ContactsTab::contactsUpdated,
                m_transfersTab, &TransfersTab::updateContacts);
    }

    setupUI();
    applyDarkTheme();
    loadLogsFromFile();

    // Для офлайн-режима сразу скрываем сетевые вкладки
    updateNetworkTabs();

    qDebug() << "[MainWindow] Готово к работе";
}

MainWindow::~MainWindow()
{
    qDebug() << "[MainWindow] Закрытие";
    saveLogsToFile();
    m_sessionToken.clear();
}

// ────────────────────────────────────────────────────────────────────
// Настройки сессии
// ────────────────────────────────────────────────────────────────────
void MainWindow::setSessionToken(const QString &token) { m_sessionToken = token; updateSessionInfo(); }
void MainWindow::setUserId(int id) { m_userId = id; updateSessionInfo(); }
void MainWindow::setUserName(const QString &name) { m_userName = name; updateSessionInfo(); }
void MainWindow::updateSessionInfo()
{
    if (m_labelUser) m_labelUser->setText(m_userName.isEmpty() ? "Офлайн" : m_userName);
    if (m_labelUserId) m_labelUserId->setVisible(false);
}

void MainWindow::switchToOnlineMode(const QString &username, int userId, const QString &token)
{
    m_online = true;
    m_userId = userId;
    m_userName = username;
    m_sessionToken = token;

    // Подключаем сигналы
    if (m_networkClient) {
        connect(m_networkClient, &NetworkClient::connected, this, &MainWindow::onServerConnected);
        connect(m_networkClient, &NetworkClient::disconnected, this, &MainWindow::onServerDisconnected);
    }

    // Создаём вкладки контактов и передач
    if (!m_contactsTab) {
        m_contactsTab = new ContactsTab(m_networkClient, this);
        m_transfersTab = new TransfersTab(m_networkClient, this);
        connect(m_contactsTab, &ContactsTab::contactsUpdated,
                m_transfersTab, &TransfersTab::updateContacts);
    }

    updateNetworkTabs();
    updateSessionInfo();
    statusBar()->showMessage("🟢 Подключено к серверу", 5000);
    addLogEntry("Сеть", "Подключено к серверу как " + username, true);
}

void MainWindow::updateNetworkTabs()
{
    if (!m_tabWidget) return;
    if (m_online) {
        // Добавляем вкладки если их ещё нет
        bool hasContacts = false, hasTransfers = false;
        for (int i = 0; i < m_tabWidget->count(); ++i) {
            if (m_tabWidget->tabText(i) == "👥 Контакты") hasContacts = true;
            if (m_tabWidget->tabText(i) == "📁 Передачи") hasTransfers = true;
        }
        if (!hasContacts && m_contactsTab)
            m_tabWidget->addTab(m_contactsTab, "👥 Контакты");
        if (!hasTransfers && m_transfersTab)
            m_tabWidget->addTab(m_transfersTab, "📁 Передачи");
    } else {
        // Убираем сетевые вкладки
        for (int i = m_tabWidget->count() - 1; i >= 0; --i) {
            QString title = m_tabWidget->tabText(i);
            if (title == "👥 Контакты" || title == "📁 Передачи") {
                m_tabWidget->removeTab(i);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// UI
// ────────────────────────────────────────────────────────────────────
void MainWindow::setupUI()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Шапка
    QWidget *header = new QWidget(central);
    header->setFixedHeight(50);
    QHBoxLayout *hHeader = new QHBoxLayout(header);
    hHeader->setContentsMargins(15, 5, 15, 5);

    QLabel *logo = new QLabel("🔐 Cryptex", header);
    QFont f = logo->font(); f.setPointSize(14); f.setBold(true);
    logo->setFont(f);
    hHeader->addWidget(logo);
    hHeader->addStretch();

    QLabel *loginLabel = new QLabel("Логин:", header);
    loginLabel->setStyleSheet("color: #888; font-size: 13px; margin-right: 6px;");
    hHeader->addWidget(loginLabel);

    m_labelUser = new QLabel(m_online ? "Пользователь" : "Офлайн", header);
    m_labelUser->setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14px;");
    hHeader->addWidget(m_labelUser);

    m_labelUserId = new QLabel("", header);
    hHeader->addWidget(m_labelUserId);

    m_btnSettings = new QPushButton("⚙ Настройки", header);
    m_btnSettings->setFixedHeight(32);
    m_btnSettings->setCursor(Qt::PointingHandCursor);
    m_btnSettings->setStyleSheet("QPushButton { background: #0f3460; color: #4CAF50; padding: 4px 12px; border-radius: 4px; } QPushButton:hover { background: #1a5276; }");
    hHeader->addWidget(m_btnSettings);

    m_btnLogout = new QPushButton(m_online ? "Выйти" : "🔌 Подключиться", header);
    m_btnLogout->setFixedHeight(32);
    m_btnLogout->setCursor(Qt::PointingHandCursor);
    hHeader->addWidget(m_btnLogout);

    mainLayout->addWidget(header);

    // Вкладки
    m_tabWidget = new QTabWidget(central);
    mainLayout->addWidget(m_tabWidget);
    m_tabWidget->addTab(createDashboardTab(), "Главная");
    m_tabWidget->addTab(createCryptoTab(), "Шифрование");
    m_tabWidget->addTab(createLogTab(), "Журнал");

    // Сигналы
    connect(m_btnLogout, &QPushButton::clicked, this, m_online ? &MainWindow::onLogout : &MainWindow::onConnectClicked);
    connect(m_btnSettings, &QPushButton::clicked, this, &MainWindow::onOpenSettings);
    connect(m_btnInput, &QPushButton::clicked, this, &MainWindow::onSelectInputFile);
    connect(m_btnInputDir, &QPushButton::clicked, this, &MainWindow::onSelectInputDir);
    connect(m_btnOutput, &QPushButton::clicked, this, &MainWindow::onSelectOutputFile);
    connect(m_btnEncrypt, &QPushButton::clicked, this, &MainWindow::onEncryptFile);
    connect(m_btnDecrypt, &QPushButton::clicked, this, &MainWindow::onDecryptFile);
    connect(m_btnRefresh, &QPushButton::clicked, this, &MainWindow::onRefreshLogs);
    connect(m_btnClearLogs, &QPushButton::clicked, this, &MainWindow::onClearLogs);
}

QWidget* MainWindow::createDashboardTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(40, 40, 40, 40);

    QLabel *welcome = new QLabel(m_online ? "Добро пожаловать в Cryptex!" : "Добро пожаловать в Cryptex! (Офлайн)", tab);
    welcome->setAlignment(Qt::AlignCenter);
    QFont wf = welcome->font(); wf.setPointSize(16); wf.setBold(true);
    welcome->setFont(wf);
    lay->addWidget(welcome);

    QString descText;
    if (m_online) {
        descText = "🔒 Шифрование файлов — вкладка «Шифрование»\n"
                   "👥 Контакты и 📁 Передачи — только в онлайн-режиме\n"
                   "📋 Все операции записываются в «Журнал»\n"
                   "⚙ Настройки — кнопка в шапке окна\n\n"
                   "Поддерживается шифрование:\n"
                   "• Отдельных файлов\n"
                   "• Нескольких файлов из папки\n"
                   "• Алгоритм AES-256-GCM с проверкой целостности";
    } else {
        descText = "🔒 Шифрование файлов — вкладка «Шифрование»\n"
                   "📋 Все операции записываются в «Журнал»\n"
                   "⚙ Настройки — кнопка в шапке окна\n"
                   "🔌 Нажмите «Подключиться» для доступа к контактам и передачам\n\n"
                   "Поддерживается шифрование:\n"
                   "• Отдельных файлов\n"
                   "• Нескольких файлов из папки\n"
                   "• Алгоритм AES-256-GCM с проверкой целостности";
    }
    QLabel *desc = new QLabel(descText, tab);
    desc->setAlignment(Qt::AlignCenter);
    desc->setWordWrap(true);
    lay->addWidget(desc);
    lay->addStretch();
    return tab;
}

QWidget* MainWindow::createCryptoTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *vLay = new QVBoxLayout(tab);
    vLay->setContentsMargins(40, 30, 40, 30);
    vLay->setSpacing(15);

    // Режим
    m_labelMode = new QLabel("Режим: одиночный файл", tab);
    m_labelMode->setStyleSheet("color: #aaa; font-size: 12px;");
    vLay->addWidget(m_labelMode);

    QFormLayout *form = new QFormLayout();
    form->setLabelAlignment(Qt::AlignRight);
    form->setSpacing(12);

    // Входной файл
    m_editInput = new QLineEdit(tab);
    m_editInput->setFixedHeight(38);
    m_editInput->setPlaceholderText("Выберите файл или папку...");
    m_editInput->setReadOnly(true);
    m_btnInput = new QPushButton("📁", tab);
    m_btnInput->setFixedWidth(45);
    m_btnInput->setToolTip("Выбрать файл");
    m_btnInputDir = new QPushButton("📂", tab);
    m_btnInputDir->setFixedWidth(45);
    m_btnInputDir->setToolTip("Выбрать папку");
    QHBoxLayout *hIn = new QHBoxLayout();
    hIn->addWidget(m_editInput);
    hIn->addWidget(m_btnInput);
    hIn->addWidget(m_btnInputDir);
    form->addRow("Исходный файл:", hIn);

    // Выходной файл
    m_editOutput = new QLineEdit(tab);
    m_editOutput->setFixedHeight(38);
    m_editOutput->setPlaceholderText("Автоматически...");
    m_editOutput->setReadOnly(true);
    m_btnOutput = new QPushButton("📁", tab);
    m_btnOutput->setFixedWidth(45);
    m_btnOutput->setToolTip("Выбрать путь сохранения");
    QHBoxLayout *hOut = new QHBoxLayout();
    hOut->addWidget(m_editOutput);
    hOut->addWidget(m_btnOutput);
    form->addRow("Сохранить как:", hOut);

    // Пароль
    m_editPassword = new QLineEdit(tab);
    m_editPassword->setEchoMode(QLineEdit::Password);
    m_editPassword->setFixedHeight(38);
    m_editPassword->setPlaceholderText("Минимум 8 символов");
    form->addRow("Пароль:", m_editPassword);

    vLay->addLayout(form);

    // Удаление исходного
    m_chkDeleteSource = new QCheckBox("Удалить исходные файлы после операции", tab);
    vLay->addWidget(m_chkDeleteSource);

    // Кнопки
    QHBoxLayout *btns = new QHBoxLayout();
    btns->setSpacing(20);
    m_btnEncrypt = new QPushButton("🔒 Зашифровать", tab);
    m_btnEncrypt->setFixedHeight(42);
    m_btnDecrypt = new QPushButton("🔓 Дешифровать", tab);
    m_btnDecrypt->setFixedHeight(42);
    btns->addWidget(m_btnEncrypt);
    btns->addWidget(m_btnDecrypt);
    vLay->addLayout(btns);
    vLay->addStretch();

    return tab;
}

QWidget* MainWindow::createLogTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *vLay = new QVBoxLayout(tab);
    vLay->setContentsMargins(20, 20, 20, 20);

    m_tableLogs = new QTableWidget(tab);
    m_tableLogs->setColumnCount(4);
    m_tableLogs->setHorizontalHeaderLabels({"Время", "Событие", "Файл", "Результат"});
    m_tableLogs->horizontalHeader()->setStretchLastSection(true);
    m_tableLogs->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tableLogs->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tableLogs->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tableLogs->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableLogs->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tableLogs->setSortingEnabled(true);
    m_tableLogs->setAlternatingRowColors(true);
    m_tableLogs->verticalHeader()->setVisible(false);
    vLay->addWidget(m_tableLogs);

    QHBoxLayout *hBtns = new QHBoxLayout();
    m_btnRefresh = new QPushButton("Обновить", tab);
    m_btnClearLogs = new QPushButton("Очистить журнал", tab);
    hBtns->addStretch();
    hBtns->addWidget(m_btnRefresh);
    hBtns->addWidget(m_btnClearLogs);
    vLay->addLayout(hBtns);

    return tab;
}

void MainWindow::applyDarkTheme()
{
    setStyleSheet(
        "QMainWindow { background-color: #1a1a2e; } "
        "QTabWidget::pane { border: 1px solid #4CAF50; background-color: #16213e; } "
        "QTabBar::tab { background-color: #0f3460; color: #fff; padding: 8px 24px; margin-right: 2px; border-radius: 6px 6px 0 0; border: 1px solid #4CAF50; border-bottom: none; } "
        "QTabBar::tab:selected { background-color: #4CAF50; color: #fff; } "
        "QTabBar::tab:last { margin-right: 0; } "
        "QLabel { color: #ffffff; font-size: 13px; } "
        "QLineEdit { padding: 6px; border: 1px solid #4CAF50; border-radius: 4px; background: #0f3460; color: #fff; } "
        "QLineEdit:read-only { background: #0a1a3a; color: #aaa; } "
        "QPushButton { background: #4CAF50; color: #fff; padding: 8px; border-radius: 4px; font-weight: bold; } "
        "QPushButton:hover { background: #45a049; } "
        "QPushButton:disabled { background: #444; } "
        "QCheckBox { color: #fff; } "
        "QTableWidget { background: #0f3460; color: #fff; gridline-color: #4CAF50; border: none; } "
        "QTableWidget::item { padding: 6px; } "
        "QTableWidget::item:alternate { background: #112244; } "
        "QHeaderView::section { background: #16213e; color: #fff; padding: 6px; border: 1px solid #4CAF50; } "
        "QStatusBar { background: #0f3460; color: #aaa; } "
        "QListWidget { background: #0f3460; color: #fff; border: 1px solid #4CAF50; } "
        "QListWidget::item { padding: 4px; } "
        "QListWidget::item:alternate { background: #112244; } "
        "QGroupBox { color: #fff; border: 1px solid #4CAF50; border-radius: 6px; margin-top: 12px; padding: 16px 12px 12px 12px; } "
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; } "
        "QComboBox { background: #0f3460; color: #fff; border: 1px solid #4CAF50; border-radius: 4px; } "
        "QSplitter::handle { background: #4CAF50; } "
        "QInputDialog { background: #1a1a2e; } "
        "QGroupBox QLineEdit { margin: 4px 6px; } "
        "QGroupBox QPushButton { margin: 4px 6px; } "
        "QGroupBox QLabel { margin: 4px 6px; } "
        "QGroupBox QComboBox { margin: 4px 6px; } "
    );
}

// ────────────────────────────────────────────────────────────────────
// Логирование
// ────────────────────────────────────────────────────────────────────
void MainWindow::addLogEntry(const QString &event, const QString &details, bool success)
{
    if (!m_tableLogs) return;
    int r = m_tableLogs->rowCount();
    m_tableLogs->insertRow(r);
    m_tableLogs->setItem(r, 0, new QTableWidgetItem(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")));
    m_tableLogs->setItem(r, 1, new QTableWidgetItem(event));
    m_tableLogs->setItem(r, 2, new QTableWidgetItem(details));
    QTableWidgetItem *st = new QTableWidgetItem(success ? "✅ Успешно" : "❌ Ошибка");
    st->setForeground(success ? QColor("#4CAF50") : QColor("#ff4444"));
    m_tableLogs->setItem(r, 3, st);
    m_tableLogs->scrollToBottom();
    saveLogsToFile();
}

QString MainWindow::getLogFilePath() const
{
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(path);
    return path + "/cryptex_log.enc";
}

void MainWindow::saveLogsToFile()
{
    if (!m_tableLogs || m_tableLogs->rowCount() == 0) return;

    QJsonArray logArray;
    for (int i = 0; i < m_tableLogs->rowCount(); ++i) {
        QJsonObject entry;
        entry["time"] = m_tableLogs->item(i, 0) ? m_tableLogs->item(i, 0)->text() : "";
        entry["event"] = m_tableLogs->item(i, 1) ? m_tableLogs->item(i, 1)->text() : "";
        entry["details"] = m_tableLogs->item(i, 2) ? m_tableLogs->item(i, 2)->text() : "";
        entry["success"] = m_tableLogs->item(i, 3) ? m_tableLogs->item(i, 3)->text().contains("✅") : false;
        logArray.append(entry);
    }

    QJsonDocument doc(logArray);
    QByteArray plainData = doc.toJson(QJsonDocument::Compact);

    QByteArray encrypted = m_crypto.encryptData(plainData);
    if (encrypted.isEmpty()) {
        qWarning() << "[Log] Не удалось зашифровать журнал";
        return;
    }

    QFile file(getLogFilePath());
    if (file.open(QIODevice::WriteOnly)) {
        file.write(encrypted);
        file.close();
    }
}

void MainWindow::loadLogsFromFile()
{
    QFile file(getLogFilePath());
    if (!file.exists()) return;
    if (!file.open(QIODevice::ReadOnly)) return;

    QByteArray encrypted = file.readAll();
    file.close();

    QByteArray plainData = m_crypto.decryptData(encrypted);
    if (plainData.isEmpty()) {
        qWarning() << "[Log] Не удалось расшифровать журнал — очистка";
        file.remove();
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(plainData);
    if (!doc.isArray()) return;

    QJsonArray logArray = doc.array();
    for (const QJsonValue &val : logArray) {
        QJsonObject entry = val.toObject();
        int r = m_tableLogs->rowCount();
        m_tableLogs->insertRow(r);
        m_tableLogs->setItem(r, 0, new QTableWidgetItem(entry["time"].toString()));
        m_tableLogs->setItem(r, 1, new QTableWidgetItem(entry["event"].toString()));
        m_tableLogs->setItem(r, 2, new QTableWidgetItem(entry["details"].toString()));
        bool succ = entry["success"].toBool();
        QTableWidgetItem *st = new QTableWidgetItem(succ ? "✅ Успешно" : "❌ Ошибка");
        st->setForeground(succ ? QColor("#4CAF50") : QColor("#ff4444"));
        m_tableLogs->setItem(r, 3, st);
    }
    m_tableLogs->scrollToBottom();
}

void MainWindow::clearLogFile()
{
    QFile::remove(getLogFilePath());
}

// ────────────────────────────────────────────────────────────────────
// Управление состоянием
// ────────────────────────────────────────────────────────────────────
void MainWindow::setProcessingState(bool p)
{
    m_isProcessing = p;
    m_btnEncrypt->setEnabled(!p);
    m_btnDecrypt->setEnabled(!p);
    m_btnInput->setEnabled(!p);
    m_btnInputDir->setEnabled(!p);
    m_btnOutput->setEnabled(!p);
    m_chkDeleteSource->setEnabled(!p);
}

void MainWindow::clearCryptoFields()
{
    m_editInput->clear();
    m_editOutput->clear();
    m_editPassword->clear();
    m_selectedFiles.clear();
    m_labelMode->setText("Режим: одиночный файл");
}

void MainWindow::showSuccessNotification(const QString &title, const QString &filePath)
{
    QFileInfo fi(filePath);
    QString dir = fi.absolutePath();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(title);
    msgBox.setText(title + "!\nФайл сохранён: " + fi.fileName() + "\nПапка: " + dir);

    QPushButton *openBtn = msgBox.addButton("Открыть папку", QMessageBox::ActionRole);
    QPushButton *okBtn = msgBox.addButton("OK", QMessageBox::AcceptRole);
    msgBox.setDefaultButton(okBtn);
    msgBox.exec();

    if (msgBox.clickedButton() == openBtn) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
    }
}

bool MainWindow::isCryptexEncryptedFile(const QString &path) const
{
    if (!path.endsWith(".enc")) return false;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    char magic[9] = {0};
    f.read(magic, 8);
    f.close();
    return QString::fromLatin1(magic, 8) == "CRYPTEX01";
}

// ────────────────────────────────────────────────────────────────────
// Слоты выбора файлов
// ────────────────────────────────────────────────────────────────────
void MainWindow::onSelectInputFile()
{
    QString p = QFileDialog::getOpenFileName(this, "Выберите файл", QDir::homePath());
    if (p.isEmpty()) return;

    m_selectedFiles.clear();
    m_selectedFiles << p;
    m_editInput->setText(p);
    m_labelMode->setText("Режим: одиночный файл");

    if (p.endsWith(".enc", Qt::CaseInsensitive)) {
        QString outPath = p.left(p.length() - 4);
        m_editOutput->setText(outPath);
    } else {
        m_editOutput->setText(p + ".enc");
    }
}

void MainWindow::onSelectInputDir()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку с файлами", QDir::homePath());
    if (dir.isEmpty()) return;

    QDir d(dir);
    QStringList filters = {"*.txt", "*.doc", "*.docx", "*.pdf", "*.xls", "*.xlsx",
                           "*.ppt", "*.pptx", "*.jpg", "*.jpeg", "*.png", "*.bmp",
                           "*.mp4", "*.mp3", "*.zip", "*.rar", "*.7z",
                           "*.cpp", "*.h", "*.py", "*.java", "*.js", "*.html", "*.css", "*.json", "*.xml", "*.csv",
                           "*.enc"};

    QFileInfoList fileList = d.entryInfoList(filters, QDir::Files | QDir::NoDotAndDotDot);

    if (fileList.isEmpty()) {
        QMessageBox::information(this, "Информация", "В выбранной папке нет подходящих файлов.");
        return;
    }

    m_selectedFiles.clear();
    for (const QFileInfo &fi : fileList) {
        m_selectedFiles << fi.absoluteFilePath();
    }

    m_editInput->setText(dir + " (" + QString::number(m_selectedFiles.size()) + " файлов)");
    m_editOutput->setText(dir);
    m_labelMode->setText("Режим: папка (" + QString::number(m_selectedFiles.size()) + " файлов)");
}

void MainWindow::onSelectOutputFile()
{
    QString p;
    if (m_selectedFiles.size() > 1) {
        p = QFileDialog::getExistingDirectory(this, "Выберите папку для сохранения", QDir::homePath());
    } else {
        p = QFileDialog::getSaveFileName(this, "Сохранить как", QDir::homePath());
    }
    if (!p.isEmpty()) m_editOutput->setText(p);
}

// ────────────────────────────────────────────────────────────────────
// Шифрование / дешифрование
// ────────────────────────────────────────────────────────────────────
void MainWindow::onEncryptFile()
{
    QString pass = m_editPassword->text();

    if (m_selectedFiles.size() <= 1) {
        QString in, out;
        if (m_selectedFiles.size() == 1) {
            in = m_selectedFiles.first();
            out = m_editOutput->text().trimmed();
            if (out.isEmpty()) out = in + ".enc";
        } else {
            in = m_editInput->text().trimmed();
            out = m_editOutput->text().trimmed();
        }
        if (in.isEmpty()) { QMessageBox::warning(this, "Ошибка", "Выберите исходный файл."); return; }
        if (out.isEmpty()) out = in + ".enc";
        if (!QFile::exists(in)) { QMessageBox::warning(this, "Ошибка", "Файл не найден."); return; }

        if (isCryptexEncryptedFile(in)) {
            QMessageBox::warning(this, "Ошибка", "Файл уже зашифрован Cryptex.");
            return;
        }

        if (pass.length() < 8) { QMessageBox::warning(this, "Ошибка", "Пароль должен быть не менее 8 символов."); return; }

        setProcessingState(true);
        bool ok = m_crypto.encryptFile(in, out, pass);
        setProcessingState(false);

        if (ok) {
            showSuccessNotification("✅ Шифрование выполнено", out);
            addLogEntry("Шифрование", QFileInfo(in).fileName(), true);
            if (m_chkDeleteSource->isChecked() && QFile::exists(in)) {
                QFile::remove(in);
                addLogEntry("Удаление исходного", QFileInfo(in).fileName(), true);
            }
            clearCryptoFields();
        } else {
            QMessageBox::critical(this, "Ошибка", "Сбой шифрования.");
            addLogEntry("Ошибка шифрования", QFileInfo(in).fileName(), false);
        }
    } else {
        if (pass.length() < 8) { QMessageBox::warning(this, "Ошибка", "Пароль должен быть не менее 8 символов."); return; }

        QString outDir = m_editOutput->text().trimmed();
        if (outDir.isEmpty()) {
            QFileInfo fi(m_selectedFiles.first());
            outDir = fi.absolutePath();
        }
        QDir().mkpath(outDir);

        setProcessingState(true);
        int successCount = 0, failCount = 0;

        for (const QString &filePath : m_selectedFiles) {
            if (isCryptexEncryptedFile(filePath)) {
                failCount++;
                continue;
            }
            QFileInfo fi(filePath);
            QString outPath = outDir + "/" + fi.fileName() + ".enc";
            bool ok = m_crypto.encryptFile(filePath, outPath, pass);
            if (ok) {
                successCount++;
                addLogEntry("Шифрование", fi.fileName(), true);
                if (m_chkDeleteSource->isChecked() && QFile::exists(filePath)) {
                    QFile::remove(filePath);
                }
            } else {
                failCount++;
                addLogEntry("Ошибка шифрования", fi.fileName(), false);
            }
        }

        setProcessingState(false);

        QString msg = QString("Шифрование завершено.\nУспешно: %1\nОшибок: %2\nПапка: %3")
                          .arg(successCount).arg(failCount).arg(outDir);
        QMessageBox msgBox(this);
        msgBox.setWindowTitle("Результат шифрования");
        msgBox.setText(msg);
        QPushButton *openBtn = msgBox.addButton("Открыть папку", QMessageBox::ActionRole);
        msgBox.addButton("OK", QMessageBox::AcceptRole);
        msgBox.setStyleSheet(
            "QMessageBox { background-color: #1a1a2e; color: #fff; } "
            "QLabel { color: #fff; } "
            "QPushButton { background: #4CAF50; color: #fff; padding: 8px 16px; border-radius: 4px; } "
        );
        msgBox.exec();
        if (msgBox.clickedButton() == openBtn) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(outDir));
        }

        clearCryptoFields();
    }
}

void MainWindow::onDecryptFile()
{
    QString pass = m_editPassword->text();

    if (pass.isEmpty()) { QMessageBox::warning(this, "Ошибка", "Введите пароль."); return; }

    if (m_selectedFiles.size() <= 1) {
        QString in, out;
        if (m_selectedFiles.size() == 1) {
            in = m_selectedFiles.first();
            out = m_editOutput->text().trimmed();
        } else {
            in = m_editInput->text().trimmed();
            out = m_editOutput->text().trimmed();
        }
        if (in.isEmpty()) { QMessageBox::warning(this, "Ошибка", "Выберите исходный файл."); return; }
        if (out.isEmpty()) {
            out = in.endsWith(".enc") ? in.left(in.length() - 4) : in + ".dec";
        }
        if (!QFile::exists(in)) { QMessageBox::warning(this, "Ошибка", "Файл не найден."); return; }

        setProcessingState(true);
        bool ok = m_crypto.decryptFile(in, out, pass);
        setProcessingState(false);

        if (ok) {
            showSuccessNotification("✅ Дешифрование выполнено", out);
            addLogEntry("Дешифрование", QFileInfo(in).fileName(), true);
            if (m_chkDeleteSource->isChecked() && QFile::exists(in)) {
                QFile::remove(in);
                addLogEntry("Удаление исходного", QFileInfo(in).fileName(), true);
            }
            clearCryptoFields();
        } else {
            QMessageBox::critical(this, "Ошибка", "Сбой дешифрования.\nВозможно, неверный пароль или файл повреждён.");
            addLogEntry("Ошибка дешифрования", QFileInfo(in).fileName(), false);
        }
    } else {
        QString outDir = m_editOutput->text().trimmed();
        if (outDir.isEmpty()) {
            QFileInfo fi(m_selectedFiles.first());
            outDir = fi.absolutePath();
        }
        QDir().mkpath(outDir);

        setProcessingState(true);
        int successCount = 0, failCount = 0;

        for (const QString &filePath : m_selectedFiles) {
            QFileInfo fi(filePath);
            QString outName = fi.fileName();
            if (outName.endsWith(".enc")) outName = outName.left(outName.length() - 4);
            else outName += ".dec";
            QString outPath = outDir + "/" + outName;

            bool ok = m_crypto.decryptFile(filePath, outPath, pass);
            if (ok) {
                successCount++;
                addLogEntry("Дешифрование", fi.fileName(), true);
                if (m_chkDeleteSource->isChecked() && QFile::exists(filePath)) {
                    QFile::remove(filePath);
                }
            } else {
                failCount++;
                addLogEntry("Ошибка дешифрования", fi.fileName(), false);
            }
        }

        setProcessingState(false);

        QString msg = QString("Дешифрование завершено.\nУспешно: %1\nОшибок: %2\nПапка: %3")
                          .arg(successCount).arg(failCount).arg(outDir);
        QMessageBox msgBox(this);
        msgBox.setWindowTitle("Результат дешифрования");
        msgBox.setText(msg);
        QPushButton *openBtn = msgBox.addButton("Открыть папку", QMessageBox::ActionRole);
        msgBox.addButton("OK", QMessageBox::AcceptRole);
        msgBox.setStyleSheet(
            "QMessageBox { background-color: #1a1a2e; color: #fff; } "
            "QLabel { color: #fff; } "
            "QPushButton { background: #4CAF50; color: #fff; padding: 8px 16px; border-radius: 4px; } "
        );
        msgBox.exec();
        if (msgBox.clickedButton() == openBtn) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(outDir));
        }

        clearCryptoFields();
    }
}

// ────────────────────────────────────────────────────────────────────
// Журнал
// ────────────────────────────────────────────────────────────────────
void MainWindow::onRefreshLogs()
{
    addLogEntry("Обновление журнала", "Просмотр журнала операций", true);
}

void MainWindow::onClearLogs()
{
    if (QMessageBox::question(this, "Очистка журнала",
                              "Удалить все записи журнала?\nЭто действие необратимо.",
                              QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        m_tableLogs->setRowCount(0);
        clearLogFile();
        addLogEntry("Очистка журнала", "Журнал очищен пользователем", true);
    }
}

// ────────────────────────────────────────────────────────────────────
// Навигация
// ────────────────────────────────────────────────────────────────────
void MainWindow::onOpenSettings()
{
    SettingsDialog dlg(m_networkClient, this);
    if (dlg.exec() == QDialog::Accepted) {
        addLogEntry("Настройки", "Настройки сохранены", true);
    } else {
        addLogEntry("Настройки", "Окно настроек закрыто", true);
    }
}

void MainWindow::onLogout()
{
    if (QMessageBox::question(this, "Выход", "Завершить сеанс?") == QMessageBox::Yes) {
        addLogEntry("Выход", "Пользователь вышел из системы", true);
        saveLogsToFile();
        if (m_networkClient) m_networkClient->disconnectFromServer();
        close();
    }
}

void MainWindow::onConnectClicked()
{
    // Переход из офлайн-режима в онлайн
    if (m_networkClient) {
        if (!m_networkClient->isConnected()) {
            m_networkClient->connectToServer("127.0.0.1", 8443);
        }
        // LoginWindow показываем для авторизации
        LoginWindow login(m_networkClient, this);
        if (login.exec() == QDialog::Accepted) {
            if (!login.isOfflineMode()) {
                switchToOnlineMode(login.getUserName(), login.getUserId(), login.getSessionToken());
                m_btnLogout->setText("Выйти");
                disconnect(m_btnLogout, nullptr, this, nullptr);
                connect(m_btnLogout, &QPushButton::clicked, this, &MainWindow::onLogout);
            }
        }
    }
}

void MainWindow::onServerConnected()
{
    statusBar()->showMessage("🟢 Подключено к серверу", 5000);
    addLogEntry("Сеть", "Подключение к серверу установлено", true);
}

void MainWindow::onServerDisconnected()
{
    statusBar()->showMessage("🔴 Соединение с сервером потеряно", 5000);
    addLogEntry("Сеть", "Соединение с сервером разорвано", false);
}