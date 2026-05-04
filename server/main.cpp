#include <QCoreApplication>
#include <QTextStream>
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <QSettings>
#include <QFile>
#include <QMutex>
#include <QDateTime>
#include <QProcess>

#include "src/cryptoserver.h"
#include "src/databasemanager.h"

// ────────────────────────────────────────────────────────────────────
// Лог-файл с ротацией
// ────────────────────────────────────────────────────────────────────
static QFile      g_logFile;
static QMutex     g_logMutex;
static QString    g_logPath = "cryptex_server.log";
static int        g_maxLogSize = 10 * 1024 * 1024;  // 10 MB
static int        g_maxLogFiles = 5;

static void rotateLog()
{
    QMutexLocker lock(&g_logMutex);
    if (g_logFile.isOpen()) {
        g_logFile.close();
    }

    // Удаляем самый старый
    QString oldest = g_logPath + "." + QString::number(g_maxLogFiles);
    QFile::remove(oldest);

    // Сдвигаем: log.4 -> log.5, log.3 -> log.4, ..., log -> log.1
    for (int i = g_maxLogFiles - 1; i >= 1; --i) {
        QString src = g_logPath + (i > 1 ? ("." + QString::number(i - 1)) : "");
        QString dst = g_logPath + "." + QString::number(i);
        QFile::remove(dst);
        QFile::rename(src, dst);
    }
    // Переименовываем текущий в .1
    QString backup = g_logPath + ".1";
    QFile::remove(backup);
    QFile::rename(g_logPath, backup);

    // Открываем заново
    g_logFile.setFileName(g_logPath);
    g_logFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
}

static void logMessageHandler(QtMsgType type, const QMessageLogContext &ctx, const QString &msg)
{
    Q_UNUSED(ctx)

    QString prefix;
    switch (type) {
    case QtDebugMsg:   prefix = "[DEBUG]"; break;
    case QtInfoMsg:    prefix = "[INFO]";  break;
    case QtWarningMsg: prefix = "[WARN]";  break;
    case QtCriticalMsg:
    case QtFatalMsg:   prefix = "[ERROR]"; break;
    }

    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");
    QString line = timestamp + " " + prefix + " " + msg + "\n";

    // В stdout
    QTextStream(stdout) << line << Qt::flush;

    // В файл с ротацией
    {
        QMutexLocker lock(&g_logMutex);
        if (g_logFile.isOpen()) {
            g_logFile.write(line.toUtf8());
            g_logFile.flush();
            if (g_logFile.size() > g_maxLogSize) {
                lock.unlock();
                rotateLog();
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────────────
static QTextStream out(stdout);
static QTextStream in(stdin);

static void printBanner()
{
    out << "\n";
    out << "  ╔══════════════════════════════════════╗\n";
    out << "  ║      Cryptex Server v2.0 (beta)     ║\n";
    out << "  ║   Secure relay — files never stored  ║\n";
    out << "  ╚══════════════════════════════════════╝\n\n";
}

static void printMenu()
{
    out << "──────────────────────────────────────────\n";
    out << "  1 — Статус сервера\n";
    out << "  2 — Активные соединения\n";
    out << "  3 — Статистика БД\n";
    out << "  4 — Файлы в ОЗУ (кеш ретранслятора)\n";
    out << "  5 — Лог аудита БД (последние 20)\n";
    out << "  h — Справка\n";
    out << "  0 — Выход\n";
    out << "──────────────────────────────────────────\n";
    out << "> " << Qt::flush;
}

// ────────────────────────────────────────────────────────────────────
static QString configValue(QSettings &cfg, const QString &group, const QString &key,
                           const QString &envVar, const QString &defaultVal)
{
    // 1. Переменная окружения
    QString env = qEnvironmentVariable(envVar.toUtf8().constData());
    if (!env.isEmpty()) return env;

    // 2. Конфиг-файл
    cfg.beginGroup(group);
    QString val = cfg.value(key).toString();
    cfg.endGroup();
    if (!val.isEmpty()) return val;

    // 3. Значение по умолчанию
    return defaultVal;
}

// ────────────────────────────────────────────────────────────────────
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("Cryptex Server");
    app.setApplicationVersion("2.0.0");

    printBanner();

    // ── Поиск конфиг-файла ───────────────────────────────────────────
    // Ищем: 1) указанный через --config, 2) рядом с бинарником, 3) в ../etc/
    QString configPath;
    QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        if (args[i] == "--config" && i + 1 < args.size()) {
            configPath = args[++i];
            break;
        }
    }
    if (configPath.isEmpty()) {
        configPath = QCoreApplication::applicationDirPath() + "/server.conf";
        if (!QFileInfo::exists(configPath)) {
            configPath = "../etc/server.conf";
            if (!QFileInfo::exists(configPath)) {
                configPath.clear(); // нет конфига — ок, используем env/дефолты
            }
        }
    }

    QSettings cfg(configPath, QSettings::IniFormat);
    if (!configPath.isEmpty()) {
        out << "[CONFIG] Loading: " << configPath << "\n";
    } else {
        out << "[CONFIG] No config file found, using env/defaults\n";
    }

    // ── Параметры с приоритетом: args > env > config > default ───────
    QString dbHost   = configValue(cfg, "Database", "host", "CRYPTEX_DB_HOST", "localhost");
    int     dbPort   = configValue(cfg, "Database", "port", "CRYPTEX_DB_PORT", "5432").toInt();
    QString dbName   = configValue(cfg, "Database", "name", "CRYPTEX_DB_NAME", "cryptex");
    QString dbUser   = configValue(cfg, "Database", "user", "CRYPTEX_DB_USER", "postgres");
    QString dbPass   = configValue(cfg, "Database", "password", "CRYPTEX_DB_PASS", "1234");
    QString certPath = configValue(cfg, "Server", "ssl_cert", "CRYPTEX_CERT", "certs/ca.crt");
    QString keyPath  = configValue(cfg, "Server", "ssl_key",  "CRYPTEX_KEY",  "certs/ca.key");
    int     srvPort  = configValue(cfg, "Server", "listen_port", "CRYPTEX_PORT", "8443").toInt();
    QString srvHost  = configValue(cfg, "Server", "listen_ip",   "CRYPTEX_HOST", "0.0.0.0");
    QString logFile  = configValue(cfg, "Logging", "file", "", "cryptex_server.log");
    int     maxLogMB = configValue(cfg, "Logging", "max_size_mb", "", "10").toInt();
    int     maxLogs  = configValue(cfg, "Logging", "max_files", "", "5").toInt();

    if (!logFile.isEmpty()) g_logPath = logFile;
    if (maxLogMB >= 1) g_maxLogSize = maxLogMB * 1024 * 1024;
    if (maxLogs >= 1) g_maxLogFiles = maxLogs;

    // Переопределение через аргументы командной строки
    for (int i = 1; i < args.size(); ++i) {
        if (args[i] == "--db-host" && i + 1 < args.size()) dbHost = args[++i];
        else if (args[i] == "--db-port" && i + 1 < args.size()) dbPort = args[++i].toInt();
        else if (args[i] == "--db-name" && i + 1 < args.size()) dbName = args[++i];
        else if (args[i] == "--db-user" && i + 1 < args.size()) dbUser = args[++i];
        else if (args[i] == "--db-pass" && i + 1 < args.size()) dbPass = args[++i];
        else if (args[i] == "--cert" && i + 1 < args.size()) certPath = args[++i];
        else if (args[i] == "--key" && i + 1 < args.size()) keyPath = args[++i];
        else if (args[i] == "--port" && i + 1 < args.size()) srvPort = args[++i].toInt();
        else if (args[i] == "--config" && i + 1 < args.size()) ++i; // уже обработано
        else if (args[i] == "--help" || args[i] == "-h") {
            out << "Использование: cryptex-server [опции]\n\n";
            out << "Конфигурация (приоритет: аргументы > env > server.conf > defaults):\n";
            out << "  --config PATH    Путь к конфиг-файлу (по умолчанию: server.conf)\n";
            out << "  --db-host HOST   Хост PostgreSQL   (env: CRYPTEX_DB_HOST)\n";
            out << "  --db-port PORT   Порт PostgreSQL   (env: CRYPTEX_DB_PORT)\n";
            out << "  --db-name NAME   Имя БД            (env: CRYPTEX_DB_NAME)\n";
            out << "  --db-user USER   Пользователь БД   (env: CRYPTEX_DB_USER)\n";
            out << "  --db-pass PASS   Пароль БД         (env: CRYPTEX_DB_PASS)\n";
            out << "  --cert PATH      SSL сертификат    (env: CRYPTEX_CERT)\n";
            out << "  --key  PATH      SSL ключ          (env: CRYPTEX_KEY)\n";
            out << "  --port PORT      Порт сервера      (env: CRYPTEX_PORT)\n";
            out << "  --help, -h       Эта справка\n\n";
            out << "Формат server.conf (INI):\n";
            out << "  [Database]  host, port, name, user, password\n";
            out << "  [Server]    listen_ip, listen_port, ssl_cert, ssl_key\n";
            out << "  [Logging]   file, max_size_mb, max_files\n";
            return 0;
        }
    }

    // ── Инициализация лог-файла ──────────────────────────────────────
    {
        QDir().mkpath(QFileInfo(g_logPath).absolutePath());
        g_logFile.setFileName(g_logPath);
        if (g_logFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            qInstallMessageHandler(logMessageHandler);
            qInfo() << "Log started:" << g_logPath;
        } else {
            qWarning() << "Cannot open log file:" << g_logPath << "(logging to stdout only)";
        }
    }

    // ── SSL-сертификаты ──────────────────────────────────────────────
    bool needGenerate = false;
    if (!QFileInfo::exists(certPath)) {
        qInfo() << "SSL certificate not found:" << certPath;
        needGenerate = true;
    }
    if (!QFileInfo::exists(keyPath)) {
        qInfo() << "SSL key not found:" << keyPath;
        needGenerate = true;
    }
    if (needGenerate) {
        qInfo() << "Generating self-signed certificate...";
        QDir().mkpath(QFileInfo(certPath).absolutePath());
        int ret = QProcess::execute("openssl", {
            "req", "-x509",
            "-newkey", "rsa:4096",
            "-keyout", keyPath,
            "-out", certPath,
            "-days", "365",
            "-nodes",
            "-subj", "/CN=Cryptex"
        });
        if (ret == 0) {
            qInfo() << "Certificate generated:" << certPath;
        } else {
            qWarning() << "Failed to generate certificate (openssl not found?).";
            qWarning() << "Run manually: openssl req -x509 -newkey rsa:4096 -keyout"
                       << keyPath << "-out" << certPath << "-days 365 -nodes -subj \"/CN=Cryptex\"";
        }
    }

    // ── Подключение к БД ────────────────────────────────────────────
    qInfo() << "Connecting to PostgreSQL:" << dbHost << ":" << dbPort << "/" << dbName << "as" << dbUser;

    auto &db = DatabaseManager::getInstance();
    if (!db.connect(dbHost, dbPort, dbName, dbUser, dbPass)) {
        qCritical() << "Database connection FAILED";
        return 1;
    }
    qInfo() << "Database connected";

    // ── Запуск сервера ──────────────────────────────────────────────
    qInfo() << "Starting SSL server (RAM-only relay)...";
    CryptoServer server;
    QObject::connect(&server, &CryptoServer::serverStarted, [srvHost](quint16 port) {
        qInfo() << "Server listening on" << srvHost << ":" << port;
        qInfo() << "TLS 1.2+, RAM-only relay, no disk storage";
    });
    QObject::connect(&server, &CryptoServer::serverStopped, []() {
        qInfo() << "Server stopped";
    });
    QObject::connect(&server, &CryptoServer::clientConnected, [](const QString &ip) {
        qInfo() << "Client connected:" << ip;
    });
    QObject::connect(&server, &CryptoServer::clientDisconnected, [](const QString &ip) {
        qInfo() << "Client disconnected:" << ip;
    });

    if (!server.startServer(srvHost, static_cast<quint16>(srvPort), certPath, keyPath)) {
        qCritical() << "Failed to start server";
        return 1;
    }

    out << "[OK] Server ready. Type a command and press Enter:\n" << Qt::flush;

    // ── CLI Command Loop ─────────────────────────────────────────────
    printMenu();

    while (true) {
        app.processEvents();
        if (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.isEmpty()) {
                out << "> " << Qt::flush;
                continue;
            }

            // Команды: число 0-5 или 'h'
            if (line == "h" || line == "H" || line == "help") {
                out << "\n─── Справка ───\n";
                out << "  Сервер-ретранслятор Cryptex v2.0\n\n";
                out << "  Архитектура:\n";
                out << "    - Файлы НЕ хранятся на диске сервера\n";
                out << "    - Данные живут только в ОЗУ на время передачи\n";
                out << "    - После скачивания получателем — удаляются из кэша\n";
                out << "    - SHA-256 контроль целостности каждого файла\n\n";
                out << "  Конфигурация:\n";
                out << "    - Переменные окружения: CRYPTEX_DB_*, CRYPTEX_PORT, CRYPTEX_CERT, CRYPTEX_KEY\n";
                out << "    - Файл: server.conf рядом с бинарником\n";
                out << "    - Аргументы: --db-host, --db-port, ...\n\n";
                out << "  Логи:\n";
                out << "    - Файл: " << g_logPath << " (ротация: " << g_maxLogFiles
                     << " x " << g_maxLogSize / (1024*1024) << " MB)\n";
                out << "    - stdout + файл одновременно\n";
                out << "──────────────\n" << Qt::flush;
                printMenu();
                continue;
            }

            bool ok = false;
            int cmd = line.toInt(&ok);

            if (!ok) {
                out << "Введите число 0-5 или 'h' для справки\n> " << Qt::flush;
                continue;
            }

            switch (cmd) {
            case 1: // Status
                out << "\n─── Статус сервера ───\n";
                out << "  Запущен:       " << (server.isRunning() ? "ДА" : "НЕТ") << "\n";
                out << "  Адрес:         " << srvHost << ":" << srvPort << "\n";
                out << "  БД:            " << dbHost << ":" << dbPort << "/" << dbName << "\n";
                out << "  Хранилище:     ОЗУ (без диска)\n";
                out << "  Потоков:       " << server.activeThreadCount() << " (макс 20)\n";
                out << "  Лог-файл:      " << g_logPath << "\n";
                out << "──────────────────────\n\n> " << Qt::flush;
                break;
            case 2: // Connections
                out << "\n─── Активные соединения ───\n";
                out << "  Потоков:       " << server.activeThreadCount() << " / 20\n";
                out << "  Режим:         TLS 1.2+ (VerifyNone в beta)\n";
                out << "  Rate limit:    120 запросов/мин на клиента\n";
                out << "───────────────────────────\n\n> " << Qt::flush;
                break;
            case 3: // DB Stats
                out << "\n─── Статистика БД ───\n";
                {
                    int users = db.userCount();
                    int contacts = db.contactCount();
                    int transfers = db.transferCount();
                    int sessions = db.activeSessionCount();
                    out << "  Пользователей:     " << users << "\n";
                    out << "  Контактов:         " << contacts << "\n";
                    out << "  Передач (всего):   " << transfers << "\n";
                    out << "  Активных сессий:   " << sessions << "\n";
                }
                out << "───────────────────────\n\n> " << Qt::flush;
                break;
            case 4: // RAM cache
                out << "\n─── Файлы в ОЗУ (кеш) ───\n";
                out << "  Файлы хранятся в оперативной памяти сервера.\n";
                out << "  Жизненный цикл:\n";
                out << "    1. Отправитель загружает файл → ОЗУ\n";
                out << "    2. Получатель скачивает → ОЗУ очищается\n";
                out << "    3. Таймаут (72 ч) → автоочистка БД\n";
                out << "  На диск сервера НИЧЕГО не пишется.\n";
                out << "────────────────────────\n\n> " << Qt::flush;
                break;
            case 5: // Audit log
                out << "\n─── Лог аудита БД (последние 20) ───\n";
                {
                    auto log = db.getRecentAuditLog(20);
                    for (const auto &entry : log) {
                        out << "  " << entry << "\n";
                    }
                    if (log.isEmpty()) out << "  (нет записей)\n";
                }
                out << "────────────────────────────────────\n\n> " << Qt::flush;
                break;
            case 0:
                out << "\n[INFO] Завершение работы...\n";
                server.stopServer();
                qInfo() << "Server stopped. Goodbye.";
                {
                    QMutexLocker lock(&g_logMutex);
                    if (g_logFile.isOpen()) g_logFile.close();
                }
                return 0;
            default:
                out << "Неизвестная команда. Доступны: 0-5, h\n> " << Qt::flush;
            }
        }
    }

    return 0;
}