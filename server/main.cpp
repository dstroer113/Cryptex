#include <QCoreApplication>
#include <QTextStream>
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <QProcess>

#include "src/cryptoserver.h"
#include "src/databasemanager.h"

// ────────────────────────────────────────────────────────────────────
static QTextStream out(stdout);
static QTextStream in(stdin);

static void printBanner()
{
    out << "\n";
    out << "  ╔══════════════════════════════════╗\n";
    out << "  ║       Cryptex Server v2.0       ║\n";
    out << "  ╚══════════════════════════════════╝\n\n";
}

static void printMenu()
{
    out << "──────────────────────────────────────────\n";
    out << "  1 — Статус сервера\n";
    out << "  2 — Активные соединения\n";
    out << "  3 — Статистика БД\n";
    out << "  4 — Хранилище файлов\n";
    out << "  5 — Очистка старых файлов (>30 дн)\n";
    out << "  6 — Лог аудита (последние 20 записей)\n";
    out << "  0 — Выход\n";
    out << "──────────────────────────────────────────\n";
    out << "> " << Qt::flush;
}

// ────────────────────────────────────────────────────────────────────
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("Cryptex Server");
    app.setApplicationVersion("2.0.0");

    printBanner();

    // ── Параметры по умолчанию ──────────────────────────────────────
    QString dbHost   = qEnvironmentVariable("CRYPTEX_DB_HOST", "localhost");
    int     dbPort   = qEnvironmentVariable("CRYPTEX_DB_PORT", "5432").toInt();
    QString dbName   = qEnvironmentVariable("CRYPTEX_DB_NAME", "cryptex");
    QString dbUser   = qEnvironmentVariable("CRYPTEX_DB_USER", "postgres");
    QString dbPass   = qEnvironmentVariable("CRYPTEX_DB_PASS", "1234");
    QString certPath = qEnvironmentVariable("CRYPTEX_CERT", "certs/ca.crt");
    QString keyPath  = qEnvironmentVariable("CRYPTEX_KEY",  "certs/ca.key");
    int     srvPort  = qEnvironmentVariable("CRYPTEX_PORT", "8443").toInt();
    QString srvHost  = qEnvironmentVariable("CRYPTEX_HOST", "0.0.0.0");

    // Можно переопределить через аргументы (простейший парсинг)
    QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        if (args[i] == "--db-host" && i + 1 < args.size()) dbHost = args[++i];
        else if (args[i] == "--db-port" && i + 1 < args.size()) dbPort = args[++i].toInt();
        else if (args[i] == "--db-name" && i + 1 < args.size()) dbName = args[++i];
        else if (args[i] == "--db-user" && i + 1 < args.size()) dbUser = args[++i];
        else if (args[i] == "--db-pass" && i + 1 < args.size()) dbPass = args[++i];
        else if (args[i] == "--cert" && i + 1 < args.size()) certPath = args[++i];
        else if (args[i] == "--key" && i + 1 < args.size()) keyPath = args[++i];
        else if (args[i] == "--port" && i + 1 < args.size()) srvPort = args[++i].toInt();
        else if (args[i] == "--help") {
            out << "Usage: cryptex-server [options]\n";
            out << "  --db-host HOST   (default: localhost, env: CRYPTEX_DB_HOST)\n";
            out << "  --db-port PORT   (default: 5432,   env: CRYPTEX_DB_PORT)\n";
            out << "  --db-name NAME   (default: cryptex, env: CRYPTEX_DB_NAME)\n";
            out << "  --db-user USER   (default: cryptex_admin)\n";
            out << "  --db-pass PASS   (env: CRYPTEX_DB_PASS)\n";
            out << "  --cert PATH      (default: certs/ca.crt)\n";
            out << "  --key  PATH      (default: certs/ca.key)\n";
            out << "  --port PORT      (default: 8443,   env: CRYPTEX_PORT)\n";
            out << "  --help\n";
            return 0;
        }
    }

    // ── Создание SSL-сертификатов через openssl, если отсутствуют ──
    bool needGenerate = false;
    if (!QFileInfo::exists(certPath)) {
        out << "[WARNING] SSL certificate not found: " << certPath << "\n";
        needGenerate = true;
    }
    if (!QFileInfo::exists(keyPath)) {
        out << "[WARNING] SSL key not found: " << keyPath << "\n";
        needGenerate = true;
    }
    if (needGenerate) {
        out << "[INFO] Generating self-signed certificate...\n";
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
            out << "[OK] Certificate generated: " << certPath << "\n\n";
        } else {
            out << "[WARNING] Failed to generate certificate (openssl not found?).\n";
            out << "  Run manually:\n";
            out << "    cd server\n";
            out << "    mkdir certs 2>nul\n";
            out << "    openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj \"/CN=Cryptex\"\n\n";
        }
    }

    // ── Подключение к БД ────────────────────────────────────────────
    out << "[1/3] Connecting to PostgreSQL...\n";
    out << "      Host: " << dbHost << ":" << dbPort << ", DB: " << dbName << ", User: " << dbUser << "\n";

    auto &db = DatabaseManager::getInstance();
    if (!db.connect(dbHost, dbPort, dbName, dbUser, dbPass)) {
        out << "[ERROR] Database connection FAILED. Check credentials and ensure PostgreSQL is running.\n";
        return 1;
    }
    out << "[OK]   Database connected\n\n";

    // ── Запуск сервера ──────────────────────────────────────────────
    out << "[2/3] Starting SSL server (RAM-only relay)...\n";
    CryptoServer server;
    QObject::connect(&server, &CryptoServer::serverStarted, [srvHost](quint16 port) {
        out << "[OK]   Server listening on " << srvHost << ":" << port << "\n";
        out << "      TLS 1.2+, bcrypt auth, rate limiting active\n";
        out << "      Thread pool: 20 workers\n\n";
        out << "[READY] Type a command number and press Enter:\n" << Qt::flush;
    });
    QObject::connect(&server, &CryptoServer::serverStopped, []() {
        out << "[INFO] Server stopped.\n" << Qt::flush;
    });
    QObject::connect(&server, &CryptoServer::clientConnected, [](const QString &ip) {
        out << "[CONNECT] Client connected: " << ip << "\n" << Qt::flush;
    });
    QObject::connect(&server, &CryptoServer::clientDisconnected, [](const QString &ip) {
        Q_UNUSED(ip)
        out << "[DISCONNECT] Client disconnected\n" << Qt::flush;
    });
    // Логи из ClientHandler'ов собираем через qDebug
    qInstallMessageHandler([](QtMsgType type, const QMessageLogContext &ctx, const QString &msg) {
        Q_UNUSED(ctx)
        QString prefix;
        switch (type) {
        case QtDebugMsg:   prefix = "[DEBUG]"; break;
        case QtInfoMsg:    prefix = "[INFO]";  break;
        case QtWarningMsg: prefix = "[WARN]";  break;
        case QtCriticalMsg:
        case QtFatalMsg:   prefix = "[ERROR]"; break;
        }
        QTextStream logOut(stdout);
        logOut << prefix << " " << msg << "\n" << Qt::flush;
    });

    if (!server.startServer(srvHost, static_cast<quint16>(srvPort), certPath, keyPath)) {
        out << "[ERROR] Failed to start server. Check SSL cert/key and port availability.\n";
        return 1;
    }

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

            bool ok = false;
            int cmd = line.toInt(&ok);

            if (!ok) {
                out << "Invalid input. Enter a number:\n> " << Qt::flush;
                continue;
            }

            switch (cmd) {
            case 1: // Status
                out << "\n─── Server Status ───\n";
                out << "  Running: " << (server.isRunning() ? "YES" : "NO") << "\n";
                out << "  Host:    " << srvHost << ":" << srvPort << "\n";
                out << "  DB:      " << dbHost << ":" << dbPort << "/" << dbName << "\n";
                out << "  Storage: RAM-only (no disk)\n";
                out << "─────────────────────\n\n> " << Qt::flush;
                break;
            case 2: // Connections — приблизительно через thread pool
                out << "\n─── Active Connections ───\n";
                out << "  Thread pool active: " << server.activeThreadCount() << "\n";
                out << "  Max threads: 20\n";
                out << "──────────────────────────\n\n> " << Qt::flush;
                break;
            case 3: // DB Stats
                out << "\n─── Database Stats ───\n";
                {
                    int users = db.userCount();
                    int contacts = db.contactCount();
                    int transfers = db.transferCount();
                    int sessions = db.activeSessionCount();
                    out << "  Users:     " << users << "\n";
                    out << "  Contacts:  " << contacts << "\n";
                    out << "  Transfers: " << transfers << "\n";
                    out << "  Sessions:  " << sessions << "\n";
                }
                out << "──────────────────────\n\n> " << Qt::flush;
                break;
            case 4: // Storage
                out << "\n─── File Storage ───\n";
                out << "  Mode: RAM-only relay (no disk)\n";
                out << "  Files live only during active transfer\n";
                out << "────────────────────\n\n> " << Qt::flush;
                break;
            case 5: // Cleanup
                out << "[OK] RAM-only mode — cleanup not needed.\n> " << Qt::flush;
                break;
            case 6: // Audit log
                out << "\n─── Recent Audit Log (last 20) ───\n";
                {
                    auto log = db.getRecentAuditLog(20);
                    for (const auto &entry : log) {
                        out << "  " << entry << "\n";
                    }
                    if (log.isEmpty()) out << "  (no records)\n";
                }
                out << "───────────────────────────────────\n\n> " << Qt::flush;
                break;
            case 0:
                out << "\n[INFO] Shutting down...\n";
                server.stopServer();
                out << "[OK] Server stopped. Goodbye.\n";
                return 0;
            default:
                out << "Unknown command. Available: 0-6\n> " << Qt::flush;
            }
        }
    }

    return 0;
}
