/**
 * @file transferstab.cpp
 * @brief Вкладка передачи файлов через сервер-ретранслятор (без хранения на диске)
 * @version 2.1
 */
#include "transferstab.h"
#include "networkclient.h"

#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <QFileInfo>
#include <QHeaderView>
#include <QDebug>
#include <QStandardPaths>
#include <QDateTime>
#include <QDesktopServices>
#include <QUrl>
#include <QTimer>
#include <QApplication>
#include <QSettings>
#include <memory>
#include <openssl/sha.h>

static constexpr int CHUNK_SIZE = 1048576; // 1 MB

static QString formatFileSize(qint64 bytes)
{
    if (bytes < 1024) return QString("%1 B").arg(bytes);
    if (bytes < 1024 * 1024) return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    if (bytes < 1024 * 1024 * 1024) return QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
    return QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

TransfersTab::TransfersTab(NetworkClient *client, QWidget *parent)
    : QWidget(parent), m_client(client), m_downloadTransferId(-1)
{
    setupUi();

    connect(m_client, &NetworkClient::fileListReceived, this, &TransfersTab::onFileListReceived);
    connect(m_client, &NetworkClient::loginSuccess, this, [this](int, const QString &, const QString &) { refresh(); });
    connect(m_client, &NetworkClient::fileDownloadMeta, this, &TransfersTab::onFileDownloadMeta);
    connect(m_client, &NetworkClient::fileDownloadChunk, this, &TransfersTab::onFileDownloadChunk);
    connect(m_client, &NetworkClient::fileDownloadComplete, this, &TransfersTab::onFileDownloadComplete);
    connect(m_client, &NetworkClient::fileSendFailed, this, &TransfersTab::onFileSendFailed);
    connect(m_client, &NetworkClient::fileDownloadFailed, this, &TransfersTab::onFileDownloadFailed);
    connect(m_client, &NetworkClient::userOnlineStatus, this, &TransfersTab::onOnlineStatusReceived);
    connect(m_client, &NetworkClient::fileSendCompleteAck, this, [this]() {
        m_statusLabel->setText(tr("✅ Файл отправлен и сохранён на сервере"));
        m_progressBar->setValue(100);
        QTimer::singleShot(2000, this, [this]() { m_statusLabel->setText(tr("Готово")); });
        refresh();
    });

    // Периодический опрос списка файлов
    QTimer *pollTimer = new QTimer(this);
    pollTimer->setInterval(10000);
    connect(pollTimer, &QTimer::timeout, this, [this]() {
        if (m_client->isAuthenticated()) refresh();
    });
    pollTimer->start();
}

TransfersTab::~TransfersTab() = default;

void TransfersTab::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(12);

    // ═══════ Секция отправки ═══════
    QGroupBox *sendGroup = new QGroupBox(tr("📤 Отправка файла (сервер-ретранслятор)"), this);
    QVBoxLayout *sendLayout = new QVBoxLayout(sendGroup);
    sendLayout->setSpacing(10);
    sendLayout->setContentsMargins(12, 20, 12, 12);

    // Строка: [To: контакт▼] [🟢/🔴 статус] [Обновить онлайн]
    QHBoxLayout *contactRow = new QHBoxLayout();
    QLabel *toLabel = new QLabel(tr("Кому:"), sendGroup);
    toLabel->setStyleSheet("font-weight: bold; color: #4CAF50;");
    contactRow->addWidget(toLabel);

    m_contactCombo = new QComboBox(sendGroup);
    m_contactCombo->setMinimumWidth(160);
    m_contactCombo->setPlaceholderText(tr("Выберите контакт..."));
    connect(m_contactCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TransfersTab::onContactSelected);
    contactRow->addWidget(m_contactCombo);

    m_onlineStatus = new QLabel(tr("Выберите контакт"), sendGroup);
    m_onlineStatus->setStyleSheet("color: #888; font-size: 13px;");
    contactRow->addWidget(m_onlineStatus);

    m_checkOnlineBtn = new QPushButton(tr("🔄"), sendGroup);
    m_checkOnlineBtn->setFixedSize(36, 42);
    m_checkOnlineBtn->setToolTip(tr("Проверить онлайн"));
    m_checkOnlineBtn->setCursor(Qt::PointingHandCursor);
    connect(m_checkOnlineBtn, &QPushButton::clicked, this, &TransfersTab::onCheckOnlineClicked);
    contactRow->addWidget(m_checkOnlineBtn);

    contactRow->addStretch();
    sendLayout->addLayout(contactRow);

    // Строка: [Файл: ______] [Обзор] [Отправить]
    QHBoxLayout *fileRow = new QHBoxLayout();
    QLabel *fileLabel = new QLabel(tr("Файл:"), sendGroup);
    fileLabel->setStyleSheet("font-weight: bold; color: #4CAF50;");
    fileRow->addWidget(fileLabel);

    m_selectedFilePath = new QLineEdit(sendGroup);
    m_selectedFilePath->setReadOnly(true);
    m_selectedFilePath->setPlaceholderText(tr("Выберите файл для отправки..."));
    m_selectedFilePath->setFixedHeight(32);
    fileRow->addWidget(m_selectedFilePath);

    m_selectFileButton = new QPushButton(tr("📂 Обзор"), sendGroup);
    m_selectFileButton->setFixedHeight(42);
    m_selectFileButton->setCursor(Qt::PointingHandCursor);
    connect(m_selectFileButton, &QPushButton::clicked, this, &TransfersTab::onSelectFileClicked);
    fileRow->addWidget(m_selectFileButton);

    m_sendButton = new QPushButton(tr("🚀 Отправить"), sendGroup);
    m_sendButton->setFixedHeight(42);
    m_sendButton->setEnabled(false);
    m_sendButton->setCursor(Qt::PointingHandCursor);
    m_sendButton->setStyleSheet("QPushButton { background: #4CAF50; color: #fff; font-weight: bold; } QPushButton:hover { background: #45a049; } QPushButton:disabled { background: #444; }");
    connect(m_sendButton, &QPushButton::clicked, this, &TransfersTab::onSendFileClicked);
    fileRow->addWidget(m_sendButton);

    sendLayout->addLayout(fileRow);

    // Размер файла и режим
    m_fileInfoLabel = new QLabel(tr("Макс. 30 MB | Шифрование: AES-256-GCM поверх TLS"), sendGroup);
    m_fileInfoLabel->setStyleSheet("color: #888; font-size: 11px;");
    sendLayout->addWidget(m_fileInfoLabel);

    mainLayout->addWidget(sendGroup);

    // ═══════ Прогресс ═══════
    QHBoxLayout *statusLayout = new QHBoxLayout();
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setFixedHeight(22);
    m_progressBar->setTextVisible(true);
    statusLayout->addWidget(m_progressBar);

    m_statusLabel = new QLabel(tr("Готово"), this);
    m_statusLabel->setStyleSheet("color: #aaa; font-size: 12px;");
    statusLayout->addWidget(m_statusLabel);
    statusLayout->addStretch();
    mainLayout->addLayout(statusLayout);

    // ═══════ Таблицы ═══════
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);

    // Входящие (ожидают получения)
    QWidget *pendingWidget = new QWidget(this);
    QVBoxLayout *pendingLayout = new QVBoxLayout(pendingWidget);
    pendingLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *pendingTitle = new QLabel(tr("📥 Ожидают получения"), pendingWidget);
    pendingTitle->setStyleSheet("font-weight: bold; color: #FF9800; font-size: 13px; margin-bottom: 4px;");
    pendingLayout->addWidget(pendingTitle);

    m_pendingTable = new QTableWidget(this);
    m_pendingTable->setColumnCount(5);
    m_pendingTable->setHorizontalHeaderLabels({tr("От"), tr("Файл"), tr("Размер"), tr("Статус"), tr("Действие")});
    m_pendingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_pendingTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_pendingTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_pendingTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_pendingTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_pendingTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pendingTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_pendingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pendingTable->setAlternatingRowColors(true);
    m_pendingTable->verticalHeader()->setVisible(false);
    m_pendingTable->setMinimumHeight(160);
    pendingLayout->addWidget(m_pendingTable);

    QHBoxLayout *pendingBtnLayout = new QHBoxLayout();
    m_downloadButton = new QPushButton(tr("📥 Скачать"), pendingWidget);
    m_downloadButton->setCursor(Qt::PointingHandCursor);
    connect(m_downloadButton, &QPushButton::clicked, this, &TransfersTab::onDownloadClicked);
    pendingBtnLayout->addWidget(m_downloadButton);

    m_cancelPendingBtn = new QPushButton(tr("❌ Отменить"), pendingWidget);
    m_cancelPendingBtn->setCursor(Qt::PointingHandCursor);
    connect(m_cancelPendingBtn, &QPushButton::clicked, this, &TransfersTab::onCancelClicked);
    pendingBtnLayout->addWidget(m_cancelPendingBtn);
    pendingBtnLayout->addStretch();
    pendingLayout->addLayout(pendingBtnLayout);
    splitter->addWidget(pendingWidget);

    // Исходящие (отправленные)
    QWidget *sentWidget = new QWidget(this);
    QVBoxLayout *sentLayout = new QVBoxLayout(sentWidget);
    sentLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *sentTitle = new QLabel(tr("📤 Отправленные"), sentWidget);
    sentTitle->setStyleSheet("font-weight: bold; color: #4CAF50; font-size: 13px; margin-bottom: 4px;");
    sentLayout->addWidget(sentTitle);

    m_sentTable = new QTableWidget(this);
    m_sentTable->setColumnCount(4);
    m_sentTable->setHorizontalHeaderLabels({tr("Кому"), tr("Файл"), tr("Размер"), tr("Статус")});
    m_sentTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_sentTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_sentTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_sentTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_sentTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_sentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_sentTable->setAlternatingRowColors(true);
    m_sentTable->verticalHeader()->setVisible(false);
    m_sentTable->setMinimumHeight(100);
    sentLayout->addWidget(m_sentTable);
    splitter->addWidget(sentWidget);

    // Принятые (история загрузок)
    QWidget *receivedWidget = new QWidget(this);
    QVBoxLayout *receivedLayout = new QVBoxLayout(receivedWidget);
    receivedLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *receivedTitle = new QLabel(tr("📥 Принятые"), receivedWidget);
    receivedTitle->setStyleSheet("font-weight: bold; color: #2196F3; font-size: 13px; margin-bottom: 4px;");
    receivedLayout->addWidget(receivedTitle);

    m_receivedTable = new QTableWidget(this);
    m_receivedTable->setColumnCount(4);
    m_receivedTable->setHorizontalHeaderLabels({tr("От"), tr("Файл"), tr("Размер"), tr("Дата")});
    m_receivedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_receivedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_receivedTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_receivedTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_receivedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_receivedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_receivedTable->setAlternatingRowColors(true);
    m_receivedTable->verticalHeader()->setVisible(false);
    m_receivedTable->setMinimumHeight(100);
    receivedLayout->addWidget(m_receivedTable);
    splitter->addWidget(receivedWidget);

    mainLayout->addWidget(splitter);

    // Refresh
    QHBoxLayout *bottomLayout = new QHBoxLayout();
    QPushButton *refreshButton = new QPushButton(tr("🔄 Обновить"), this);
    refreshButton->setCursor(Qt::PointingHandCursor);
    connect(refreshButton, &QPushButton::clicked, this, [this]() { refresh(); });
    bottomLayout->addStretch();
    bottomLayout->addWidget(refreshButton);
    mainLayout->addLayout(bottomLayout);
}

void TransfersTab::refresh()
{
    m_client->getFileList();
}

void TransfersTab::onFileListReceived(const QJsonArray &pending, const QJsonArray &sent)
{
    // Входящие
    m_pendingTable->setRowCount(0);
    for (const auto &item : pending) {
        QJsonObject t = item.toObject();
        int row = m_pendingTable->rowCount();
        m_pendingTable->insertRow(row);
        m_pendingTable->setItem(row, 0, new QTableWidgetItem(t["sender_name"].toString()));
        m_pendingTable->setItem(row, 1, new QTableWidgetItem(t["file_name"].toString()));
        m_pendingTable->setItem(row, 2, new QTableWidgetItem(formatFileSize(t["file_size"].toVariant().toLongLong())));

        QString status = t["status"].toString();
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        if (status == "ready") statusItem->setForeground(QColor("#4CAF50"));
        else if (status == "uploading") statusItem->setForeground(QColor("#FF9800"));
        else statusItem->setForeground(QColor("#888"));
        m_pendingTable->setItem(row, 3, statusItem);

        // Сохраняем transfer_id и sender_name
        m_pendingTable->item(row, 0)->setData(Qt::UserRole, t["transfer_id"].toInt());
        m_pendingTable->item(row, 0)->setData(Qt::UserRole + 1, t["sender_name"].toString());
    }

    // Исходящие
    m_sentTable->setRowCount(0);
    for (const auto &item : sent) {
        QJsonObject t = item.toObject();
        int row = m_sentTable->rowCount();
        m_sentTable->insertRow(row);
        m_sentTable->setItem(row, 0, new QTableWidgetItem(t["receiver_name"].toString()));
        m_sentTable->setItem(row, 1, new QTableWidgetItem(t["file_name"].toString()));
        m_sentTable->setItem(row, 2, new QTableWidgetItem(formatFileSize(t["file_size"].toVariant().toLongLong())));

        QString status = t["status"].toString();
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        if (status == "ready") statusItem->setForeground(QColor("#4CAF50"));
        else if (status == "uploading") statusItem->setForeground(QColor("#FF9800"));
        else if (status == "completed") statusItem->setForeground(QColor("#2196F3"));
        else if (status == "cancelled") statusItem->setForeground(QColor("#ff4444"));
        else statusItem->setForeground(QColor("#888"));
        m_sentTable->setItem(row, 3, statusItem);
    }
}

void TransfersTab::onSelectFileClicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, tr("Выберите файл для отправки"),
                                                     QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    if (filePath.isEmpty()) return;

    QFileInfo fi(filePath);
    if (fi.size() > 31457280) {
        QMessageBox::critical(this, tr("Ошибка"), tr("Файл превышает лимит 30 MB"));
        return;
    }
    if (fi.size() == 0) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Нельзя отправить пустой файл"));
        return;
    }

    m_pendingFilePath = filePath;
    m_selectedFilePath->setText(filePath);
    m_fileInfoLabel->setText(tr("Размер: %1 | Шифрование: AES-256-GCM поверх TLS").arg(formatFileSize(fi.size())));

    m_sendButton->setEnabled(m_contactCombo->currentIndex() >= 0);
}

void TransfersTab::onContactSelected(int index)
{
    if (index < 0) {
        m_onlineStatus->setText(tr("Выберите контакт"));
        m_onlineStatus->setStyleSheet("color: #888; font-size: 13px;");
        m_sendButton->setEnabled(false);
        return;
    }
    m_sendButton->setEnabled(!m_pendingFilePath.isEmpty());
    // Запрашиваем онлайн-статус
    onCheckOnlineClicked();
}

void TransfersTab::onCheckOnlineClicked()
{
    if (m_contactCombo->currentIndex() < 0) return;
    QString contact = m_contactCombo->currentText();
    m_onlineStatus->setText(tr("Проверка..."));
    m_onlineStatus->setStyleSheet("color: #FF9800; font-size: 13px;");
    m_client->checkUserOnline(contact);
}

void TransfersTab::onSendFileClicked()
{
    if (m_pendingFilePath.isEmpty() || m_contactCombo->currentIndex() < 0) return;

    QFile file(m_pendingFilePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, tr("Ошибка"), tr("Не удалось открыть файл"));
        return;
    }

    QByteArray rawData = file.readAll();
    file.close();

    QFileInfo fi(m_pendingFilePath);
    QString receiver = m_contactCombo->currentText();
    QString fileName = fi.fileName();

    // SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(rawData.constData()), rawData.size(), hash);
    QString fileHash = QByteArray(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH).toHex();

    qDebug() << "[Transfers] sendFileInit ->" << receiver << fileName << fileHash << rawData.size();
    m_statusLabel->setText(tr("Отправка на сервер..."));
    m_progressBar->setValue(0);
    m_sendButton->setEnabled(false);
    m_client->sendFileInit(receiver, fileName, fileHash, rawData.size());

    // Ждём подтверждение с таймаутом
    auto conn = std::make_shared<QMetaObject::Connection>();
    auto timer = new QTimer(this);
    timer->setSingleShot(true);
    timer->setInterval(15000); // 15 сек таймаут на инициализацию

    *conn = connect(m_client, &NetworkClient::fileSendInitAck, this,
        [this, rawData, fileHash, conn, timer](int transferId) {
            qDebug() << "[Transfers] fileSendInitAck received, transferId:" << transferId;
            disconnect(*conn);
            timer->stop();
            timer->deleteLater();
            sendFileChunks(transferId, rawData, fileHash);
        }, Qt::QueuedConnection);

    // Обработка ошибки FILE_SEND_INIT
    auto errConn = std::make_shared<QMetaObject::Connection>();
    *errConn = connect(m_client, &NetworkClient::fileSendFailed, this,
        [this, conn, timer, errConn](const QString &reason) {
            qDebug() << "[Transfers] fileSendFailed (init):" << reason;
            disconnect(*conn);
            disconnect(*errConn);
            timer->stop();
            timer->deleteLater();
            QMessageBox::warning(this, tr("Ошибка отправки"), tr("Не удалось начать передачу: %1").arg(reason));
            m_statusLabel->setText(tr("Ошибка: %1").arg(reason));
            m_progressBar->setValue(0);
            m_sendButton->setEnabled(true);
        }, Qt::QueuedConnection);

    connect(timer, &QTimer::timeout, this, [this, conn, errConn, timer]() {
        qDebug() << "[Transfers] fileSendInitAck timeout";
        disconnect(*conn);
        if (errConn) disconnect(*errConn);
        m_statusLabel->setText(tr("Таймаут: сервер не отвечает"));
        m_sendButton->setEnabled(true);
        timer->deleteLater();
    });

    m_statusLabel->setText(tr("Инициализация передачи..."));
}

void TransfersTab::sendFileChunks(int transferId, const QByteArray &data, const QString &fileHash)
{
    int totalChunks = (data.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    m_progressBar->setRange(0, totalChunks);
    m_statusLabel->setText(tr("Отправка чанков: 0/%1").arg(totalChunks));

    for (int i = 0; i < totalChunks; ++i) {
        QByteArray chunk = data.mid(i * CHUNK_SIZE, CHUNK_SIZE);
        m_client->sendFileChunk(transferId, i, chunk);
        m_progressBar->setValue(i + 1);
        m_statusLabel->setText(tr("Отправка чанков: %1/%2").arg(i + 1).arg(totalChunks));
        QApplication::processEvents();
    }

    m_statusLabel->setText(tr("Завершение передачи..."));
    m_client->sendFileComplete(transferId, fileHash);
}

void TransfersTab::onDownloadClicked()
{
    int row = m_pendingTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, tr("Информация"), tr("Выберите файл для скачивания"));
        return;
    }

    QTableWidgetItem *nameItem = m_pendingTable->item(row, 1);
    if (!nameItem) return;

    QTableWidgetItem *senderItem = m_pendingTable->item(row, 0);
    int transferId = senderItem->data(Qt::UserRole).toInt();
    m_downloadSender = senderItem->data(Qt::UserRole + 1).toString();
    QString fileName = nameItem->text();

    QString savePath = QFileDialog::getSaveFileName(this, tr("Сохранить как"),
                                                     QStandardPaths::writableLocation(QStandardPaths::DownloadLocation) + "/" + fileName);
    if (savePath.isEmpty()) return;

    m_downloadPendingPath = savePath;
    m_pendingFilePath = savePath;

    QFile f(savePath);
    if (f.exists()) f.remove();

    // Сохраняем путь для последующей сборки
    QSettings s;
    s.setValue("transfers/last_download", savePath);

    m_client->downloadFile(transferId);
    m_statusLabel->setText(tr("Загрузка файла..."));
    m_progressBar->setValue(0);
}

void TransfersTab::onCancelClicked()
{
    int row = m_pendingTable->currentRow();
    if (row < 0) return;

    QTableWidgetItem *item = m_pendingTable->item(row, 0);
    if (!item) return;

    int transferId = item->data(Qt::UserRole).toInt();
    m_client->cancelTransfer(transferId);
    m_statusLabel->setText(tr("Передача отменена"));
    QTimer::singleShot(1500, this, [this]() { refresh(); });
}

void TransfersTab::onFileDownloadMeta(int transferId, const QString &fileName,
                                       qint64 fileSize, int totalChunks, const QString &fileHash)
{
    Q_UNUSED(transferId)
    Q_UNUSED(fileHash)
    m_downloadFileName = fileName;
    m_downloadFileSize = fileSize;
    m_downloadTransferId = transferId;
    m_progressBar->setRange(0, totalChunks);
    m_progressBar->setValue(0);
    m_statusLabel->setText(tr("Загрузка: %1 (%2)").arg(fileName).arg(formatFileSize(fileSize)));
}

void TransfersTab::onFileDownloadChunk(int transferId, int chunkIndex, int totalChunks,
                                        const QByteArray &chunkData)
{
    Q_UNUSED(transferId)
    // Пишем чанк в файл
    if (!m_downloadPendingPath.isEmpty()) {
        QFile f(m_downloadPendingPath);
        if (f.open(QIODevice::Append)) {
            f.write(chunkData);
            f.close();
        }
    }
    m_progressBar->setValue(chunkIndex + 1);
    m_statusLabel->setText(tr("Загрузка: %1/%2 чанков").arg(chunkIndex + 1).arg(totalChunks));
}

void TransfersTab::onFileDownloadComplete(int transferId)
{
    Q_UNUSED(transferId)
    m_statusLabel->setText(tr("✅ Файл сохранён: %1").arg(m_downloadFileName));
    m_progressBar->setValue(100);

    // Запись в историю принятых
    if (!m_downloadPendingPath.isEmpty() && m_receivedTable) {
        QFileInfo fi(m_downloadPendingPath);
        int row = m_receivedTable->rowCount();
        m_receivedTable->insertRow(row);
        m_receivedTable->setItem(row, 0, new QTableWidgetItem(m_downloadSender));
        m_receivedTable->setItem(row, 1, new QTableWidgetItem(m_downloadFileName));
        m_receivedTable->setItem(row, 2, new QTableWidgetItem(formatFileSize(m_downloadFileSize)));
        m_receivedTable->setItem(row, 3, new QTableWidgetItem(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm")));

        // Открыть папку
        QString msg = tr("Файл сохранён:\n%1\n\nОткрыть папку?").arg(m_downloadPendingPath);
        if (QMessageBox::question(this, tr("Загрузка завершена"), msg) == QMessageBox::Yes) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(fi.absolutePath()));
        }
    }

    refresh();
    m_downloadPendingPath.clear();
}

void TransfersTab::onFileSendFailed(const QString &reason)
{
    qDebug() << "[Transfers] File send FAILED:" << reason;
    m_statusLabel->setText(tr("❌ Ошибка: %1").arg(reason));
    m_statusLabel->setStyleSheet("color: #ff4444; font-size: 12px;");
    m_progressBar->setValue(0);
    QTimer::singleShot(5000, this, [this]() {
        m_statusLabel->setText(tr("Готово"));
        m_statusLabel->setStyleSheet("color: #aaa; font-size: 12px;");
    });
}

void TransfersTab::onFileDownloadFailed(const QString &reason)
{
    m_statusLabel->setText(tr("❌ Ошибка загрузки: %1").arg(reason));
    m_progressBar->setValue(0);
}

void TransfersTab::onOnlineStatusReceived(const QString &username, bool online)
{
    if (m_contactCombo->currentText() != username) return;
    if (online) {
        m_onlineStatus->setText(tr("🟢 Онлайн"));
        m_onlineStatus->setStyleSheet("color: #4CAF50; font-size: 13px; font-weight: bold;");
    } else {
        m_onlineStatus->setText(tr("🔴 Офлайн (файл дойдёт при следующем подключении)"));
        m_onlineStatus->setStyleSheet("color: #ff4444; font-size: 13px;");
    }
}

void TransfersTab::updateContacts(const QStringList &usernames)
{
    m_contactCombo->clear();
    m_contactCombo->addItems(usernames);
}
