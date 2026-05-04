#ifndef TRANSFERSTAB_H
#define TRANSFERSTAB_H

#include <QWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QJsonArray>
#include <QFileInfo>
#include <QColor>

class NetworkClient;
class ContactsTab;

class TransfersTab : public QWidget
{
    Q_OBJECT

public:
    explicit TransfersTab(NetworkClient *client, QWidget *parent = nullptr);
    ~TransfersTab() override;

    void refresh();

public slots:
    void updateContacts(const QStringList &usernames);

private slots:
    void onFileListReceived(const QJsonArray &pending, const QJsonArray &sent);
    void onSendFileClicked();
    void onDownloadClicked();
    void onCancelClicked();
    void onFileDownloadMeta(int transferId, const QString &fileName, qint64 fileSize,
                            int totalChunks, const QString &fileHash);
    void onFileDownloadChunk(int transferId, int chunkIndex, int totalChunks,
                             const QByteArray &chunkData);
    void onFileDownloadComplete(int transferId);
    void onFileSendFailed(const QString &reason);
    void onFileDownloadFailed(const QString &reason);
    void onContactSelected(int index);
    void onSelectFileClicked();
    void onCheckOnlineClicked();
    void onOnlineStatusReceived(const QString &username, bool online);

private:
    void setupUi();
    void sendFileChunks(int transferId, const QByteArray &data, const QString &fileHash);
    void updateContactCombo();
    void notifyIncomingFile(const QJsonObject &transfer);

    NetworkClient *m_client;

    // Таблицы
    QTableWidget *m_pendingTable;
    QTableWidget *m_sentTable;
    QTableWidget *m_receivedTable;

    QPushButton *m_downloadButton;
    QPushButton *m_cancelPendingBtn;

    // Отправка
    QComboBox *m_contactCombo;
    QLabel *m_onlineStatus;
    QLineEdit *m_selectedFilePath;
    QPushButton *m_selectFileButton;
    QPushButton *m_sendButton;
    QPushButton *m_checkOnlineBtn;

    QLabel *m_fileInfoLabel;

    QProgressBar *m_progressBar;
    QLabel *m_statusLabel;

    QString m_pendingFilePath;   // путь для отправки
    QString m_downloadPendingPath; // путь для сохранения скачиваемого файла
    int m_downloadTransferId;
    QString m_downloadFileName;
    qint64 m_downloadFileSize;
    QString m_downloadSender;      // отправитель скачиваемого файла
    QStringList m_receivedHistory; // история принятых файлов
};

#endif // TRANSFERSTAB_H