#ifndef CONTACTSTAB_H
#define CONTACTSTAB_H

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QTimer>
#include <QHeaderView>

class NetworkClient;

class ContactsTab : public QWidget
{
    Q_OBJECT

public:
    explicit ContactsTab(NetworkClient *client, QWidget *parent = nullptr);
    ~ContactsTab() override;

    void refreshAll();

signals:
    void contactsUpdated(const QStringList &usernames);

private slots:
    void onContactsListReceived(const QJsonArray &contacts);
    void onContactRequestsReceived(const QJsonArray &incoming, const QJsonArray &outgoing);
    void onAddContactClicked();
    void onAcceptClicked();
    void onRejectClicked();
    void onRemoveClicked();
    void onContactRequestSent();
    void onContactRequestFailed(const QString &reason);

private:
    void setupUi();

    NetworkClient *m_client;
    QTimer *m_pollTimer;

    // Контакты
    QTableWidget *m_contactsTable;
    QPushButton *m_removeButton;

    // Входящие запросы
    QTableWidget *m_incomingTable;
    QPushButton *m_acceptButton;
    QPushButton *m_rejectButton;

    // Исходящие запросы
    QTableWidget *m_outgoingTable;

    // Добавление
    QLineEdit *m_usernameInput;
    QLineEdit *m_commentInput;
    QPushButton *m_addButton;
    QPushButton *m_refreshButton;
};

#endif // CONTACTSTAB_H