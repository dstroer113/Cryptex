#include "contactstab.h"
#include "networkclient.h"

#include <QMessageBox>
#include <QInputDialog>
#include <QSplitter>
#include <QHeaderView>
#include <QDebug>
#include <QTimer>

ContactsTab::ContactsTab(NetworkClient *client, QWidget *parent)
    : QWidget(parent), m_client(client)
{
    setupUi();

    connect(m_client, &NetworkClient::contactsListReceived, this, &ContactsTab::onContactsListReceived);
    connect(m_client, &NetworkClient::contactRequestsReceived, this, &ContactsTab::onContactRequestsReceived);
    connect(m_client, &NetworkClient::contactAdded, this, &ContactsTab::onContactRequestSent);
    connect(m_client, &NetworkClient::contactAccepted, this, [this]() { refreshAll(); });
    connect(m_client, &NetworkClient::contactRejected, this, [this]() { refreshAll(); });
    connect(m_client, &NetworkClient::contactRemoved, this, [this]() { refreshAll(); });
    connect(m_client, &NetworkClient::contactRequestFailed, this, &ContactsTab::onContactRequestFailed);
    // Обработка ошибок accept/reject
    connect(m_client, &NetworkClient::errorOccurred, this, [this](const QString &reason) {
        if (reason.contains("Invalid request") || reason.contains("Contact")) {
            QMessageBox::warning(this, tr("Operation Failed"), reason);
            refreshAll(); // перезапрашиваем списки для синхронизации
        }
    });

    // Авто-опрос входящих запросов (пока нет push от сервера)
    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(5000);
    connect(m_pollTimer, &QTimer::timeout, this, [this]() {
        if (m_client->isAuthenticated()) {
            m_client->getContactRequests();
        }
    });
    m_pollTimer->start();

    if (m_client->isAuthenticated()) {
        refreshAll();
    }
}

ContactsTab::~ContactsTab() = default;

void ContactsTab::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // ── Секция "Добавить контакт"
    QGroupBox *addGroup = new QGroupBox(tr("Add Contact"), this);
    QHBoxLayout *addLayout = new QHBoxLayout(addGroup);

    addLayout->addWidget(new QLabel(tr("Username:"), this));
    m_usernameInput = new QLineEdit(this);
    m_usernameInput->setPlaceholderText(tr("Enter username"));
    m_usernameInput->setFixedHeight(32);
    addLayout->addWidget(m_usernameInput);

    addLayout->addWidget(new QLabel(tr("Message:"), this));
    m_commentInput = new QLineEdit(this);
    m_commentInput->setPlaceholderText(tr("Optional comment"));
    m_commentInput->setFixedHeight(32);
    addLayout->addWidget(m_commentInput);

    m_addButton = new QPushButton(tr("Send Request"), this);
    m_addButton->setFixedHeight(32);
    connect(m_addButton, &QPushButton::clicked, this, &ContactsTab::onAddContactClicked);
    addLayout->addWidget(m_addButton);

    m_refreshButton = new QPushButton(tr("Refresh"), this);
    m_refreshButton->setFixedHeight(32);
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAll(); });
    addLayout->addWidget(m_refreshButton);

    mainLayout->addWidget(addGroup);

    // ── Splitter: контакты | входящие/исходящие
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);

    // Мои контакты
    QWidget *contactsWidget = new QWidget(this);
    QVBoxLayout *contactsLayout = new QVBoxLayout(contactsWidget);
    contactsLayout->setContentsMargins(0, 0, 0, 0);
    contactsLayout->addWidget(new QLabel(tr("<b>My Contacts</b>"), this));

    m_contactsTable = new QTableWidget(this);
    m_contactsTable->setColumnCount(2);
    m_contactsTable->setHorizontalHeaderLabels({tr("Username"), tr("User ID")});
    m_contactsTable->horizontalHeader()->setStretchLastSection(true);
    m_contactsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_contactsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_contactsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_contactsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_contactsTable->setAlternatingRowColors(true);
    m_contactsTable->verticalHeader()->setVisible(false);
    m_contactsTable->setMinimumHeight(150);
    contactsLayout->addWidget(m_contactsTable);

    m_removeButton = new QPushButton(tr("Remove Selected"), this);
    connect(m_removeButton, &QPushButton::clicked, this, &ContactsTab::onRemoveClicked);
    contactsLayout->addWidget(m_removeButton);

    splitter->addWidget(contactsWidget);

    // Входящие запросы
    QWidget *incomingWidget = new QWidget(this);
    QVBoxLayout *incomingLayout = new QVBoxLayout(incomingWidget);
    incomingLayout->setContentsMargins(0, 0, 0, 0);
    incomingLayout->addWidget(new QLabel(tr("<b>Incoming Requests</b>"), this));

    m_incomingTable = new QTableWidget(this);
    m_incomingTable->setColumnCount(3);
    m_incomingTable->setHorizontalHeaderLabels({tr("From"), tr("Comment"), tr("Request ID")});
    m_incomingTable->horizontalHeader()->setStretchLastSection(true);
    m_incomingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_incomingTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_incomingTable->setColumnHidden(2, true); // скрываем ID
    m_incomingTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_incomingTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_incomingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_incomingTable->setAlternatingRowColors(true);
    m_incomingTable->verticalHeader()->setVisible(false);
    m_incomingTable->setMinimumHeight(120);
    incomingLayout->addWidget(m_incomingTable);

    QHBoxLayout *incomingBtnLayout = new QHBoxLayout();
    m_acceptButton = new QPushButton(tr("Accept"), this);
    connect(m_acceptButton, &QPushButton::clicked, this, &ContactsTab::onAcceptClicked);
    incomingBtnLayout->addWidget(m_acceptButton);

    m_rejectButton = new QPushButton(tr("Reject"), this);
    connect(m_rejectButton, &QPushButton::clicked, this, &ContactsTab::onRejectClicked);
    incomingBtnLayout->addWidget(m_rejectButton);
    incomingLayout->addLayout(incomingBtnLayout);

    splitter->addWidget(incomingWidget);

    // Исходящие запросы
    QWidget *outgoingWidget = new QWidget(this);
    QVBoxLayout *outgoingLayout = new QVBoxLayout(outgoingWidget);
    outgoingLayout->setContentsMargins(0, 0, 0, 0);
    outgoingLayout->addWidget(new QLabel(tr("<b>Outgoing Requests</b>"), this));

    m_outgoingTable = new QTableWidget(this);
    m_outgoingTable->setColumnCount(2);
    m_outgoingTable->setHorizontalHeaderLabels({tr("To"), tr("Comment")});
    m_outgoingTable->horizontalHeader()->setStretchLastSection(true);
    m_outgoingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_outgoingTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_outgoingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_outgoingTable->setAlternatingRowColors(true);
    m_outgoingTable->verticalHeader()->setVisible(false);
    m_outgoingTable->setMinimumHeight(100);
    outgoingLayout->addWidget(m_outgoingTable);

    splitter->addWidget(outgoingWidget);

    mainLayout->addWidget(splitter);
}

void ContactsTab::refreshAll()
{
    m_client->getContactsList();
    m_client->getContactRequests();
}

void ContactsTab::onContactsListReceived(const QJsonArray &contacts)
{
    m_contactsTable->setRowCount(0);
    QStringList usernames;
    for (const auto &c : contacts) {
        QJsonObject entry = c.toObject();
        int row = m_contactsTable->rowCount();
        m_contactsTable->insertRow(row);
        QString name = entry["username"].toString();
        m_contactsTable->setItem(row, 0, new QTableWidgetItem(name));
        m_contactsTable->setItem(row, 1, new QTableWidgetItem(QString::number(entry["user_id"].toInt())));
        usernames << name;
    }
    emit contactsUpdated(usernames);
}

void ContactsTab::onContactRequestsReceived(const QJsonArray &incoming, const QJsonArray &outgoing)
{
    // Входящие
    m_incomingTable->setRowCount(0);
    for (const auto &r : incoming) {
        QJsonObject entry = r.toObject();
        int row = m_incomingTable->rowCount();
        m_incomingTable->insertRow(row);
        m_incomingTable->setItem(row, 0, new QTableWidgetItem(entry["sender_name"].toString()));
        m_incomingTable->setItem(row, 1, new QTableWidgetItem(entry["comment"].toString()));
        m_incomingTable->setItem(row, 2, new QTableWidgetItem(QString::number(entry["id"].toInt())));
    }

    // Исходящие
    m_outgoingTable->setRowCount(0);
    for (const auto &r : outgoing) {
        QJsonObject entry = r.toObject();
        int row = m_outgoingTable->rowCount();
        m_outgoingTable->insertRow(row);
        m_outgoingTable->setItem(row, 0, new QTableWidgetItem(entry["receiver_name"].toString()));
        m_outgoingTable->setItem(row, 1, new QTableWidgetItem(entry["comment"].toString()));
    }
}

void ContactsTab::onAddContactClicked()
{
    QString username = m_usernameInput->text().trimmed();
    if (username.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Enter username"));
        return;
    }

    QString comment = m_commentInput->text().trimmed().left(500);
    m_client->sendContactRequest(username, comment);
    m_usernameInput->clear();
    m_commentInput->clear();
}

void ContactsTab::onAcceptClicked()
{
    QTableWidgetItem *current = m_incomingTable->currentItem();
    if (!current) {
        QMessageBox::information(this, tr("Info"), tr("Select a request to accept"));
        return;
    }
    int row = current->row();
    QTableWidgetItem *idItem = m_incomingTable->item(row, 2); // Request ID в скрытой колонке
    if (!idItem) return;
    int requestId = idItem->text().toInt();
    m_client->acceptContactRequest(requestId);
}

void ContactsTab::onRejectClicked()
{
    QTableWidgetItem *current = m_incomingTable->currentItem();
    if (!current) {
        QMessageBox::information(this, tr("Info"), tr("Select a request to reject"));
        return;
    }
    int row = current->row();
    QTableWidgetItem *idItem = m_incomingTable->item(row, 2);
    if (!idItem) return;
    int requestId = idItem->text().toInt();
    m_client->rejectContactRequest(requestId);
}

void ContactsTab::onRemoveClicked()
{
    int row = m_contactsTable->currentRow();
    if (row < 0) {
        QMessageBox::information(this, tr("Info"), tr("Select a contact to remove"));
        return;
    }
    QString username = m_contactsTable->item(row, 0)->text();
    if (QMessageBox::question(this, tr("Confirm"),
                              tr("Remove %1 from contacts?").arg(username)) == QMessageBox::Yes) {
        m_client->removeContact(username);
    }
}

void ContactsTab::onContactRequestSent()
{
    QMessageBox::information(this, tr("Success"), tr("Contact request sent"));
    refreshAll();
}

void ContactsTab::onContactRequestFailed(const QString &reason)
{
    QMessageBox::warning(this, tr("Request Failed"), reason);
}