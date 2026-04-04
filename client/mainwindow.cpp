#include "MainWindow.h"
#include "ui_MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_userId(-1)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setSessionToken(const QString &token)
{
    m_sessionToken = token;
}

void MainWindow::setUserId(int id)
{
    m_userId = id;
}
