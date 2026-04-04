#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void setSessionToken(const QString &token);
    void setUserId(int id);

private:
    Ui::MainWindow *ui;
    QString m_sessionToken;
    int m_userId;
};

#endif // MAINWINDOW_H
