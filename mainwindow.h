#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <secret_key.h>
#include <decode.h>
#include <encryption.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


private slots:

    void go_back_secret_key_page();
    void go_back_decode_page();
    void go_back_encryption();


private:
    Ui::MainWindow *ui;
    miyao *mM;
    decode *mD;
    jiami *mE;

};
#endif // MAINWINDOW_H
