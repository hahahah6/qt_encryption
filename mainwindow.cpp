#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("encryption");
    this->setWindowIcon(QIcon(":/favicon.ico"));
    mM = new miyao;
    mD = new decode;
    mE = new jiami;

    ui->stackedWidget->addWidget(mM);
    ui->stackedWidget->addWidget(mD);
    ui->stackedWidget->addWidget(mE);
    ui->stackedWidget->setCurrentIndex(3);
    connect(ui->action_mi,&QAction::triggered,this,&MainWindow::go_back_secret_key_page);
    connect(ui->action_jie,&QAction::triggered,this,&MainWindow::go_back_decode_page);
    connect(ui->action_jia,&QAction::triggered,this,&MainWindow::go_back_encryption);


    connect(mM,&miyao::public_secret_key_path,mE,&jiami::public_secret_key_path_slot);
    connect(mM,&miyao::private_secret_key_path,mD,&decode::private_secret_key_path_slot);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::go_back_secret_key_page()
{
    ui->stackedWidget->setCurrentIndex(2);
}
void MainWindow::go_back_decode_page()
{
    ui->stackedWidget->setCurrentIndex(3);
}
void MainWindow::go_back_encryption()
{
    ui->stackedWidget->setCurrentIndex(4);
}
