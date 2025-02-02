#include "encryption.h"
#include "ui_encryption.h"

jiami::jiami(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::jiami)
{
    ui->setupUi(this);
}

jiami::~jiami()
{
    delete ui;
}
