#include "decode.h"
#include "ui_decode.h"

decode::decode(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::decode)
{
    ui->setupUi(this);
}

decode::~decode()
{
    delete ui;
}

void decode::on_pushButton_decode_clicked()
{

}

