#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <QWidget>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
namespace Ui {
class jiami;
}

class jiami : public QWidget
{
    Q_OBJECT

public:
    explicit jiami(QWidget *parent = nullptr);
    ~jiami();
    RSA* loadPublicKey(const QString &path);
    bool generateAES256Key(unsigned char *key);


public slots:
    void public_secret_key_path_slot(const QString &path);

private slots:
    void on_pushButton_public_clicked();

    void on_pushButton_file_clicked();

    void on_pushButton_en_clicked();

private:
    Ui::jiami *ui;
};

#endif // ENCRYPTION_H
