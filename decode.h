#ifndef DECODE_H
#define DECODE_H

#include <QWidget>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

namespace Ui {
class decode;
}

class decode : public QWidget
{
    Q_OBJECT

public:
    explicit decode(QWidget *parent = nullptr);
    ~decode();
    RSA* loadPrivateKey(const QString &path);
    bool decryptAESKey(RSA* privateKey, const unsigned char* encryptedAesKey, int aesKeyLength, unsigned char* aesKey);

public slots:
    void private_secret_key_path_slot(const QString &path);

private slots:
    void on_pushButton_decode_clicked();

    void on_pushButton_private_clicked();

    void on_pushButton_file_clicked();

private:
    Ui::decode *ui;
};

#endif // DECODE_H
