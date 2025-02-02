#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include <QWidget>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
namespace Ui {
class miyao;
}

class miyao : public QWidget
{
    Q_OBJECT

public:
    explicit miyao(QWidget *parent = nullptr);
    ~miyao();

private slots:
    void on_pushButton_generate_clicked();

    void on_pushButton_choose_clicked();
    bool createRSA(int num, const QString &privateKeyFilename);
    void on_pushButton_choose_public_clicked();

    void on_pushButton_genrate_public_clicked();
    RSA* loadPrivateKey(const QString& privateKeyFilename);

    bool generatePublicKey(RSA* rsa, const QString& publicKeyFilePath);
signals:
    void public_secret_key_path(const QString &path);
    void private_secret_key_path(const QString &path);


private:
    Ui::miyao *ui;
};

#endif // SECRET_KEY_H
