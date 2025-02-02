#include "secret_key.h"
#include "ui_secret_key.h"
#include <QFileDialog>
#include <QDir>
#include <QString>
#include <QDebug>
#include <QMessageBox>

#include <QFile>
#include <QIODevice>
#include <QDesktopServices>
miyao::miyao(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::miyao)
{
    ui->setupUi(this);
}

miyao::~miyao()
{
    delete ui;
}

void miyao::on_pushButton_generate_clicked()
{
    QString path = ui->lineEdit_save_path->text();
    if(path.isEmpty())
    {
        QMessageBox::warning(this, "警告", "目录空");
        return;
    }
    QString folderPath = path + "/keypair"; // 使用正斜杠作为路径分隔符
    QDir dir(folderPath);

    if (!dir.exists()) {
        if (dir.mkpath(folderPath)) {
            qDebug() << "目录创建成功：" << folderPath;
        } else {
            QString message_failure = "目录创建失败：" + folderPath;
            QMessageBox::warning(this, "警告", message_failure);
            return ;
        }
    } else {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "确认删除", "文件夹已经存在，确定要删除该目录下的所有文件吗？",
                                      QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            // 获取目录下的所有文件和子文件夹
            QStringList files = dir.entryList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
            foreach (const QString &file, files) {
                QString filePath = dir.absoluteFilePath(file);
                if (QFileInfo(filePath).isDir()) {
                    // 如果是子文件夹，则递归删除
                    QDir subDir(filePath);
                    if (subDir.removeRecursively()) {
                        qDebug() << "已删除子文件夹：" << filePath;
                    } else {
                        QMessageBox::warning(this, "警告", "删除子文件夹失败：" + filePath + "\n错误：");
                        return ;
                    }
                } else {
                    // 如果是文件，直接删除
                    if (QFile::remove(filePath)) {
                        qDebug() << "已删除文件：" << filePath;
                    } else {
                        QMessageBox::warning(this, "警告", "删除文件失败：" + filePath + "\n错误：");
                        return ;
                    }
                }
            }
        } else {
            qDebug() << "用户取消了删除操作";
            return ;
        }
    }
    QString selectedText = ui->comboBox_bit->currentText();
    int selectedNumber = selectedText.toInt();
    if(this->createRSA(selectedNumber,folderPath))
    {
        qDebug() << "create" << folderPath << selectedNumber;
        QMessageBox::StandardButton reply_success;
        reply_success = QMessageBox::question(this, "打开", "密钥对生成成功,是否打开目录",
                                      QMessageBox::Yes | QMessageBox::No);
        if(reply_success == QMessageBox::Yes)
        {
            QString strFilePath = "file:///" + folderPath;
            QDesktopServices::openUrl(QUrl(strFilePath));
        }
    }
    else
    {
        QMessageBox::warning(this, "failure", "密钥对生成失败\n" + folderPath + "\n");
    }



}


void miyao::on_pushButton_choose_clicked()
{
    QString folderPath = QFileDialog::getExistingDirectory(
        this,            // 父窗口指针（这里为 nullptr）
        "选择文件夹",       // 对话框标题
        QDir::homePath()    // 默认路径（这里为用户的家目录）
        );

    if (!folderPath.isEmpty()) {
        ui->lineEdit_save_path->setText(folderPath);
    } else {
        QMessageBox::warning(this,"warning","没有选择文件夹");
        return;
    }
}

bool miyao::createRSA(const int num, const QString &folderPath) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();

    if (BN_set_word(bn, RSA_F4) != 1) {
        return false;  // use boolean values for return
    }

    if (RSA_generate_key_ex(rsa, num, bn, nullptr) != 1) {
        return false;
    }

    // 保存私钥
    QString privateKeyFilename = folderPath + "/private.pem";
    QFile privateKeyFile(privateKeyFilename);
    if (!privateKeyFile.open(QIODevice::WriteOnly)) {
        return false;
    }





    // Convert file descriptor to FILE* using fdopen
    FILE* privateKeyFileHandle = fdopen(privateKeyFile.handle(), "wb");
    if (privateKeyFileHandle == nullptr) {
        privateKeyFile.close();
        return false;
    }

    // Write the private key to the file
    if (PEM_write_RSAPrivateKey(privateKeyFileHandle, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        fclose(privateKeyFileHandle);
        privateKeyFile.close();
        return false;
    }

    fclose(privateKeyFileHandle);
    privateKeyFile.close();
    emit private_secret_key_path(privateKeyFilename);
    // 保存公钥
    QString publicKeyFilename = folderPath + "/public.pem";
    QFile publicKeyFile(publicKeyFilename);
    if (!publicKeyFile.open(QIODevice::WriteOnly)) {
        return false;
    }

    // Convert file descriptor to FILE* for public key
    FILE* publicKeyFileHandle = fdopen(publicKeyFile.handle(), "wb");
    if (publicKeyFileHandle == nullptr) {
        publicKeyFile.close();
        return false;
    }

    // Write the public key to the file
    if (PEM_write_RSA_PUBKEY(publicKeyFileHandle, rsa) != 1) {
        fclose(publicKeyFileHandle);
        publicKeyFile.close();
        return false;
    }

    fclose(publicKeyFileHandle);
    publicKeyFile.close();
    emit public_secret_key_path(publicKeyFilename);

    RSA_free(rsa);
    BN_free(bn);
    return true;
}

void miyao::on_pushButton_choose_public_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,           // 父窗口指针，通常为当前窗口指针
        "选择私钥",         // 对话框标题
        QDir::homePath(),      // 初始目录路径
        "密钥文件 (*.pem *.key *.cer *.crt *.pfx);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->lineEdit_choose_public->setText(fileName);
        emit private_secret_key_path(fileName);
    } else {
        // 用户取消了文件选择
        QMessageBox::critical(this, "文件选择", "您没有选择任何文件。");
    }
}
RSA* miyao::loadPrivateKey(const QString& privateKeyFilename) {
    QFile file(privateKeyFilename);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open private key file.";
        return nullptr;
    }
    QByteArray keyData = file.readAll();
    const char* keyDataPtr = keyData.constData();
    BIO* bio = BIO_new_mem_buf((void*)keyDataPtr, keyData.size());
    if (!bio) {
        qDebug() << "Failed to create BIO.";
        return nullptr;
    }
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        qDebug() << "Failed to read private key.";
    }
    return rsa;
}


bool miyao::generatePublicKey(RSA* rsa, const QString& publicKeyFilePath) {
    RSA* publicKey = RSAPublicKey_dup(rsa);  // 从私钥复制出公钥
    if (!publicKey) {
        qDebug() << "Failed to extract public key from private key.";
        return false;
    }

    // 创建一个内存 BIO 用来存储公钥
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        qDebug() << "Failed to create BIO.";
        RSA_free(publicKey);
        return false;
    }

    // 将公钥写入到 BIO 中
    if (PEM_write_bio_RSA_PUBKEY(bio, publicKey) != 1) {
        qDebug() << "Failed to write public key to BIO.";
        BIO_free(bio);
        RSA_free(publicKey);
        return false;
    }

    // 获取公钥数据的长度
    size_t pubKeyLen = BIO_pending(bio);
    QByteArray pubKeyData(pubKeyLen, Qt::Uninitialized);
    BIO_read(bio, pubKeyData.data(), pubKeyLen);
    BIO_free(bio);
    RSA_free(publicKey);

    // 构造公钥文件的路径
    QString publicKeyFilename = QDir(publicKeyFilePath).filePath("public.pem");
    if (QFile::exists(publicKeyFilename)) {
        if(!QFile::remove(publicKeyFilename))
        {
            return false;
        }

    }

    // 写入公钥数据到文件
    QFile file(publicKeyFilename);
    if (!file.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open public key file.";
        return false;
    }

    qint64 bytesWritten = file.write(pubKeyData);
    if (bytesWritten != pubKeyData.size()) {
        qDebug() << "Failed to write entire public key data.";
        return false;
    }
    emit public_secret_key_path(publicKeyFilename);
    return true;
}


void miyao::on_pushButton_genrate_public_clicked()
{
    QString privateFilePath = ui->lineEdit_choose_public->text();

    RSA* privateFile = this->loadPrivateKey(privateFilePath);
    QFileInfo fileInfo(privateFilePath);
    QString pathWithoutFileName = fileInfo.path();
    if(this->generatePublicKey(privateFile,pathWithoutFileName))
    {

        QMessageBox::StandardButton reply_success;
        reply_success = QMessageBox::question(this, "打开", "密钥对生成成功,是否打开目录",
                                              QMessageBox::Yes | QMessageBox::No);
        if(reply_success == QMessageBox::Yes)
        {
            QString strFilePath = "file:///" + pathWithoutFileName;
            QDesktopServices::openUrl(QUrl(strFilePath));
        }

    } else {
        // 公钥生成失败，显示错误消息
        QMessageBox::critical(this, "Error", "Failed to generate public key.");
    }


}

