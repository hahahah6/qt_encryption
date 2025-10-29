#include "decode.h"
#include "ui_decode.h"
#include <QDebug>
#include <QFileDialog>
#include <QDir>
#include <QString>

#include <QMessageBox>

#include <QFile>
#include <QIODevice>
#include <QDesktopServices>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
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
// 加载私钥
RSA* decode::loadPrivateKey(const QString &path) {
    qDebug() << "Loading private key from:" << path;
    QString correctedPath = QDir::toNativeSeparators(path);

    QFile file(correctedPath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open private key file:" << correctedPath;
        return nullptr;
    }

    QByteArray keyData = file.readAll();
    file.close();

    if (keyData.isEmpty()) {
        qDebug() << "Private key file is empty";
        return nullptr;
    }

    // Use BIO to read key from memory buffer
    BIO* bio = BIO_new_mem_buf(keyData.constData(), keyData.size());
    if (!bio) {
        qDebug() << "Failed to create BIO for private key";
        return nullptr;
    }

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (rsa == nullptr) {
        qDebug() << "Failed to parse private key from file";
        return nullptr;
    }

    return rsa;
}

// 解密 AES 密钥
bool decode::decryptAESKey(RSA* privateKey, const unsigned char* encryptedAesKey, int aesKeyLength, unsigned char* aesKey) {
    int decryptedKeyLen = RSA_private_decrypt(aesKeyLength, encryptedAesKey, aesKey, privateKey, RSA_PKCS1_OAEP_PADDING);
    return (decryptedKeyLen == AES_BLOCK_SIZE * 2); // AES-256 密钥为 32 字节
}

void decode::on_pushButton_decode_clicked()
{
    QString privateKeyFilename = ui->lineEdit_private->text();
    QString encryptedFile = ui->lineEdit_file->text();

    // Validate input
    if (privateKeyFilename.isEmpty() || encryptedFile.isEmpty()) {
        QMessageBox::critical(this, "输入错误", "请选择私钥和加密文件");
        return;
    }

    // 加载私钥
    RSA* mPrivateKey = loadPrivateKey(privateKeyFilename);
    if (mPrivateKey == nullptr) {
        QMessageBox::critical(this, "私钥错误", "私钥加载错误");
        return;
    }

    // 打开加密文件
    QFile file(encryptedFile);
    if (!file.open(QIODevice::ReadOnly)) {
        RSA_free(mPrivateKey);
        QMessageBox::critical(this, "文件读取", "无法读取加密文件");
        return;
    }

    int ivLen;
    file.read((char*)&ivLen, sizeof(ivLen));

    // 检查 IV 长度是否有效
    if (ivLen != AES_BLOCK_SIZE) {
        file.close();
        RSA_free(mPrivateKey);
        QMessageBox::critical(this, "错误", "IV 长度无效");
        return;
    }

    // 读取 IV 数据
    unsigned char iv[AES_BLOCK_SIZE];
    file.read((char*)iv, ivLen);

    // 读取 AES 密钥的长度
    int aesKeyLength;
    file.read((char*)&aesKeyLength, sizeof(aesKeyLength));

    // Validate key length to prevent buffer overflow
    if (aesKeyLength <= 0 || aesKeyLength > 1024) {
        file.close();
        RSA_free(mPrivateKey);
        OPENSSL_cleanse(iv, sizeof(iv));
        QMessageBox::critical(this, "错误", "无效的 AES 密钥长度");
        return;
    }

    // 读取加密的 AES 密钥
    unsigned char* encryptedAesKey = new unsigned char[aesKeyLength];
    file.read((char*)encryptedAesKey, aesKeyLength);

    // 解密 AES 密钥
    unsigned char aesKey[32];  // 32 字节 = 256 位
    if (!decryptAESKey(mPrivateKey, encryptedAesKey, aesKeyLength, aesKey)) {
        delete[] encryptedAesKey;
        file.close();
        RSA_free(mPrivateKey);
        OPENSSL_cleanse(iv, sizeof(iv));
        OPENSSL_cleanse(aesKey, sizeof(aesKey));
        QMessageBox::critical(this, "错误", "私钥解密 AES 密钥失败");
        return;
    }
    delete[] encryptedAesKey;
    // 读取加密的文件数据
    QByteArray encryptedData = file.readAll();
    file.close();

    // 解密文件数据
    QByteArray decryptedData;
    decryptedData.resize(encryptedData.size());

    AES_KEY aesDecryptKey;
    if (AES_set_decrypt_key(aesKey, 256, &aesDecryptKey) < 0) {
        RSA_free(mPrivateKey);
        OPENSSL_cleanse(aesKey, sizeof(aesKey));
        OPENSSL_cleanse(iv, sizeof(iv));
        QMessageBox::critical(this, "错误", "AES 解密密钥设置失败");
        return;
    }

    // 解密
    int numBlocks = encryptedData.size() / AES_BLOCK_SIZE;
    for (int i = 0; i < numBlocks; i++) {
        AES_cbc_encrypt((unsigned char*)encryptedData.constData() + i * AES_BLOCK_SIZE,
                        (unsigned char*)decryptedData.data() + i * AES_BLOCK_SIZE,
                        AES_BLOCK_SIZE, &aesDecryptKey, iv, AES_DECRYPT);
    }

    // 获取填充字节的值
    int padding = static_cast<unsigned char>(decryptedData[decryptedData.size() - 1]);

    // 检查填充是否有效
    if (padding < 1 || padding > AES_BLOCK_SIZE) {
        RSA_free(mPrivateKey);
        OPENSSL_cleanse(aesKey, sizeof(aesKey));
        OPENSSL_cleanse(iv, sizeof(iv));
        OPENSSL_cleanse(&aesDecryptKey, sizeof(aesDecryptKey));
        QMessageBox::critical(this, "错误", "无效的填充字节");
        return;
    }

    // 检查填充字节是否正确
    for (int i = decryptedData.size() - padding; i < decryptedData.size(); ++i) {
        if (static_cast<unsigned char>(decryptedData[i]) != padding) {
            RSA_free(mPrivateKey);
            OPENSSL_cleanse(aesKey, sizeof(aesKey));
            OPENSSL_cleanse(iv, sizeof(iv));
            OPENSSL_cleanse(&aesDecryptKey, sizeof(aesDecryptKey));
            QMessageBox::critical(this, "错误", "填充字节不匹配");
            return;
        }
    }

    // 移除填充
    decryptedData.chop(padding);

    // 保存解密后的文件
    QString decryptedFile = encryptedFile;
    if (decryptedFile.endsWith(".enc")) {
        decryptedFile.chop(4);  // 去掉 ".enc" 后缀
    }

    // 创建解密后的文件并写入数据
    QFile decryptedFileOut(decryptedFile);
    if (!decryptedFileOut.open(QIODevice::WriteOnly)) {
        RSA_free(mPrivateKey);
        OPENSSL_cleanse(aesKey, sizeof(aesKey));
        OPENSSL_cleanse(iv, sizeof(iv));
        OPENSSL_cleanse(&aesDecryptKey, sizeof(aesDecryptKey));
        QMessageBox::critical(this, "错误", "无法保存解密文件");
        return;
    }

    decryptedFileOut.write(decryptedData);
    decryptedFileOut.close();

    // Clean up sensitive data and resources
    RSA_free(mPrivateKey);
    OPENSSL_cleanse(aesKey, sizeof(aesKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(&aesDecryptKey, sizeof(aesDecryptKey));

    // 提示成功
    QMessageBox::information(this, "成功", "文件解密成功！");

    // 提示用户打开解密后的文件目录
    QFileInfo fileInfo(encryptedFile);
    QString folderPath = fileInfo.absoluteDir().path();
    QMessageBox::StandardButton reply_success;
    reply_success = QMessageBox::question(this, "打开", "文件解密成功！,是否打开目录",
                                          QMessageBox::Yes | QMessageBox::No);
    if(reply_success == QMessageBox::Yes)
    {
        QString strFilePath = "file:///" + folderPath;
        QDesktopServices::openUrl(QUrl(strFilePath));
    }
}



void decode::private_secret_key_path_slot(const QString &path)
{
    ui->lineEdit_private->setText(path);
}

void decode::on_pushButton_private_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,           // 父窗口指针，通常为当前窗口指针
        "选择私钥",         // 对话框标题
        "",      // 初始目录路径
        "密钥文件 (*.pem *.key *.cer *.crt *.pfx);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->lineEdit_private->setText(fileName);
    } else {
        // 用户取消了文件选择
        QMessageBox::critical(this, "文件选择", "您没有选择任何文件。");
    }
}


void decode::on_pushButton_file_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,           // 父窗口指针，通常为当前窗口指针
        "选择私钥",         // 对话框标题
        "",      // 初始目录路径
        "加密文件 (*.enc);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->lineEdit_file->setText(fileName);
    } else {
        // 用户取消了文件选择
        QMessageBox::critical(this, "文件选择", "您没有选择任何文件。");
    }
}

