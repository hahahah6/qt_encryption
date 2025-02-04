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
    qDebug() << path;
    QString correctedPath = QDir::toNativeSeparators(path);
    qDebug() << correctedPath;

    QFile file(correctedPath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open private key file.";
        return nullptr;
    }

    FILE* filePointer = fdopen(file.handle(), "r");
    if (filePointer == nullptr) {
        qDebug() << "Failed to convert file handle to FILE*";
        return nullptr;
    }

    RSA* rsa = PEM_read_RSAPrivateKey(filePointer, nullptr, nullptr, nullptr);
    fclose(filePointer);

    if (rsa == nullptr) {
        qDebug() << "Failed to load private key.";
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

    // 加载私钥
    RSA* mPrivateKey = loadPrivateKey(privateKeyFilename);
    if (mPrivateKey == nullptr) {
        QMessageBox::critical(this, "私钥错误", "私钥加载错误");
        return;
    }

    // 打开加密文件
    QFile file(encryptedFile);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "文件读取", "无法读取加密文件");
        return;
    }

    int ivLen;
    file.read((char*)&ivLen, sizeof(ivLen));  // 读取 IV 长度
    // qDebug() << "读取 IV 长度: " << ivLen;

    // 检查 IV 长度是否有效
    if (ivLen != AES_BLOCK_SIZE) {
        QMessageBox::critical(this, "错误", "IV 长度无效");
        return;
    }

    // 动态分配内存读取 IV 数据
    unsigned char iv[AES_BLOCK_SIZE];
    file.read((char*)iv, ivLen);  // 根据读取的长度读取 IV 数据

    // // 打印读取的 IV 数据
    // qDebug() << "读取的 IV 数据: ";
    // for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    //     qDebug() << QString("%1 ").arg(iv[i], 2, 16, QLatin1Char('0'));  // 打印 IV 数据
    // }

    // 读取 AES 密钥的长度
    int aesKeyLength;
    file.read((char*)&aesKeyLength, sizeof(aesKeyLength));
    // qDebug() << "读取 AES 密钥长度: " << aesKeyLength;

    // 读取加密的 AES 密钥
    unsigned char encryptedAesKey[aesKeyLength];
    file.read((char*)encryptedAesKey, aesKeyLength);

    // // 打印读取的 AES 密钥
    // qDebug() << "读取加密的 AES 密钥: ";
    // for (int i = 0; i < aesKeyLength; i++) {
    //     qDebug() << QString("%1 ").arg(encryptedAesKey[i], 2, 16, QLatin1Char('0'));
    // }

    // 解密 AES 密钥
    unsigned char aesKey[32];  // 32 字节 = 256 位
    if (!decryptAESKey(mPrivateKey, encryptedAesKey, aesKeyLength, aesKey)) {
        QMessageBox::critical(this, "错误", "私钥解密 AES 密钥失败");
        return;
    }
    // 读取加密的文件数据
    QByteArray encryptedData = file.readAll();
    file.close();

    // // 打印读取的加密文件数据
    // qDebug() << "读取加密的文件数据: ";
    // for (int i = 0; i < encryptedData.size(); i++) {
    //     qDebug() << QString("%1 ").arg(encryptedData[i], 2, 16, QLatin1Char('0'));
    // }


    // 解密文件数据
    QByteArray decryptedData;
    decryptedData.resize(encryptedData.size());

    AES_KEY aesDecryptKey;
    if (AES_set_decrypt_key(aesKey, 256, &aesDecryptKey) < 0) {
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
        QMessageBox::critical(this, "错误", "无效的填充字节");
        return;
    }

    // 检查填充字节是否正确
    for (int i = decryptedData.size() - padding; i < decryptedData.size(); ++i) {
        if (static_cast<unsigned char>(decryptedData[i]) != padding) {
            QMessageBox::critical(this, "错误", "填充字节不匹配");
            return;
        }
    }

    // 移除填充
    decryptedData.chop(padding);




    // qDebug() << "解密后的文件内容 (十六进制): ";
    // for (int i = 0; i < decryptedData.size(); ++i) {
    //     // 通过'0x'标识输出十六进制
    //     qDebug() << "0x" + QString::number(static_cast<unsigned char>(decryptedData[i]), 16).toUpper();
    // }

    // 保存解密后的文件
    QString decryptedFile = encryptedFile;
    if (decryptedFile.endsWith(".enc")) {
        decryptedFile.chop(4);  // 去掉 ".enc" 后缀
    }

    // qDebug() << decryptedFile;

    // 创建解密后的文件并写入数据
    QFile decryptedFileOut(decryptedFile);
    if (!decryptedFileOut.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "错误", "无法保存解密文件");
        return;
    }

    decryptedFileOut.write(decryptedData);
    decryptedFileOut.close();

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

