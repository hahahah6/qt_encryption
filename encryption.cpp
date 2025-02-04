#include "encryption.h"
#include "ui_encryption.h"
#include <QDebug>
#include <QFileDialog>
#include <QDir>
#include <QString>

#include <QMessageBox>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <QFile>
#include <QIODevice>
#include <QDesktopServices>
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

void jiami::public_secret_key_path_slot(const QString &path)
{
    ui->lineEdit_public->setText(path);
}

void jiami::on_pushButton_public_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,           // 父窗口指针，通常为当前窗口指针
        "选择公钥",         // 对话框标题
        "",      // 初始目录路径
        "密钥文件 (*.pem *.key *.cer *.crt *.pfx);;所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->lineEdit_public->setText(fileName);
    } else {
        // 用户取消了文件选择
        QMessageBox::critical(this, "文件选择", "您没有选择任何文件。");
    }
}


void jiami::on_pushButton_file_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,           // 父窗口指针，通常为当前窗口指针
        "选择公钥",         // 对话框标题
        "",      // 初始目录路径
        "所有文件 (*.*)"
        );

    if (!fileName.isEmpty()) {
        ui->lineEdit_file->setText(fileName);

    } else {
        // 用户取消了文件选择
        QMessageBox::critical(this, "文件选择", "您没有选择任何文件。");
    }
}
// RSA* jiami::loadPublicKey(const QString &path) {
//     qDebug() << path;
//     QString correctedPath = QDir::toNativeSeparators(path);
//     qDebug() << correctedPath;
//     FILE *file = fopen(path.toStdString().c_str(), "r");
//     if (file == nullptr) {
//         qDebug() << "1 Failed to open public key file.";
//         return nullptr;
//     }

//     RSA *rsa = PEM_read_RSA_PUBKEY(file, nullptr, nullptr, nullptr);
//     fclose(file);

//     if (rsa == nullptr) {
//         qDebug() << "2 Failed to load public key.";
//         return nullptr;
//     }

//     return rsa;
// }


RSA* jiami::loadPublicKey(const QString &path) {
    qDebug() << path;  // 打印路径，确保路径正确
    QString correctedPath = QDir::toNativeSeparators(path);
    qDebug() << correctedPath;  // 打印纠正后的路径

    QFile file(correctedPath);  // 使用 QFile 打开文件
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open public key file.";
        return nullptr;
    }

    // 使用 fdopen 将文件描述符转换为 FILE* 类型
    FILE* filePointer = fdopen(file.handle(), "r");
    if (filePointer == nullptr) {
        qDebug() << "Failed to convert file handle to FILE*";
        return nullptr;
    }

    // 读取公钥
    RSA* rsa = PEM_read_RSA_PUBKEY(filePointer, nullptr, nullptr, nullptr);
    fclose(filePointer);  // 记得关闭文件

    if (rsa == nullptr) {
        qDebug() << "Failed to load public key.";
        return nullptr;
    }

    return rsa;
}




bool jiami::generateAES256Key(unsigned char *key) {
    // 使用 OpenSSL 的 RAND_bytes 函数生成 256 位 (32 字节) 随机数
    if (RAND_bytes(key, AES_BLOCK_SIZE * 2) != 1) {  // AES_BLOCK_SIZE 是 16 字节，AES-256 需要 32 字节
        qDebug() << "AES-256 密钥生成失败！";
        return false;
    }
    return true;
}

void jiami::on_pushButton_en_clicked()
{
    QString publicKeyFilename = ui->lineEdit_public->text();
    QString filename = ui->lineEdit_file->text();

    // 加载公钥
    RSA* mPublicKey = loadPublicKey(publicKeyFilename);
    if (mPublicKey == nullptr) {
        QMessageBox::critical(this, "公钥错误", "公钥加载错误");
        return;
    }

    // 生成 AES-256 密钥
    unsigned char aesKey[32];  // 32 字节 = 256 位
    if (!generateAES256Key(aesKey)) {
        QMessageBox::critical(this, "错误", "密钥生成失败");
        return;
    }

    // // 打印生成的 AES 密钥
    // QString aesKeyString;
    // for (int i = 0; i < 32; i++) {
    //     aesKeyString += QString("%1 ").arg(aesKey[i], 2, 16, QLatin1Char('0'));  // 将每个字节转换为 2 位十六进制数
    // }
    // qDebug() << "生成的 AES 密钥: " << aesKeyString;

    // 读取文件内容
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "文件读取", "无法读取文件");
        return;
    }

    QByteArray fileData = file.readAll();
    file.close();

    // // 打印文件内容的十六进制表示
    // qDebug() << "文件内容 (十六进制): ";
    // for (int i = 0; i < fileData.size(); ++i) {
    //     qDebug() << "0x" + QString::number(static_cast<unsigned char>(fileData[i]), 16).toUpper();
    // }

    // 使用 AES 加密文件数据
    // 生成加密前的初始化向量 (IV)，AES 加密需要它
    unsigned char iv[AES_BLOCK_SIZE];  // 初始化向量 (IV)，AES 加密需要它
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        QMessageBox::critical(this, "错误", "初始化向量生成失败");
        return;
    }

    // 保存加密前的 IV（这个是加密时使用的初始 IV）
    unsigned char originalIv[AES_BLOCK_SIZE];
    memcpy(originalIv, iv, AES_BLOCK_SIZE);

    // 打印加密前的 IV（初始化向量）
    QString ivString;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        ivString += QString("%1 ").arg(iv[i], 2, 16, QLatin1Char('0'));  // 将每个字节转换为 2 位十六进制数
    }
    // qDebug() << "加密前的 IV: " << ivString;

    // 计算需要添加的填充长度
    int paddingLen = AES_BLOCK_SIZE - (fileData.size() % AES_BLOCK_SIZE);
    if (paddingLen == 0) {
        paddingLen = AES_BLOCK_SIZE;
    }

    // 添加 PKCS#7 填充
    QByteArray paddedData = fileData;
    paddedData.append(paddingLen, static_cast<char>(paddingLen));

    // 调整加密数据的大小
    QByteArray encryptedData;
    encryptedData.resize(paddedData.size());

    // 初始化加密密钥
    AES_KEY aesEncryptKey;
    if (AES_set_encrypt_key(aesKey, 256, &aesEncryptKey) < 0) {
        QMessageBox::critical(this, "错误", "AES 加密密钥设置失败");
        return;
    }

    // AES 加密
    int numBlocks = paddedData.size() / AES_BLOCK_SIZE;
    for (int i = 0; i < numBlocks; i++) {
        AES_cbc_encrypt((unsigned char*)paddedData.constData() + i * AES_BLOCK_SIZE,
                        (unsigned char*)encryptedData.data() + i * AES_BLOCK_SIZE,
                        AES_BLOCK_SIZE, &aesEncryptKey, iv, AES_ENCRYPT);
    }
    // 使用 RSA 公钥加密 AES 密钥
    int aesKeyLength = RSA_size(mPublicKey);
    unsigned char encryptedAesKey[aesKeyLength];
    int encryptedKeyLen = RSA_public_encrypt(32, aesKey, encryptedAesKey, mPublicKey, RSA_PKCS1_OAEP_PADDING);

    if (encryptedKeyLen == -1) {
        QMessageBox::critical(this, "错误", "RSA 加密 AES 密钥失败");
        return;
    }

    // 保存加密的 AES 密钥和加密的文件
    QString encryptedFile = filename + ".enc";
    // 加密时的 IV 存储
    QFile encryptedFileOut(encryptedFile);
    if (!encryptedFileOut.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "错误", "无法保存加密文件");
        return;
    }

    // 先写入 IV 的长度
    int ivLen = AES_BLOCK_SIZE;  // 假设 IV 长度为 AES_BLOCK_SIZE (16 字节)
    // qDebug() << "写入 IV 长度: " << ivLen;
    encryptedFileOut.write((char*)&ivLen, sizeof(ivLen));  // 写入 IV 长度

    // // 然后写入加密前的 IV（即最初生成的 IV）
    // qDebug() << "写入加密前的 IV 数据: ";
    // for (int i = 0; i < ivLen; i++) {
    //     qDebug() << QString("%1 ").arg(originalIv[i], 2, 16, QLatin1Char('0'));  // 打印原始 IV 数据
    // }
    encryptedFileOut.write((char*)originalIv, ivLen);  // 写入加密前的 IV 数据

    // 写入 AES 密钥的长度
    // qDebug() << "写入 AES 密钥长度: " << encryptedKeyLen;
    encryptedFileOut.write((char*)&encryptedKeyLen, sizeof(encryptedKeyLen));

    // // 写入加密的 AES 密钥
    // qDebug() << "写入加密的 AES 密钥: ";
    // for (int i = 0; i < encryptedKeyLen; i++) {
    //     qDebug() << QString("%1 ").arg(encryptedAesKey[i], 2, 16, QLatin1Char('0'));
    // }
    encryptedFileOut.write((char*)encryptedAesKey, encryptedKeyLen);

    // // 写入加密后的文件数据
    // qDebug() << "写入加密的文件数据: ";
    // for (int i = 0; i < encryptedData.size(); i++) {
    //     qDebug() << QString("%1 ").arg(encryptedData[i], 2, 16, QLatin1Char('0'));
    // }
    encryptedFileOut.write(encryptedData);
    encryptedFileOut.close();


    QFileInfo fileInfo(filename);
    QString folderPath = fileInfo.absoluteDir().path();

    // 提示成功
    qDebug() << "create" << folderPath;
    QMessageBox::StandardButton reply_success;
    reply_success = QMessageBox::question(this, "打开", "文件加密成功！是否打开目录",
                                          QMessageBox::Yes | QMessageBox::No);
    if(reply_success == QMessageBox::Yes)
    {
        QString strFilePath = "file:///" + folderPath;
        QDesktopServices::openUrl(QUrl(strFilePath));
    }
}


