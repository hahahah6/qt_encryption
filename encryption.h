#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <QWidget>

namespace Ui {
class jiami;
}

class jiami : public QWidget
{
    Q_OBJECT

public:
    explicit jiami(QWidget *parent = nullptr);
    ~jiami();

private:
    Ui::jiami *ui;
};

#endif // ENCRYPTION_H
