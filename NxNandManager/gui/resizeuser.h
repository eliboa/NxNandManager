#ifndef RESIZEUSER_H
#define RESIZEUSER_H

#include <QDialog>
#include "../res/utils.h"
#include "../NxStorage.h"

namespace Ui {
class ResizeUser;
}

class ResizeUser : public QDialog
{
    Q_OBJECT

public:
    explicit ResizeUser(QWidget *parent = nullptr, NxStorage *input = nullptr);
    ~ResizeUser();

private:
    Ui::ResizeUser *ui;
    QWidget *parent;
    NxStorage *input;
};

#endif // RESIZEUSER_H
