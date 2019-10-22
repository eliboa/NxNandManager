#include "resizeuser.h"
#include "ui_resizeuser.h"

ResizeUser::ResizeUser(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ResizeUser)
{
    ui->setupUi(this);
}

ResizeUser::~ResizeUser()
{
    delete ui;
}
