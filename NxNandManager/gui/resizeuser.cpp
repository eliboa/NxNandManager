#include "resizeuser.h"
#include "ui_resizeuser.h"

ResizeUser::ResizeUser(QWidget *parent, NxStorage *input) :
    QDialog(parent),
    ui(new Ui::ResizeUser)
{
    ui->setupUi(this);
    this->parent = parent;
    this->input = input;

    NxPartition *user = input->getNxPartition(USER);
    u32 size = user->lbaEnd() - user->lbaStart() + 1;
    u32 freesectors = (u32)(user->freeSpace / NX_BLOCKSIZE);
    u32 min = (size - freesectors) / 0x800;
    if(!min) min = 64;

    dbg_printf("ResizeUserDialog - size = %I32d, freesectors = %I32d, min = %I32d", size, freesectors, min);

    ui->new_size->setMinimum(min);
    ui->new_size->setMaximum(999999);
    ui->new_size->setValue(min);
    ui->range_size_label->setText("(Min: " + QString::number(min) + " Mb, Max: " + QString::number(999999) + " Mb)");
}

ResizeUser::~ResizeUser()
{
    delete ui;
}

void ResizeUser::on_checkBox_stateChanged(int arg1)
{
    u32 min = 64;
    if(!ui->checkBox->isChecked())
    {
        NxPartition *user = input->getNxPartition(USER);
        u32 size = user->lbaEnd() - user->lbaStart() + 1;
        u32 freesectors = (u32)(user->freeSpace / NX_BLOCKSIZE);
        u32 min = (size - freesectors) / 0x800;
        if(!min) min = 64;
    }
    ui->new_size->setMinimum(min);
    ui->range_size_label->setText("(Min: " + QString::number(min) + " Mb, Max: " + QString::number(999999) + " Mb)");
}
