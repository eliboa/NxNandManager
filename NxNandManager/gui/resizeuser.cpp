/*
 * Copyright (c) 2019 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "resizeuser.h"
#include "ui_resizeuser.h"

ResizeUser::ResizeUser(QWidget *parent, NxStorage *input) :
    QDialog(parent),
    ui(new Ui::ResizeUser)
{
    ui->setupUi(this);
    this->parent = parent;
    this->input = input;
    connect(this, SIGNAL(finished(QString, int, bool)), parent, SLOT(resizeUser(QString, int, bool)));

    NxPartition *user = input->getNxPartition(USER);
    u32 size = user->lbaEnd() - user->lbaStart() + 1;
    u32 freesectors = (u32)(user->freeSpaceRaw / NX_BLOCKSIZE);
    u32 min = (size - freesectors) / 0x800;
    if(!min) min = 64;

    dbg_printf("ResizeUserDialog - size = %I32d, freesectors = %I32d, min = %I32d", size, freesectors, min);

    ui->new_size->setMinimum(min);
    ui->new_size->setMaximum(999999);
    ui->new_size->setValue(min);
    ui->range_size_label->setText("(Min: " + QString::number(min) + " Mb, Max: " + QString::number(999999) + " Mb)");
    on_new_size_valueChanged(min);

    QString CurrentFile;
    wchar_t buffer[_MAX_PATH];
    GetModuleFileName(NULL, buffer, _MAX_PATH);
    std::wstring curmodule(buffer);
    std::wstring curpath = curmodule.substr(0, curmodule.find(base_nameW(curmodule)));
    CurrentFile.append(std::string(curpath.begin(), curpath.end()).c_str());
    CurrentFile.append(input->getNxTypeAsStr());
    CurrentFile.append(".resized");
    ui->output->setText(CurrentFile);
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
        min = (size - freesectors) / 0x800;
        if(!min) min = 64;
    }
    ui->new_size->setMinimum(min);
    ui->range_size_label->setText("(Min: " + QString::number(min) + " Mb, Max: " + QString::number(999999) + " Mb)");
}

void ResizeUser::on_new_size_valueChanged(int size)
{
    u32 lba_count = size * 0x800; // 1mb = 0x800 sectors
    NxPartition *user = input->getNxPartition(USER);
    u32 total_lba_count = user->lbaStart() + (lba_count / 0x1000 + lba_count + 66);
    ui->label_total_size->setText(GetReadableSize((u64)total_lba_count * NX_BLOCKSIZE).c_str());
}

void ResizeUser::on_selectFileButton_clicked()
{
    // Create new file dialog
    QFileDialog fd(this);
    fd.setAcceptMode(QFileDialog::AcceptSave); // Ask overwrite
    QString save_filename(input->getNxTypeAsStr());
    save_filename.append(".resized");

    QString fileName = fd.getSaveFileName(this, "Save as", "default_dir\\" + save_filename);
    if (!fileName.isEmpty())
        ui->output->setText(fileName);
}

void ResizeUser::on_buttonBox_accepted()
{
    if(is_file(ui->output->text().toLocal8Bit().constData()))
        remove(ui->output->text().toLocal8Bit().constData());

    params_t par;
    par.user_new_size = ui->new_size->value() * 0x800;
    par.format_user = ui->checkBox->isChecked();

    WorkerInstance wi(this, WorkerMode::dump, &par, input, ui->output->text());
    wi.exec();

    //emit finished(ui->output->text(), ui->new_size->value(), ui->checkBox->isChecked());
}
