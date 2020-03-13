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

#include "ui_opendrive.h"
#include "opendrive.h"

OpenDrive::OpenDrive(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogOpenDrive)
{
    ui->setupUi(this);
    connect(this, SIGNAL(finished(QString)), parent, SLOT(driveSet(QString)));
    setWindowTitle("Drives");

    ui->treeWidget->setEnabled(false);
    ui->treeWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
    ui->RemovableCheckBox->hide();

    keyEnterReceiver* key = new keyEnterReceiver();
        this->installEventFilter(key);

    timer1000();
    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timer1000()));
    timer->start(1000);

}

OpenDrive::~OpenDrive()
{
    delete ui;
}

void OpenDrive::build_DriveList()
{
    ui->RemovableCheckBox->show();
    ui->treeWidget->setColumnHidden(2, true);
    ui->treeWidget->setColumnWidth(0, 310);
    ui->treeWidget->clear();

    QTreeWidgetItem *topLevelItem = new QTreeWidgetItem(ui->treeWidget);
    ui->treeWidget->addTopLevelItem(topLevelItem);
    topLevelItem->setText(0,"Drives & volumes");

    for (diskDescriptor disk : m_disks)
    {
        if (removableDrivesOnly && !disk.removableMedia)
            continue;

        QTreeWidgetItem *item = new QTreeWidgetItem(topLevelItem);
        item->setText(0, QString::fromStdString(disk.pId) + " " + QString::fromStdString(disk.vId));
        item->setText(1, QString::fromStdString(GetReadableSize(disk.size)));
        item->setText(2, "\\\\.\\PhysicalDrive" + QString::number(disk.diskNumber));

        for (volumeDescriptor vol : disk.volumes)
        {
            QTreeWidgetItem *child = new QTreeWidgetItem(item);

            QString label;
            if (vol.mountPt.size())
                label.append(QString::fromStdWString(vol.mountPt).toUpper() + ":");
            else
                label.append(QString::fromStdWString(vol.volumeName));

            child->setText(0, label);
            child->setText(1, QString::fromStdString(GetReadableSize(vol.volumeTotalBytes)));
            child->setText(2, QString::fromStdWString(vol.volumeName));
        }
    }
    ui->treeWidget->expandAll();
}

void OpenDrive::on_treeWidget_itemDoubleClicked(QTreeWidgetItem *item, int column)
{
    if (!item->text(2).length())
        return;

    emit finished(item->text(2));
    close();
}

void OpenDrive::timer1000()
{

    Worker *workThread = new Worker(this, WorkerMode::get_disks);
    workThread->start();

}

void OpenDrive::on_GetDisks_callback(const std::vector<diskDescriptor> disks)
{
    ui->treeWidget->setEnabled(true);
    ui->treeWidget->show();
    ui->label->setEnabled(false);
    ui->label->hide();

    std::vector<diskDescriptor> disks_tmp;
    disks_tmp = m_disks;
    if (disks.size() != disks_tmp.size() || (disks_tmp.size() && !std::equal(disks_tmp.begin(), disks_tmp.end(), disks.begin())))
    {
       m_disks = disks;
       build_DriveList();
    }
}

bool keyEnterReceiver::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type()==QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ( (key->key()==Qt::Key_Enter) || (key->key()==Qt::Key_Return) ) {
            OpenDrive *parent = (OpenDrive *) obj;
            if (parent->ui->treeWidget->selectedItems().first()->text(2).length())
            {
                emit parent->finished(parent->ui->treeWidget->selectedItems().first()->text(2));
                parent->close();
            }
        } else return QObject::eventFilter(obj, event);
        return true;
    } else return QObject::eventFilter(obj, event);
}

void OpenDrive::on_RemovableCheckBox_stateChanged(int arg1)
{
    removableDrivesOnly = ui->RemovableCheckBox->isChecked();
    build_DriveList();
}

void OpenDrive::on_DialogOpenDrive_finished(int result)
{
    isOpen = false;
}
