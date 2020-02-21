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

    ui->listWidget->setEnabled(false);
    ui->listWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
    setWindowTitle("Physical drives");

    Worker* workThread = new Worker(this, WorkerMode::list_storage);
    workThread->start();

    GetDisks(&m_disks);

    ui->treeWidget->setColumnHidden(2, true);
    ui->treeWidget->setColumnWidth(0, 180);
    QTreeWidgetItem *topLevelItem = new QTreeWidgetItem(ui->treeWidget);
    ui->treeWidget->addTopLevelItem(topLevelItem);
    topLevelItem->setText(0,"Drives");

    for (diskDescriptor disk : m_disks)
    {
        QTreeWidgetItem *item = new QTreeWidgetItem(topLevelItem);
        item->setText(0, QString::fromStdString(disk.pId) + QString::fromStdString(disk.vId));
        item->setText(1, QString::fromStdString(GetReadableSize(disk.size)));
        item->setText(2, QString::number(disk.diskNumber));

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

OpenDrive::~OpenDrive()
{
    delete ui;
}
void OpenDrive::ShowLabel()
{
    ui->listWidget->setEnabled(false);
    ui->listWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
}
void OpenDrive::ListDrives(QString drives)
{
    //QString drives = QString(ListPhysicalDrives().c_str());
    ui->label->setEnabled(false);
    ui->label->hide();
    ui->listWidget->setEnabled(true);
    ui->listWidget->show();
    QString drivename;
    int li = 0;
    for (int i = 0; i < drives.count(); ++i)
    {
        if(drives[i] == '\n' && drives.count() > 0)
        {
            drivename = drivename.toUpper();
            QListWidgetItem *item = new QListWidgetItem(drivename);
            ui->listWidget->insertItem(li, item);
            drivename.clear();
            ui->listWidget->setCurrentItem(item);
            li++;
        } else {
            drivename += drives[i];
        }
    }
    keyEnterReceiver* key = new keyEnterReceiver();
    this->installEventFilter(key);    
}

void OpenDrive::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{    
    emit finished(item->text().left(item->text().indexOf(" ")));
    close();
}

bool keyEnterReceiver::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type()==QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ( (key->key()==Qt::Key_Enter) || (key->key()==Qt::Key_Return) ) {
            OpenDrive *parent = (OpenDrive *) obj;
            if(parent->ui->listWidget->selectedItems().count() > 0)
            {
                QString item = parent->ui->listWidget->selectedItems().first()->text();
                emit parent->finished(item.left(item.indexOf(" ")));
                parent->close();
            }

        } else {
            return QObject::eventFilter(obj, event);
        }
        return true;
    } else {
        return QObject::eventFilter(obj, event);
    }
    return false;
}

void OpenDrive::list_callback(QString drives)
{
    ListDrives(drives);
}


