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

    ui->treeWidget->setEnabled(false);
    ui->treeWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
    setWindowTitle("Drives");

    GetDisks(&m_disks);

    ui->treeWidget->setColumnHidden(2, true);
    ui->treeWidget->setColumnWidth(0, 280);
    QTreeWidgetItem *topLevelItem = new QTreeWidgetItem(ui->treeWidget);
    ui->treeWidget->addTopLevelItem(topLevelItem);
    topLevelItem->setText(0,"Drives & volumes");

    for (diskDescriptor disk : m_disks)
    {
        QTreeWidgetItem *item = new QTreeWidgetItem(topLevelItem);
        item->setText(0, QString::fromStdString(disk.pId) + QString::fromStdString(disk.vId));
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

    keyEnterReceiver* key = new keyEnterReceiver();
        this->installEventFilter(key);

    ui->treeWidget->setEnabled(true);
    ui->treeWidget->show();
    ui->label->setEnabled(false);
    ui->label->hide();
}

OpenDrive::~OpenDrive()
{
    delete ui;
}


void OpenDrive::on_treeWidget_itemDoubleClicked(QTreeWidgetItem *item, int column)
{
    if (!item->text(2).length())
        return;

    emit finished(item->text(2));
    close();
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




