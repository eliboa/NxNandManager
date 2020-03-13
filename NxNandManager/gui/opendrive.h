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

#ifndef OPENDRIVE_H
#define OPENDRIVE_H
#include <QMainWindow>
#include <QDialog>
#include <QtWidgets>
#include "worker.h"
#include "../res/utils.h"
#include "../NxStorage.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;

namespace Ui {
    class DialogOpenDrive;
}

class OpenDrive : public QDialog
{
    Q_OBJECT

public:
    explicit OpenDrive(QWidget *parent = nullptr);
    ~OpenDrive();
    Ui::DialogOpenDrive *ui;
    bool isOpen = true;

private slots:
    void on_treeWidget_itemDoubleClicked(QTreeWidgetItem *item, int column);
    void timer1000();
    void on_RemovableCheckBox_stateChanged(int arg1);

    void on_DialogOpenDrive_finished(int result);

private:
    std::vector<diskDescriptor> m_disks;
    bool removableDrivesOnly = true;
    void build_DriveList();

public slots:
    void on_GetDisks_callback(const std::vector<diskDescriptor> disks);

signals:
    void finished(QString);
};

class keyEnterReceiver : public QObject
{
    Q_OBJECT
protected:
    bool eventFilter(QObject* obj, QEvent* event);
};
#endif // OPENDRIVE_H
