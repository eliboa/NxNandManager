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

#ifndef PROPERTIES_H
#define PROPERTIES_H

#include <QMainWindow>
#include <QObject>
#include <QDialog>
#include <QtWidgets>
#include "../res/utils.h"
#include "../NxStorage.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;

namespace Ui {
    class DialogProperties;
}

class Properties : public QDialog
{
    Q_OBJECT
public:
    explicit Properties(NxStorage *input);
    ~Properties();
    Ui::DialogProperties *ui;

private:
    NxStorage *input;

signals:

public:
    bool isOpen = true;
private slots:
    void on_DialogProperties_finished(int result);
};

#endif // PROPERTIES_H
