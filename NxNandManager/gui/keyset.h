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

#ifndef KEYSET_H
#define KEYSET_H
#include <QMainWindow>
#include <QDialog>
#include <QtWidgets>
#include "../res/utils.h"
#include <QObject>

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;

namespace Ui {
    class DialogKeySet;
}

class KeySetDialog : public QDialog
{
    Q_OBJECT

public:
    explicit KeySetDialog(QWidget *parent = nullptr);
    ~KeySetDialog();
    Ui::DialogKeySet *ui;

private:
    QWidget *parent;

signals:
    void finished();

public slots:
private slots:
    void on_ImportButton_clicked();
    void on_buttonBox_accepted();
};

#endif // KEYSET_H
