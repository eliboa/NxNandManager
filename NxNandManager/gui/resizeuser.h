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

#ifndef RESIZEUSER_H
#define RESIZEUSER_H

#include <QDialog>
#include <QFileDialog>
#include <QSettings>
#include "../res/utils.h"
#include "../NxStorage.h"
#include "worker.h"

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

private slots:
    void on_checkBox_stateChanged(int arg1);
    void on_new_size_valueChanged(int arg1);
    void on_selectFileButton_clicked();
    void on_buttonBox_accepted();

signals:
    void finished(QString file, int new_size, bool format);
};

#endif // RESIZEUSER_H
