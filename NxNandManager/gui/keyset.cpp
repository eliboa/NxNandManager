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

#include "ui_keyset.h"
#include "keyset.h"

KeySetDialog::KeySetDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogKeySet)
{
    ui->setupUi(this);
    this->setAttribute(Qt::WA_DeleteOnClose);
    connect(this, SIGNAL(finished()), parent, SLOT(keySetSet()));
    this->parent = parent;

    QFile file("keys.dat");
    if (file.exists())
    {
        KeySet biskeys;
        if(parseKeySetFile("keys.dat", &biskeys))
        {
            ui->key0_crypt_edit->setText(QString(biskeys.crypt0));
            ui->key0_tweak_edit->setText(QString(biskeys.tweak0));
            ui->key1_crypt_edit->setText(QString(biskeys.crypt1));
            ui->key1_tweak_edit->setText(QString(biskeys.tweak1));
            ui->key2_crypt_edit->setText(QString(biskeys.crypt2));
            ui->key2_tweak_edit->setText(QString(biskeys.tweak2));
            ui->key3_crypt_edit->setText(QString(biskeys.crypt3));
            ui->key3_tweak_edit->setText(QString(biskeys.tweak3));
        }
    }

}

KeySetDialog::~KeySetDialog()
{
    delete ui;
}

void KeySetDialog::on_ImportButton_clicked()
{
    // Create new file dialog
    KeySet biskeys;
    QString fileName = QFileDialog::getOpenFileName(this);
    if (fileName.isEmpty())
            return;
    if (!parseKeySetFile(fileName.toUtf8(), &biskeys))
    {
        QMessageBox::critical(nullptr,"Error", QString("Error while parsing keyset file"));
    }
    else {
        //QMessageBox::critical(nullptr,"Error", QString(biskeys.crypt0));

        ui->key0_crypt_edit->setText(QString(biskeys.crypt0));
        ui->key0_tweak_edit->setText(QString(biskeys.tweak0));
        ui->key1_crypt_edit->setText(QString(biskeys.crypt1));
        ui->key1_tweak_edit->setText(QString(biskeys.tweak1));
        ui->key2_crypt_edit->setText(QString(biskeys.crypt2));
        ui->key2_tweak_edit->setText(QString(biskeys.tweak2));
        ui->key3_crypt_edit->setText(QString(biskeys.crypt3));
        ui->key3_tweak_edit->setText(QString(biskeys.tweak3));

    }
}

void KeySetDialog::on_buttonBox_accepted()
{
    QFile file("keys.dat");

    if (file.exists())
        file.remove();

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::critical(nullptr,"Error", QString("Cannot open/create keys.dat"));
        return;
    }
    QTextStream out(&file);
    if(ui->key0_crypt_edit->text().length() >= 32) out << "BIS KEY 0 (crypt): " << ui->key0_crypt_edit->text() << " \n";
    if(ui->key0_tweak_edit->text().length() >= 32) out << "BIS KEY 0 (tweak): " << ui->key0_tweak_edit->text() << " \n";
    if(ui->key1_crypt_edit->text().length() >= 32) out << "BIS KEY 1 (crypt): " << ui->key1_crypt_edit->text() << " \n";
    if(ui->key1_tweak_edit->text().length() >= 32) out << "BIS KEY 1 (tweak): " << ui->key1_tweak_edit->text() << " \n";
    if(ui->key2_crypt_edit->text().length() >= 32) out << "BIS KEY 2 (crypt): " << ui->key2_crypt_edit->text() << " \n";
    if(ui->key2_tweak_edit->text().length() >= 32) out << "BIS KEY 2 (tweak): " << ui->key2_tweak_edit->text() << " \n";
    if(ui->key3_crypt_edit->text().length() >= 32) out << "BIS KEY 3 (crypt): " << ui->key3_crypt_edit->text() << " \n";
    if(ui->key3_tweak_edit->text().length() >= 32) out << "BIS KEY 3 (tweak): " << ui->key3_tweak_edit->text() << " \n";

    file.close();
    emit finished();
}
