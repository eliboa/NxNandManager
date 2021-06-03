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
        m_keyset = new KeySet;
        if(parseKeySetFile("keys.dat", m_keyset))
            displayKeys();
    }
}

KeySetDialog::~KeySetDialog()
{
    delete ui;
    if (m_keyset)
        delete m_keyset;
}

void KeySetDialog::displayKeys()
{
    if (!m_keyset)
        return;

    ui->key0_crypt_edit->setText(QString(m_keyset->crypt0));
    ui->key0_tweak_edit->setText(QString(m_keyset->tweak0));
    ui->key1_crypt_edit->setText(QString(m_keyset->crypt1));
    ui->key1_tweak_edit->setText(QString(m_keyset->tweak1));
    ui->key2_crypt_edit->setText(QString(m_keyset->crypt2));
    ui->key2_tweak_edit->setText(QString(m_keyset->tweak2));
    ui->key3_crypt_edit->setText(QString(m_keyset->crypt3));
    ui->key3_tweak_edit->setText(QString(m_keyset->tweak3));

    ui->label_other_keys->setText("");
    if (!m_keyset->other_keys.empty())
        ui->label_other_keys->setText(QString("+%1 other keys (useful for explorer and hactool)").arg(m_keyset->other_keys.size()));
}

void KeySetDialog::on_ImportButton_clicked()
{
    // Create new file dialog    
    QString fileName = QFileDialog::getOpenFileName(this);
    if (fileName.isEmpty())
        return;

    if (m_keyset)
        delete m_keyset;
    m_keyset = new KeySet;

    if (!parseKeySetFile(fileName.toUtf8(), m_keyset))
    {
        QMessageBox::critical(nullptr,"Error", QString("Error while parsing keyset file"));
        return;
    }

    displayKeys();
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
    if(ui->key0_crypt_edit->text().length() >= 32 && ui->key0_tweak_edit->text().length() >= 32)
        out << "bis_key_00 = " << ui->key0_crypt_edit->text() << ui->key0_tweak_edit->text() << "\n";
    if(ui->key1_crypt_edit->text().length() >= 32 && ui->key1_tweak_edit->text().length() >= 32)
        out << "bis_key_01 = " << ui->key1_crypt_edit->text() << ui->key1_tweak_edit->text() << "\n";
    if(ui->key2_crypt_edit->text().length() >= 32 && ui->key2_tweak_edit->text().length() >= 32)
        out << "bis_key_02 = " << ui->key2_crypt_edit->text() << ui->key2_tweak_edit->text() << "\n";
    if(ui->key3_crypt_edit->text().length() >= 32 && ui->key3_tweak_edit->text().length() >= 32)
        out << "bis_key_03 = " << ui->key3_crypt_edit->text() << ui->key3_tweak_edit->text() << "\n";

    if (m_keyset && !m_keyset->other_keys.empty()) for (auto k : m_keyset->other_keys)
        out << QString::fromStdString(k.name) << " = " << QString::fromStdString(k.key) << "\n";

    file.close();
    emit finished();
}
