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
#include <QMessageBox>

QList<KeyEntry> QParseKeyFile(const QString &keyFile)
{
    QList<KeyEntry> keys;
    QFile file(keyFile);
    if (!file.open(QIODevice::ReadOnly))
        return keys;

    QTextStream stream(file.readAll());
    QString line;
    int pos;

    while (stream.readLineInto(&line)) if ((pos = line.indexOf("=")) >= 0) {
        KeyEntry e;
        e.key = line.left(pos++).trimmed();
        e.value = line.right(line.length() - pos).trimmed();
        keys << e;
    }
    return keys;
}

KeySetDialog::KeySetDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogKeySet)
{
    ui->setupUi(this);
    this->setAttribute(Qt::WA_DeleteOnClose);
    connect(this, SIGNAL(finished()), parent, SLOT(keySetSet()));
    this->parent = parent;

    auto table = ui->keysTable;
    table->setContextMenuPolicy(Qt::ActionsContextMenu);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    auto deleteAction = new QAction(QIcon(":/images/close-window-32.ico"), "Remove selected key(s)");
    connect(deleteAction, &QAction::triggered, [&](){
        auto selection = ui->keysTable->selectionModel()->selectedRows();
        QList<int> idxs;
        for (auto row : selection)
            idxs << ui->keysTable->item(row.row(), 0)->data(Qt::UserRole).value<int>();

        std::sort(idxs.begin(), idxs.end(), [](int a, int b) { return a > b; });
        for (auto ix : idxs)
            m_keys.removeAt(ix);

        displayKeys();
    });
    table->addAction(deleteAction);
    m_keys = QParseKeyFile("keys.dat");
    displayKeys();
}

KeySetDialog::~KeySetDialog()
{
    delete ui;
    if (m_keyset)
        delete m_keyset;
}

void KeySetDialog::displayKeys()
{
    auto table = ui->keysTable;
    table->horizontalHeader()->hide();
    table->setColumnCount(2);

    table->setRowCount(0);
    for (int i(0); i < m_keys.count(); i++) {
        auto k = m_keys.at(i);
        auto idx = table->rowCount();
        table->insertRow(idx);
        table->setRowHeight(idx, 25);
        auto it1 = new QTableWidgetItem(k.key);
        it1->setFlags(it1->flags() ^ Qt::ItemIsEditable);
        it1->setData(Qt::UserRole, i);
        table->setItem(idx, 0, it1);
        auto it2 = new QTableWidgetItem(k.value);
        it2->setFlags(it1->flags());
        table->setItem(idx, 1, it2);
    }
    table->resizeColumnsToContents();    
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    ui->clearKeysButton->setDisabled(m_keys.isEmpty());
}

void KeySetDialog::on_ImportButton_clicked()
{
    // Create new file dialog    
    QString fileName = QFileDialog::getOpenFileName(this);
    if (fileName.isEmpty())
        return;

    auto keys = QParseKeyFile(fileName);
    int new_count = 0, upd_count = 0;

    for (auto k : keys) {
        bool found = false;
        for (int i(0); i < m_keys.count(); i++) if (m_keys[i].key == k.key){
            found = true;
            if (m_keys[i].value != k.value) {
                m_keys[i].value = k.value;
                upd_count++;
            }
            break;
        }
        if (!found) {
            m_keys << k;
            new_count++;
        }
    }

    if (new_count + upd_count)
        displayKeys();

    QMessageBox::information(this, "Key import", QString("%1 key%2 imported (new: %3, updated: %4)")
                                                    .arg(new_count + upd_count)
                                                    .arg(new_count + upd_count > 1 ? "s" : "")
                                                    .arg(new_count).arg(upd_count));
}

void KeySetDialog::on_buttonBox_accepted()
{
    QFile file("keys.dat");

    if (file.exists())
        file.remove();

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
       return (void) QMessageBox::critical(nullptr,"Error", QString("Failed to open/create keys.dat"));

    QTextStream out(&file);
    for (auto k : m_keys)
        out << k.key << " = " << k.value << "\n";

    file.close();
    emit finished();
}

void KeySetDialog::on_clearKeysButton_clicked()
{
    m_keys.clear();
    displayKeys();
}
