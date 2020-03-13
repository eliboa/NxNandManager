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

#include "ui_properties.h"
#include "properties.h"

Properties::Properties(NxStorage *in) :
    ui(new Ui::DialogProperties)
{
    ui->setupUi(this);
    input = in;
    int i = 0;
    char buffer[0x100];

    ui->PropertiesTable->setRowCount(0);
    ui->PropertiesTable->setColumnCount(2);
    ui->PropertiesTable->setColumnWidth(0, 100);
    ui->PropertiesTable->setColumnWidth(1, 220);
    QStringList header;
    header<<"Property"<<"Value";
    ui->PropertiesTable->setHorizontalHeaderLabels(header);
    QFont font("Calibri", 10, QFont::Bold);
    ui->PropertiesTable->horizontalHeader()->setFont(font);
    ui->PropertiesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    //ui->PropertiesTable->setWordWrap(false);
    //ui->PropertiesTable->setTextElideMode(Qt::ElideNone);



    wstring ws(input->m_path);
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Path"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(string(ws.begin(), ws.end()).c_str()));
    i++;

    sprintf(buffer, "%s%s", input->getNxTypeAsStr(), input->isSplitted() ? " (splitted dump)" : "");
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("NAND type"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
    i++;

    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("File/Disk"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->isDrive() ? "Disk" : "File"));
    i++;


    sprintf(buffer, "%s%s", input->isEncrypted() ? "Yes" : "No",
                    input->isEncrypted() && input->badCrypto() ? "  !!! DECRYPTION FAILED !!!" : "");
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Encrypted"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
    i++;

    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Size"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(GetReadableSize(input->size()).c_str()));
    i++;

    if(input->type == BOOT0 || input->type == RAWMMC)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Auto RCM"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->autoRcm ? "ENABLED" : "DISABLED"));
        i++;

        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Bootloader ver."));
        sprintf(buffer, "%d", static_cast<int>(input->bootloader_ver));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
        i++;
    }

    if(strlen(input->fw_version))
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Firmware ver."));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->fw_version));
        i++;

        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("ExFat driver"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->exFat_driver ? "Detected" : "Undetected"));
        i++;
    }
    /*
    if (strlen(input->last_boot) > 0)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Last boot time"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->last_boot));
        i++;
    }
    */
    if (strlen(input->serial_number) > 3)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Serial number"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->serial_number));
        i++;
    }

    if (strlen(input->deviceId) > 0)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Device Id"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->deviceId));
        i++;
    }

    //if (strlen(input->wlanMacAddress) > 0)
    if (input->macAddress.length() > 0)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("MAC Address"));
        //ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(hexStr(reinterpret_cast<unsigned char*>(input->wlanMacAddress), 6).c_str()));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->macAddress.c_str()));
        i++;
    }

    if (input->type == RAWNAND || input->type == RAWMMC)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Backup GPT"));
        if(input->backupGPT())
        {
            sprintf(buffer, "FOUND (offset 0x%s)", n2hexstr(input->backupGPT(), 10).c_str());
            ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
        }
        else
            ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem("NOT FOUND"));
        i++;
    }
}

Properties::~Properties()
{
    delete ui;
}

void Properties::on_DialogProperties_finished(int result)
{
    isOpen = false;
}
