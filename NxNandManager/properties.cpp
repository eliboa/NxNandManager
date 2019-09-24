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



    wstring ws(input->pathLPWSTR);
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Path"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(string(ws.begin(), ws.end()).c_str()));
    i++;


    sprintf(buffer, "%s%s%s%s", input->GetNxStorageTypeAsString(),
                    input->type == PARTITION ? " " : "", input->type == PARTITION ? input->partitionName : "",
                    input->isSplitted ? " (splitted dump)" : "");
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("NAND type"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
    i++;

    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("File/Disk"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->isDrive ? "Disk" : "File"));
    i++;


    sprintf(buffer, "%s%s", input->isEncrypted ? "Yes" : "No",
                    input->isEncrypted && input->bad_crypto ? "  !!! DECRYPTION FAILED !!!" : "");
    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Encrypted"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(QString(buffer).trimmed()));
    i++;

    ui->PropertiesTable->setRowCount(i+1);
    ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Size"));
    ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(GetReadableSize(input->size).c_str()));
    i++;

    if(input->type == BOOT0)
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

    if(input->fw_detected)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Firmware ver."));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->fw_version));
        i++;

        if(input->type == RAWNAND || strcmp(input->partitionName, "SYSTEM") == 0)
        {
            ui->PropertiesTable->setRowCount(i+1);
            ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("ExFat driver"));
            ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->exFat_driver ? "Detected" : "Undetected"));
            i++;
        }
    }

    if (strlen(input->last_boot) > 0)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Last boot time"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(input->last_boot));
        i++;
    }

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

    if (strlen(input->wlanMacAddress) > 0)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("MAC Address"));
        ui->PropertiesTable->setItem(i, 1, new QTableWidgetItem(hexStr(reinterpret_cast<unsigned char*>(input->wlanMacAddress), 6).c_str()));
        i++;
    }

    if (input->type == RAWNAND)
    {
        ui->PropertiesTable->setRowCount(i+1);
        ui->PropertiesTable->setItem(i, 0, new QTableWidgetItem("Backup GPT"));
        if(input->backupGPTfound)
        {
            sprintf(buffer, "FOUND (offset 0x%s)", n2hexstr((u64)input->size - NX_EMMC_BLOCKSIZE, 10).c_str());
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
