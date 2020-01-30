#include "emunand.h"
#include "ui_emunand.h"

Emunand::Emunand(QWidget *parent, NxStorage *input) :
    QDialog(parent),
    ui(new Ui::Emunand)
{
    ui->setupUi(this);
    this->parent = parent;

    if(nullptr != input)
    {
        this->input = input;

        if(is_in(input->type, { RAWNAND, RAWMMC}))
        {
            ui->nand_path->setText(QString::fromWCharArray(input->m_path));
            ui->nand_pushBtn->setDisabled(true);

            if(input->type == RAWMMC)
                ui->bootPartBox->setDisabled(true);
        }
    }

    ui->outBar->setValue(0);
    ui->outBar->setFormat("");
    on_emunandType_toggled(rawBased);

    connect(this, SIGNAL(finished(WorkParam_t)), parent, SLOT(startWorkThread(WorkParam_t)));

    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timer1000()));
    timer->start(1000);
}

Emunand::~Emunand()
{
    delete ui;
}

void Emunand::timer1000()
{
    if (m_emu_type == rawBased)
    {
        std::vector<diskDescriptor> disks, removableDisks;
        GetDisks(&disks);
        for (diskDescriptor disk : disks)
        {
            if(disk.removableMedia)
                removableDisks.push_back(disk);
        }

        if (m_disks.size() && (removableDisks.size() != m_disks.size() || !std::equal(m_disks.begin(), m_disks.end(), removableDisks.begin())))
           listDisks();
    }
    else
    {
        std::vector<volumeDescriptor> volumes, removableVolumes;
        GetVolumes(&volumes);
        for (volumeDescriptor volume : volumes)
        {
            if (volume.removableMedia)
                removableVolumes.push_back(volume);
        }
        if (m_volumes.size() && (removableVolumes.size() != m_volumes.size() || !std::equal(m_volumes.begin(), m_volumes.end(), removableVolumes.begin())))
            listVolumes();
    }
}

void Emunand::listVolumes()
{
    volumeDescriptor *selected_vol = nullptr;
    if(ui->driveList->selectedItems().count())
    {
        QListWidgetItem *item = ui->driveList->selectedItems().at(0);
        int selected = 0;
        for(int i(0); i < ui->driveList->count(); i++)
        {
            if(ui->driveList->item(i) == item)
                selected = i;
        }
        selected_vol = &m_volumes.at(selected);
    }

    ui->driveList->clear();
    std::vector<volumeDescriptor> v_volumes;
    m_volumes.clear();
    GetVolumes(&v_volumes);
    for (volumeDescriptor vol : v_volumes)
    {
        if(!vol.removableMedia)
            continue;

        QString drivename;
        if(vol.mountPt.length())
            drivename.append(QString::fromWCharArray(vol.mountPt.c_str()).toUpper() + ":\\ - ");

        if(vol.vId.length())
            drivename.append(QString::fromStdString(vol.vId) + " ");
        drivename.append(QString::fromStdString(vol.pId));
        drivename.append(" (" + QString::fromStdString(GetReadableSize(vol.size)) + ")");

        QListWidgetItem *item = new QListWidgetItem(drivename);
        if (nullptr != selected_vol && vol == *selected_vol)
            item->setSelected(true);
        ui->driveList->insertItem(ui->driveList->count(), item);
        m_volumes.push_back(vol);
    }


}

void Emunand::listDisks()
{
    diskDescriptor *selected_disk = nullptr;
    if(ui->driveList->selectedItems().count())
    {
        QListWidgetItem *item = ui->driveList->selectedItems().at(0);
        int selected = 0;
        for(int i(0); i < ui->driveList->count(); i++)
        {
            if(ui->driveList->item(i) == item)
                selected = i;
        }
        selected_disk = &m_disks.at(selected);
    }

    ui->driveList->clear();
    std::vector<diskDescriptor> disks;
    m_disks.clear();
    GetDisks(&disks);

    for (diskDescriptor disk : disks)
    {
        if(!disk.removableMedia)
            continue;

        QString drivename;
        if(disk.vId.length())
            drivename.append(QString::fromStdString(disk.vId) + " ");
        drivename.append(QString::fromStdString(disk.pId));
        drivename.append(" (" + QString::fromStdString(GetReadableSize(disk.size)) + ")");
        if(disk.volumes.size())
        {
            int count = 0;
            QString letters;
            for(volumeDescriptor vol : disk.volumes)
            {
                if(vol.mountPt.length())
                {
                    letters.append((count ? ", " : "") + QString::fromStdWString(vol.mountPt).toUpper() + ":\\");
                    count++;
                }
            }
            if(count)
                drivename.append(" [" + letters + "]");
        }

        QListWidgetItem *item = new QListWidgetItem(drivename);
        if (nullptr != selected_disk && disk == *selected_disk)
            item->setSelected(true);
        ui->driveList->insertItem(ui->driveList->count(), item);
        m_disks.push_back(disk);
    }
}

void Emunand::on_boo0_pushBtn_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this);
    if (!fileName.isEmpty())
    {
        NxStorage storage(fileName.toLocal8Bit().constData());
        if(storage.isNxStorage() && storage.isSinglePartType() && storage.getNxPartition(BOOT0) != nullptr)
            ui->boot0_path->setText(fileName);
        else QMessageBox::critical(nullptr,"Error", "Selected file is not a valid BOOT0 file");
    }
}

void Emunand::on_boo1_pushBtn_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this);
    if (!fileName.isEmpty())
    {
        NxStorage storage(fileName.toLocal8Bit().constData());
        if(storage.isNxStorage() && storage.isSinglePartType() && storage.getNxPartition(BOOT1) != nullptr)
            ui->boot1_path->setText(fileName);
        else QMessageBox::critical(nullptr,"Error", "Selected file is not a valid BOOT1 file");
    }
}

void Emunand::on_emunandType_toggled(int type)
{
    switch (type) {
        case rawBased:
            if(ui->emunandType_SDFileAMSChkBox->isChecked()) ui->emunandType_SDFileAMSChkBox->setChecked(false);
            if(ui->emunandType_SDFileSXChkBox->isChecked()) ui->emunandType_SDFileSXChkBox->setChecked(false);
            if(!ui->emunandType_PartitionChkBox->isChecked()) ui->emunandType_PartitionChkBox->setChecked(true);
            ui->emunandType_lbl->setText(
                "An hidden partition for emuNAND will be created on target disk.\n"
                "A second partition (FAT32) for user purpose (SD Files) will be \n"
                "created with space left. All data on target disk will be erased.\n"
                "emuNAND will be compatible with both Atmosphere and SX OS."
            );
            ui->driveListBox->setTitle("Select target disk:");
            listDisks();
            m_driveList_type = DISK;
            m_emu_type = rawBased;
            break;

        case fileBasedAMS:
            if(ui->emunandType_SDFileSXChkBox->isChecked()) ui->emunandType_SDFileSXChkBox->setChecked(false);
            if(ui->emunandType_PartitionChkBox->isChecked()) ui->emunandType_PartitionChkBox->setChecked(false);
            if(!ui->emunandType_SDFileAMSChkBox->isChecked()) ui->emunandType_SDFileAMSChkBox->setChecked(true);
            ui->emunandType_lbl->setText(
                "This will create a file based emuNAND and needed files for\n"
                "Atmosphere CFW on target volume."
            );
            ui->driveListBox->setTitle("Select target volume:");
            listVolumes();
            m_driveList_type = VOLUME;
            m_emu_type = fileBasedAMS;
            break;

        case fileBasedSXOS:
            if(ui->emunandType_SDFileAMSChkBox->isChecked()) ui->emunandType_SDFileAMSChkBox->setChecked(false);
            if(ui->emunandType_PartitionChkBox->isChecked()) ui->emunandType_PartitionChkBox->setChecked(false);
            if(!ui->emunandType_SDFileSXChkBox->isChecked()) ui->emunandType_SDFileSXChkBox->setChecked(true);
            ui->emunandType_lbl->setText(
                "This will create a file based emuNAND and needed files for\n"
                "SX OS CFW on target volume."
            );
            ui->driveListBox->setTitle("Select target volume:");
            listVolumes();
            m_driveList_type = VOLUME;
            m_emu_type = fileBasedSXOS;
            break;
    }

    ui->outBar->setValue(0);
    ui->outBar->setFormat("");
    ui->outLbl1->setText("");
    ui->outLbl2->setText("");
    ui->outPix1->setVisible(false);
    ui->outPix2->setVisible(false);

    QString st = QString (
                    "QProgressBar::chunk {"
                        "background-color: #eeeeee;}"
                    "QProgressBar {"
                        "border: 1px solid grey;"
                        "border-radius: 2px;"
                        "text-align: center;"
                        "background: #eeeeee;}");
    ui->outBar->setStyleSheet(st);

}

void Emunand::on_emunandType_PartitionChkBox_clicked()
{
    on_emunandType_toggled(rawBased);
}

void Emunand::on_emunandType_SDFileAMSChkBox_clicked()
{
    on_emunandType_toggled(fileBasedAMS);
}

void Emunand::on_emunandType_SDFileSXChkBox_clicked()
{
    on_emunandType_toggled(fileBasedSXOS);
}

void Emunand::on_driveList_itemSelectionChanged()
{
    if(nullptr == input)
        return;

    if(!ui->driveList->selectedItems().count())
        return;

    QListWidgetItem *item = ui->driveList->selectedItems().at(0);
    int selected = 0;
    for(int i(0); i < ui->driveList->count(); i++)
    {
        if(ui->driveList->item(i) == item)
            selected = i;
    }

    bool error = false;
    if(m_driveList_type == DISK)
    {
        diskDescriptor *disk = &m_disks.at(selected);
        u64 emuNandSize = input->size();

        if(emuNandSize > disk->size)
        {
            ui->outBar->setFormat("NOT ENOUGH SPACE !");
            error = true;
        }
        else
        {
            u64 userPartSize = disk->size - emuNandSize;
            ui->outPathLbl->setText(QString("\\\\.\\PhysicalDrive").append(QString::number(disk->diskNumber)));

            unsigned int emuNandPct = emuNandSize * 100 / (disk->size);
            ui->outBar->setValue(emuNandPct);
            ui->outLbl1->setText("emuNAND: " + QString::fromStdString(GetReadableSize(emuNandSize)));
            ui->outLbl2->setText("User partition: " + QString::fromStdString(GetReadableSize(userPartSize)));
            ui->outPix2->setGeometry(170, ui->outPix2->y(), ui->outPix2->width(), ui->outPix2->height());
            ui->outLbl2->setGeometry(190, ui->outLbl2->y(), ui->outLbl2->width(), ui->outLbl2->height());
        }

    }

    if(m_driveList_type == VOLUME)
    {
        volumeDescriptor *vol = &m_volumes.at(selected);
        u64 emuNandSize = input->size();
        ui->outPathLbl->setText(QString::fromStdWString(vol->mountPt) + ":");

        u64 freeSpace = 0;
        DWORD dwSectPerClust, dwBytesPerSect, dwFreeClusters, dwTotalClusters;
        std::wstring volName = vol->volumeName;
        volName.append(L"\\");
        if(GetDiskFreeSpace(volName.c_str(), &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters))
            freeSpace = (u64)dwFreeClusters * dwSectPerClust * dwBytesPerSect;

        if(emuNandSize > freeSpace)
        {
            ui->outBar->setFormat("NOT ENOUGH SPACE !");
            error = true;
        }
        else
        {
            u64 usedBytes = vol->size - u64(freeSpace - emuNandSize);
            unsigned int usedSpace = usedBytes * 100 / vol->size;
            ui->outBar->setValue(usedSpace);
            ui->outLbl1->setText("Used space + emuNand: " + QString::fromStdString(GetReadableSize(usedBytes)));
            ui->outLbl2->setText("Free space: " + QString::fromStdString(GetReadableSize(freeSpace - emuNandSize)));
            ui->outPix2->setGeometry(205, ui->outPix2->y(), ui->outPix2->width(), ui->outPix2->height());
            ui->outLbl2->setGeometry(225, ui->outLbl2->y(), ui->outLbl2->width(), ui->outLbl2->height());
        }
    }

    QString st;
    if(error)
    {
        st = QString (
            "QProgressBar::chunk {"
                "background-color: #eeeeee;}"
            "QProgressBar {"
                "border: 1px solid grey;"
                "border-radius: 2px;"
                "text-align: center;"
                "background: #eeeeee;}");

        ui->outPix1->setVisible(false);
        ui->outPix2->setVisible(false);
        ui->outLbl1->setVisible(false);
        ui->outLbl2->setVisible(false);

    } else {
        st = QString (
            "QProgressBar::chunk {"
                "background-color: #7cd0aa;}"
            "QProgressBar {"
                "border: 1px solid grey;"
                "border-radius: 2px;"
                "text-align: center;"
                "background: #3346A4;}");

        ui->outPix1->setVisible(true);
        ui->outPix2->setVisible(true);
        ui->outLbl1->setVisible(true);
        ui->outLbl2->setVisible(true);
        ui->outBar->setFormat("");
    }
    ui->outBar->setStyleSheet(st);
}

void Emunand::on_createEmunandBtn_clicked()
{
    std::vector<QString> errors;

    if(nullptr == input)
        return error("Input is missing");
    else if(not_in(input->type, { RAWNAND, RAWMMC}))
        return error("Input must be RAWNAND or FULL NAND");

    if(!ui->driveList->selectedItems().count())
        return;

    m_par.emunand_type = m_emu_type;

    std::string output(ui->outPathLbl->text().toLocal8Bit().constData());
    if (is_in(m_emu_type, {fileBasedAMS, fileBasedSXOS}))
    {
        string volumename("\\\\.\\ :");
        volumename.at(4) = output.at(0);
        output = volumename;
    }

    // Do WORK
    WorkerInstance wi(this, create_emunand, &m_par, input, output.c_str());
    wi.exec();

}
void Emunand::error(QString err)
{
    QMessageBox::critical(nullptr,"Error", err);
}
