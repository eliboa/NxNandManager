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

    timer1000();
    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timer1000()));
    timer->start(1000);
}

Emunand::~Emunand()
{
    delete ui;
}

// This timer is used to update m_volumes & m_disks every seconds
// Depending on selected emunand's type, the drive list will be update when new volume/disk is (un)mounted
void Emunand::timer1000()
{
    if (stop_timer) return;

    // Update disks
    std::vector<diskDescriptor> disks, removableDisks, disks_tmp;
    GetDisks(&disks);
    for (diskDescriptor disk : disks)
    {
        if(disk.removableMedia)
            removableDisks.push_back(disk);
    }
    disks_tmp = m_disks;
    if (removableDisks.size() != disks_tmp.size() || (disks_tmp.size() && !std::equal(disks_tmp.begin(), disks_tmp.end(), removableDisks.begin())))
    {
       m_disks = removableDisks;
       if (m_driveList_type == DISK) updateDisksList();
    }

    // Update volumes
    std::vector<volumeDescriptor> volumes, removableVolumes, volumes_tmp;
    GetVolumes(&volumes);
    for (volumeDescriptor volume : volumes)
    {
        if (volume.removableMedia)
            removableVolumes.push_back(volume);
    }
    volumes_tmp = m_volumes;
    if (removableVolumes.size() != volumes_tmp.size() || (volumes_tmp.size() && !std::equal(volumes_tmp.begin(), volumes_tmp.end(), removableVolumes.begin())))
    {
        m_volumes = removableVolumes;
        if (m_driveList_type == VOLUME) updateVolumesList();
    }

}

void Emunand::updateVolumesList()
{
    stop_timer = true;

    // Get selected volume
    BOOL isSelected = false;
    std::wstring selected_vol;
    if(ui->driveList->selectedItems().count() && m_driveList_type == VOLUME)
    {
        QListWidgetItem *item = ui->driveList->selectedItems().at(0);
        int selected = -1;
        for(int i(0); i < ui->driveList->count(); i++)
        {
            if(ui->driveList->item(i) == item)
                selected = i;
        }       
        if(selected > -1 && l_volumes.size())
        {
            selected_vol.append(l_volumes.at(selected).volumeName);
            isSelected = true;
        }
    }

    ui->driveList->clear();

    // Add WidgetItems to driveList
    for (volumeDescriptor vol : m_volumes)
    {
        QString drivename;
        if(vol.mountPt.length())
            drivename.append(QString::fromWCharArray(vol.mountPt.c_str()).toUpper() + ":\\ - ");

        if(vol.vId.length()) drivename.append(QString::fromStdString(vol.vId) + " ");
        drivename.append(QString::fromStdString(vol.pId));
        drivename.append(" (" + QString::fromStdString(GetReadableSize(vol.size)) + ")");

        QListWidgetItem *item = new QListWidgetItem(drivename);
        ui->driveList->insertItem(ui->driveList->count(), item);

        if (isSelected && vol.volumeName == selected_vol)
            ui->driveList->setCurrentItem(item);
    }

    // Save disks
    l_volumes = m_volumes;
    stop_timer = false;
}

void Emunand::updateDisksList()
{
    stop_timer = true;
    // Get selected disk
    DWORD selected_disk;
    BOOL isSelected = false;
    if(ui->driveList->selectedItems().count() && m_driveList_type == DISK)
    {
        QListWidgetItem *item = ui->driveList->selectedItems().at(0);
        int selected = -1;
        for(int i(0); i < ui->driveList->count(); i++)
        {
            if(ui->driveList->item(i) == item)
                selected = i;
        }
        if(selected > -1 && l_disks.size())
        {
            selected_disk = l_disks.at(selected).diskNumber;
            isSelected = true;
        }
    }

    ui->driveList->clear();

    // Add WidgetItems to driveList
    for (diskDescriptor disk : m_disks)
    {
        QString drivename;
        if(disk.vId.length()) drivename.append(QString::fromStdString(disk.vId) + " ");
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
        ui->driveList->insertItem(ui->driveList->count(), item);

        if (isSelected && disk.diskNumber == selected_disk)
            ui->driveList->setCurrentItem(item);
    }

    // Save disks
    l_disks = m_disks;
    stop_timer = false;
}

void Emunand::on_boo0_pushBtn_clicked()
{
    QString fileName = FileDialog(this, fdMode::open_file);
    if (!fileName.isEmpty())
    {
        NxStorage storage(fileName.toLocal8Bit().constData());
        if(storage.isNxStorage() && storage.isSinglePartType() && storage.getNxPartition(BOOT0) != nullptr)
        {
            ui->boot0_path->setText(fileName);
            sprintf_s(m_par.boot0_path, 260, "%s", fileName.toLocal8Bit().constData());
        }
        else QMessageBox::critical(nullptr,"Error", "Selected file is not a valid BOOT0 file");
    }
}

void Emunand::on_boo1_pushBtn_clicked()
{
    QString fileName = FileDialog(this, fdMode::open_file);
    if (!fileName.isEmpty())
    {
        NxStorage storage(fileName.toLocal8Bit().constData());
        if(storage.isNxStorage() && storage.isSinglePartType() && storage.getNxPartition(BOOT1) != nullptr)
        {
            ui->boot1_path->setText(fileName);
            sprintf_s(m_par.boot1_path, 260, "%s", fileName.toLocal8Bit().constData());
        }
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
            updateDisksList();
            m_driveList_type = DISK;
            m_emu_type = rawBased;
            break;

        case fileBasedAMS:
            if(ui->emunandType_SDFileSXChkBox->isChecked()) ui->emunandType_SDFileSXChkBox->setChecked(false);
            if(ui->emunandType_PartitionChkBox->isChecked()) ui->emunandType_PartitionChkBox->setChecked(false);
            if(!ui->emunandType_SDFileAMSChkBox->isChecked()) ui->emunandType_SDFileAMSChkBox->setChecked(true);
            ui->emunandType_lbl->setText(
                "This will create file based emuNAND and needed files for\n"
                "Atmosphere CFW on target volume."
            );
            ui->driveListBox->setTitle("Select target volume:");
            updateVolumesList();
            m_driveList_type = VOLUME;
            m_emu_type = fileBasedAMS;
            break;

        case fileBasedSXOS:
            if(ui->emunandType_SDFileAMSChkBox->isChecked()) ui->emunandType_SDFileAMSChkBox->setChecked(false);
            if(ui->emunandType_PartitionChkBox->isChecked()) ui->emunandType_PartitionChkBox->setChecked(false);
            if(!ui->emunandType_SDFileSXChkBox->isChecked()) ui->emunandType_SDFileSXChkBox->setChecked(true);
            ui->emunandType_lbl->setText(
                "This will create file based emuNAND and needed files for\n"
                "SX OS CFW on target volume."
            );
            ui->driveListBox->setTitle("Select target volume:");
            updateVolumesList();
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
    on_driveList_itemSelectionChanged();
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

    m_notEnoughSpace = false;
    if(m_driveList_type == DISK)
    {
        diskDescriptor *disk = &m_disks.at(selected);
        u64 emuNandSize = input->size();

        if(emuNandSize > disk->size)
        {
            ui->outBar->setFormat("NOT ENOUGH SPACE !");
            m_notEnoughSpace = true;
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
            m_notEnoughSpace = true;
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
    if(m_notEnoughSpace)
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

    if (m_notEnoughSpace)
        return error("Not enough space on target volume/disk");

    if (input->type == RAWNAND)
    {
        NxStorage boot0((const char*) m_par.boot0_path);
        if (boot0.type != BOOT0)
            return error("Input BOOT0 is missing or invalid");

        NxStorage boot1((const char*) m_par.boot1_path);
        if (boot1.type != BOOT1)
            return error("Input BOOT1 is missing or invalid");
    }

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

    if (m_emu_type == rawBased && QMessageBox::question(this, "Warning", "All data on target disk will be lost. Are you sure you want to continue ?", QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
        return;

    // Do WORK
    stop_timer = true;
    WorkerInstance wi(this, create_emunand, &m_par, input, output.c_str());
    wi.exec();
    stop_timer = false;
}
void Emunand::error(QString err)
{
    QMessageBox::critical(nullptr,"Error", err);
}
