#ifndef EMUNAND_H
#define EMUNAND_H

#include <QDialog>
#include <QFileDialog>
#include <QStorageInfo>
#include <QListWidgetItem>
#include "qutils.h"
#include "../res/utils.h"
#include "../NxStorage.h"
#include "worker.h"
#include <windows.h>
#include <winioctl.h>

#define SD_PARTITION  0x01
#define SD_FILE_AMS   0x02
#define SD_FILE_SX    0x03

#define VOLUME        0xC0
#define DISK          0xC1

namespace Ui {
class Emunand;
}

class Emunand : public QDialog
{
    Q_OBJECT

public:
    explicit Emunand(QWidget *parent, NxStorage *input = nullptr);
    ~Emunand();

private slots:
    void on_boo0_pushBtn_clicked();
    void on_boo1_pushBtn_clicked();
    void on_emunandType_PartitionChkBox_clicked();
    void on_emunandType_SDFileAMSChkBox_clicked();
    void on_emunandType_SDFileSXChkBox_clicked();
    void on_driveList_itemSelectionChanged();
    void timer1000();
    void on_createEmunandBtn_clicked();

private:
    Ui::Emunand *ui;
    QWidget *parent;
    NxStorage *input = nullptr;
    std::vector<volumeDescriptor> m_volumes;
    std::vector<diskDescriptor> m_disks;
    std::vector<volumeDescriptor> l_volumes;
    std::vector<diskDescriptor> l_disks;
    int m_driveList_type = 0;
    params_t m_par;
    EmunandType m_emu_type;
    bool stop_timer = false;
    bool m_notEnoughSpace = false;
    void on_emunandType_toggled(int type);
    void error(QString err);
    void updateVolumesList();
    void updateDisksList();

signals:
    void finished();
};

#endif // EMUNAND_H
