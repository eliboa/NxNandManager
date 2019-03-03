#include "ui_opendrive.h"
#include "opendrive.h"

OpenDrive::OpenDrive(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    //ui->listWidget->insertItem(0, new QListWidgetItem("Test"));
    connect(this, SIGNAL(finished(QString)), parent, SLOT(driveSet(QString)));

    QString drives = QString(ListPhysicalDrives(TRUE).c_str());
    QString drivename;
    int li = 0;
    for (int i = 0; i < drives.count(); ++i)
    {
        if(drives[i] == '\n' && drives.count() > 0)
        {
            drivename = drivename.toUpper();
            ui->listWidget->insertItem(li, new QListWidgetItem(drivename));
            drivename.clear();
            li++;
        } else {
            drivename += drives[i];
        }
    }
}

OpenDrive::~OpenDrive()
{
    delete ui;
}

void OpenDrive::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{
    emit finished(item->text());
    close();
}
