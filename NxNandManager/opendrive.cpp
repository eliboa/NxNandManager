#include "ui_opendrive.h"
#include "opendrive.h"

OpenDrive::OpenDrive(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    connect(this, SIGNAL(finished(QString)), parent, SLOT(driveSet(QString)));

    QString drives = QString(ListPhysicalDrives(TRUE).c_str());
    QString drivename;
    int li = 0;
    for (int i = 0; i < drives.count(); ++i)
    {
        if(drives[i] == '\n' && drives.count() > 0)
        {
            drivename = drivename.toUpper();
            QListWidgetItem *item = new QListWidgetItem(drivename);
            ui->listWidget->insertItem(li, item);
            drivename.clear();
            ui->listWidget->setCurrentItem(item);
            li++;
        } else {
            drivename += drives[i];
        }
    }    
    keyEnterReceiver* key = new keyEnterReceiver();
    this->installEventFilter(key);
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

bool keyEnterReceiver::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type()==QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ( (key->key()==Qt::Key_Enter) || (key->key()==Qt::Key_Return) ) {
            OpenDrive *parent = (OpenDrive *) obj;
            if(parent->ui->listWidget->selectedItems().count() > 0)
            {
                emit parent->finished(parent->ui->listWidget->selectedItems().first()->text());
                parent->close();
            }

        } else {
            return QObject::eventFilter(obj, event);
        }
        return true;
    } else {
        return QObject::eventFilter(obj, event);
    }
    return false;
}

