#include "ui_opendrive.h"
#include "opendrive.h"

OpenDrive::OpenDrive(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogOpenDrive)
{
    ui->setupUi(this);
    connect(this, SIGNAL(finished(QString)), parent, SLOT(driveSet(QString)));

    ui->listWidget->setEnabled(false);
    ui->listWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
    setWindowTitle("Physical drives");

    Worker* workThread = new Worker(this);
    workThread->start();
}

OpenDrive::~OpenDrive()
{
    delete ui;
}
void OpenDrive::ShowLabel()
{
    ui->listWidget->setEnabled(false);
    ui->listWidget->hide();
    ui->label->setEnabled(true);
    ui->label->show();
}
void OpenDrive::ListDrives(QString drives)
{
    //QString drives = QString(ListPhysicalDrives().c_str());
    ui->label->setEnabled(false);
    ui->label->hide();
    ui->listWidget->setEnabled(true);
    ui->listWidget->show();
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

void OpenDrive::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{    
    emit finished(item->text().left(item->text().indexOf(" ")));
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
                QString item = parent->ui->listWidget->selectedItems().first()->text();
                emit parent->finished(item.left(item.indexOf(" ")));
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

void OpenDrive::list_callback(QString drives)
{
    ListDrives(drives);
}


