#include "mount.h"
#include "ui_mount.h"
#include "../res/utils.h"
#include "mainwindow.h"
#include <QtConcurrent/QtConcurrent>
#include <QProcess>

MountDialog::MountDialog(QWidget *parent, NxPartition* partition) :
    QDialog(parent),
    ui(new Ui::MountDialog), m_nxp(partition)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
    setWindowTitle(QString("Mount %1 (virtual disk, virtual fs)").arg(QString::fromStdString(m_nxp->partitionName())));

    auto mainwin = reinterpret_cast<MainWindow*>(parent);
    connect(this, &MountDialog::error, mainwin, &MainWindow::error);
    connect(this, &MountDialog::dokanDriver_install_signal, this, &MountDialog::dokanDriver_install);

    loading = new QMovie(":/images/loading_wheel.gif");
    loading->setScaledSize(QSize(25, 25));
    ui->loadingLabel->setMovie(loading);
    loading->start();
    ui->loadingLabel->hide();
    auto mount_points = GetAvailableMountPoints();
    auto cmb = ui->mountPointComboBox;
    for (const auto mount_point : mount_points)
        cmb->insertItem(cmb->count(), QString(mount_point).toUpper() + ":", QString(mount_point));
}

MountDialog::~MountDialog()
{
    delete ui;
    delete loading;
    disconnect(this);
    disconnect(m_nxp);
}

void MountDialog::on_mountButton_clicked()
{

    if (ui->mountPointComboBox->currentData().toString().isEmpty())
        return emit error(1, "Drive letter empty!");

    auto mount_point = ui->mountPointComboBox->currentData().toString().toStdWString().at(0);

    m_nxp->disconnect();
    //connect(m_nxp, &NxPartition::vfs_mounted_signal, this, &MountDialog::close);
    connect(m_nxp, &NxPartition::vfs_mounted_signal, [&]() {
        if (ui->openExplorerCheckBox->isChecked()) {
            QProcess process;
            process.start("explorer.exe", QStringList() << QString::fromStdWString(m_nxp->vfs()->mount_point));
            process.waitForFinished(-1); // Synchronous
        }
        done(0);
    });
    connect(m_nxp, &NxPartition::vfs_callback, [&](long status){
        if (status == DOKAN_DRIVER_INSTALL_ERROR)
            emit dokanDriver_install_signal();
        else if (status < -1000)
            emit error((int)status);
        else if (status != DOKAN_SUCCESS)
            emit error(1, QString::fromStdString(dokanNtStatusToStr(status)));

        ui->loadingLabel->hide();
        ui->mountButton->setText("Mount");
        ui->mountButton->setEnabled(true);
    });
    ui->loadingLabel->show();
    ui->mountButton->setText("Mounting...");
    ui->mountButton->setDisabled(true);
    QtConcurrent::run(m_nxp, &NxPartition::mount_vfs, true, mount_point, ui->readOnlyCheckBox->isChecked(), nullptr);
}

void MountDialog::dokanDriver_install()
{
    if(QMessageBox::question(nullptr, "Error", "Dokan driver not found\nDo you want to proceed with installation ?",
             QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
    {
        int res = installDokanDriver();
        if (res)
            emit error(res);
    }
}
