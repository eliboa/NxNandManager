#include "mount.h"
#include "ui_mount.h"
#include "../res/utils.h"
#include "mainwindow.h"
#include <QtConcurrent/QtConcurrent>
#include <QProcess>
#include <QSettings>

MountDialog::MountDialog(QWidget *parent, NxPartition* partition) :
    QDialog(parent),
    ui(new Ui::MountDialog), m_nxp(partition)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
    setWindowTitle(QString("Mount %1").arg(QString::fromStdString(m_nxp->partitionName())));

    auto mainwin = reinterpret_cast<MainWindow*>(parent);
    connect(this, &MountDialog::error, mainwin, &MainWindow::error);
    connect(this, &MountDialog::dokanDriver_install_signal, this, &MountDialog::dokanDriver_install);
    connect(this, &MountDialog::on_mounting_done_signal, this, &MountDialog::on_mounting_done);

    ui->virtualNxaCheckBox->setToolTip("Only applies to NCA under /Contents (& subdirs)<br><img src=':/images/vfs_nca.png'><br>No more 4GB file size limitation");

    loading = new QMovie(":/images/loading_wheel.gif");
    loading->setScaledSize(QSize(25, 25));
    ui->loadingLabel->setMovie(loading);
    loading->start();
    ui->loadingLabel->hide();
    auto mount_points = GetAvailableMountPoints();
    auto cmb = ui->mountPointComboBox;
    for (const auto mount_point : mount_points)
        cmb->insertItem(cmb->count(), QString(mount_point).toUpper() + ":", QString(mount_point));

    QSettings userSettings;
    if (userSettings.contains("mount_readonly"))
        ui->readOnlyCheckBox->setChecked(userSettings.value("mount_readonly").toBool());
    if (userSettings.contains("mount_explorer"))
        ui->openExplorerCheckBox->setChecked(userSettings.value("mount_explorer").toBool());
    if (userSettings.contains("mount_virtualNxa"))
        ui->virtualNxaCheckBox->setChecked(userSettings.value("mount_virtualNxa").toBool());

    auto mntPt_val = userSettings.value(QString("mount_%1_mountPoint").arg(QString::fromStdString(m_nxp->partitionName())));
    for (int ix = 0; ix < ui->mountPointComboBox->count(); ix++)
        if (ui->mountPointComboBox->itemData(ix) == mntPt_val) {
            ui->mountPointComboBox->setCurrentIndex(ix);
            break;
        }
    return;
}

MountDialog::~MountDialog()
{
    QSettings userSettings;
    userSettings.setValue("mount_readonly", ui->readOnlyCheckBox->isChecked());
    userSettings.setValue("mount_explorer", ui->openExplorerCheckBox->isChecked());
    userSettings.setValue("mount_virtualNxa", ui->virtualNxaCheckBox->isChecked());
    auto mntPt_key = QString("mount_%1_mountPoint").arg(QString::fromStdString(m_nxp->partitionName()));
    userSettings.setValue(mntPt_key, ui->mountPointComboBox->currentData());

    delete ui;
    delete loading;
    disconnect(this);
    disconnect(m_nxp);
}

void MountDialog::on_mountButton_clicked()
{

    if (m_nxp->is_vfs_mounted())
    {

        ui->openExplorerCheckBox->setDisabled(false);
        ui->readOnlyCheckBox->setDisabled(false);
        ui->mountPointComboBox->setDisabled(false);
        ui->virtualNxaCheckBox->setDisabled(false);
        ui->loadingLabel->show();
        ui->mountButton->setText("Unmounting...");
        ui->mountButton->setEnabled(false);

        int res = m_nxp->unmount_vfs();
        emit res ? error(res) : on_mounting_done_signal();
    }
    else
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
            emit on_mounting_done_signal();
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
        VFSOptions options = NoOption;
        if (ui->readOnlyCheckBox->isChecked())
            options |= ReadOnly;
        if (ui->virtualNxaCheckBox->isChecked())
            options |= VirtualNXA;

        QtConcurrent::run(m_nxp, &NxPartition::mount_vfs, true, mount_point, options, nullptr);
    }
}

void MountDialog::on_mounting_done()
{
    if (!m_nxp->is_vfs_mounted())
    {
        ui->loadingLabel->hide();
        ui->mountButton->setText("Mount");
        ui->mountButton->setEnabled(true);
        ui->openExplorerCheckBox->setDisabled(false);
        ui->readOnlyCheckBox->setDisabled(false);
        ui->mountPointComboBox->setDisabled(false);
        ui->virtualNxaCheckBox->setDisabled(false);
    }
    else
    {
        ui->loadingLabel->hide();
        ui->mountButton->setText("Unmount");
        ui->mountButton->setEnabled(true);
        ui->openExplorerCheckBox->setDisabled(true);
        ui->readOnlyCheckBox->setDisabled(true);
        ui->mountPointComboBox->setDisabled(true);
        ui->virtualNxaCheckBox->setDisabled(true);
    }
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
