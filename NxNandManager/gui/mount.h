#ifndef MOUNT_H
#define MOUNT_H

#include <QDialog>
#include "../NxPartition.h"
#include <QMovie>

namespace Ui {
class MountDialog;
}

class MountDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MountDialog(QWidget *parent, NxPartition* partition);
    ~MountDialog();

private slots:
    void on_mountButton_clicked();
    void dokanDriver_install();
    void on_mounting_done();

private:
    Ui::MountDialog *ui;
    NxPartition* m_nxp;
    QMovie *loading;

signals:
    void error(int, QString s = nullptr);
    void dokanDriver_install_signal();
    void on_mounting_done_signal();

};

#endif // MOUNT_H
