#ifndef RESIZEUSER_H
#define RESIZEUSER_H

#include <QDialog>
#include <QFileDialog>
#include <QSettings>
#include "../res/utils.h"
#include "../NxStorage.h"
#include "worker.h"

namespace Ui {
class ResizeUser;
}

class ResizeUser : public QDialog
{
    Q_OBJECT

public:
    explicit ResizeUser(QWidget *parent = nullptr, NxStorage *input = nullptr);
    ~ResizeUser();

private:
    Ui::ResizeUser *ui;
    QWidget *parent;
    NxStorage *input;

private slots:
    void on_checkBox_stateChanged(int arg1);
    void on_new_size_valueChanged(int arg1);
    void on_selectFileButton_clicked();
    void on_buttonBox_accepted();

signals:
    void finished(QString file, int new_size, bool format);
};

#endif // RESIZEUSER_H
