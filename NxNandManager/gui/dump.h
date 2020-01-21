#ifndef DUMP_H
#define DUMP_H

#include <QDialog>
#include <QFileDialog>
#include <QMessageBox>
#include <QAction>
#include "../res/utils.h"
#include "../NxStorage.h"
#include "worker.h"
#include "progress.h"

QT_BEGIN_NAMESPACE
class QAction;
class Worker;

namespace Ui {
class Dump;
}

class Dump : public QDialog
{
    Q_OBJECT

public:
    explicit Dump(QWidget *parent, NxStorage* input, int in_part = UNKNOWN);
    ~Dump();

private slots:
    void on_selectOutputBtn_clicked();
    void on_splitCheckBox_stateChanged(int arg1);
    void on_ptZeroesCheckBox_stateChanged(int arg1 = 0);
    void on_encryptValue_toggled(bool checked);
    void on_decryptValue_toggled(bool checked);
    void on_noCryptotValue_toggled(bool checked);
    void on_formatUserCheckBox_stateChanged(int arg1);
    void on_pushButton_clicked();

private:
    Ui::Dump *ui;
    NxStorage* m_input;
    Worker* workThread;
    params_t m_par;
    u64 m_in_size = 0;
    bool m_good_crypto = false;
    bool m_previous_bypassMD5 = false;
    Progress* progressDialog;
    void on_crypto_changed();
    void lock_md5CheckBox(bool checked = true);
    void unlock_md5CheckBox();
};

#endif // DUMP_H
