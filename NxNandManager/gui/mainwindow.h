/*
 * Copyright (c) 2019 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTimer>
#include <QtWinExtras>
#include <QtWinExtras>
#include <QWinTaskbarProgress>
#include <QTableWidgetItem>
#include "../res/progress_info.h"
#include "../NxStorage.h"
#include "qutils.h"
#include "worker.h"
#include "opendrive.h"
#include "keyset.h"
#include "properties.h"
#include "resizeuser.h"
#include "emunand.h"
#include "dump.h"
#include "debug.h"
//#include "explorer.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;
class Worker;

namespace Ui {
    class MainWindow;
}
using namespace std;


class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();
	Worker *workerThread;

private:
	Ui::MainWindow *ui;
    OpenDrive* openDriveDialog = nullptr;
    KeySetDialog* keysetDialog = nullptr;
    Properties* PropertiesDialog = nullptr;
    ResizeUser* ResizeUserDialog;
    Emunand* EmunandDialog;
    Dump* DumpDialog;
    Debug* DebugDialog = nullptr;
    //Explorer* ExplorerDialog;


	NxStorage* input;
    NxStorage* selected_io = nullptr;
    NxPartition *selected_part;
	bool m_ready;
	Worker* workThread;

	int cur_operation = 0;
	QWinTaskbarButton *TaskBarButton;
	QWinTaskbarProgress *TaskBarProgress;
	bool bTaskBarSet = FALSE;
    bool bKeyset;
    int elapsed_seconds = 0;

	void initButtons();
    void beforeInputSet();

protected:
	void showEvent(QShowEvent *e) override;
    void closeEvent(QCloseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private slots:
	void open();
	void openDrive();
    void Properties();
    void openKeySet();
    void openResizeDialog();
    void openEmunandDialog();
    void openDumpDialog(int partition = UNKNOWN);
    void openDebugDialog();
    void incognito();
    void dumpPartition(int crypto_mode=NULL);
    void dumpPartitionAdvanced();
    void dumpDecPartition();
    void dumpEncPartition();
	void restorePartition();
	void toggleAutoRCM();
    void formatPartition();
    void on_rawdump_button_clicked(int crypto_mode, bool rawnand_dump);
    void on_rawdumpDec_button_clicked();
    void on_rawdumpEnc_button_clicked();
    void on_rawdump_button();
    void dumpRAWNAND();
	void on_fullrestore_button_clicked();
	void on_partition_table_itemSelectionChanged();
    void on_moreinfo_button_clicked();    
    void on_rawdump_button_clicked();

public slots:
    //void startWorkThread(WorkParam_t param);
	void inputSet(NxStorage *storage = nullptr);
	void driveSet(QString);
    void resizeUser(QString file, int new_size, bool format);
    //void openExplorer();
    void keySetSet();
	void error(int err, QString label = nullptr);

public:
    KeySet biskeys;
};

#endif // MAINWINDOW_H
