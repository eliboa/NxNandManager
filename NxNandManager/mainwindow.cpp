#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtWidgets>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	bTaskBarSet = FALSE;
	ui->setupUi(this);
	createActions();
    input = nullptr;

	// Init partition table
	QTableWidget *partitionTable = ui->partition_table;
    //partitionTable->resize(330, partitionTable->height());
	partitionTable->setRowCount(0);
    partitionTable->setColumnCount(3);
    partitionTable->setColumnWidth(0, 160);
    partitionTable->setColumnWidth(1, 60);
    partitionTable->setColumnWidth(2, 60);
	QStringList header;
    header<<"Name"<<"Size"<<"Encrypt.";
	partitionTable->setHorizontalHeaderLabels(header);
	QFont font("Calibri", 10, QFont::Bold);
	partitionTable->horizontalHeader()->setFont(font);
	partitionTable->setSelectionBehavior(QAbstractItemView::SelectRows);


	// Init progress bar
    //ui->progressBar->resize(305, ui->progressBar->height());
	ui->progressBar->setValue(0);
	ui->progressBar->setTextVisible(true);
	ui->progressBar->setFormat("");
	ui->progressBar->setAlignment(Qt::AlignCenter);
	setProgressBarStyle();

	TaskBarButton = new QWinTaskbarButton(this);

	// Init timer
	QTimer *timer = new QTimer(this);
	connect(timer, SIGNAL(timeout()), this, SLOT(timer1000()));
	timer->start(1000);

	// Init elapsed & remaining time labels
	QPalette palette;
	palette.setColor(QPalette::WindowText, Qt::gray);
	ui->elapsed_time_label->setPalette(palette);
	ui->remaining_time_label->setPalette(palette);

	// Init buttons
	ui->rawdump_button->setEnabled(false);
	ui->fullrestore_button->setEnabled(false);

    // Keyset bool
    bKeyset = false;
    QFile file("keys.dat");
    if (file.exists())
        bKeyset = true;
}

MainWindow::~MainWindow()
{
	delete ui;
}

void MainWindow::showEvent(QShowEvent *e)
{
	if(!bTaskBarSet)
	{
		TaskBarButton->setWindow(windowHandle());
		TaskBarProgress = TaskBarButton->progress();
		bTaskBarSet = TRUE;
	}
	e->accept();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
	if(workInProgress)
	{
		if(QMessageBox::question(this, "Warning", "Work in progress, are you sure you want to quit ?", QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
		{
			event->ignore();
			return;
		}
	}
	event->accept();
}

void MainWindow::open()
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

	QString fileName = QFileDialog::getOpenFileName(this);
	if (!fileName.isEmpty())
	{
		ui->progressBar->setFormat("Analysing input... please wait.");
		ui->progressBar->setValue(100);
		qApp->processEvents();

		// Open new thread to init storage (callback => inputSet(NxStorage))
		workThread = new Worker(this, fileName);
		workThread->start();
	}
}

void MainWindow::openDrive()
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

    openDriveDialog = new OpenDrive(this);
    openDriveDialog->setWindowTitle("Scanning drives, please wait...");
	openDriveDialog->show();    
    openDriveDialog->ListDrives();
    openDriveDialog->setWindowTitle("Logical drives");
	openDriveDialog->exec();


}

void MainWindow::Properties()
{
    PropertiesDialog = new class Properties(this->input);
    PropertiesDialog->setWindowTitle("Properties");
    PropertiesDialog->show();
    PropertiesDialog->exec();
}

void MainWindow::openKeySet()
{
    if(workInProgress)
    {
        error(ERR_WORK_RUNNING);
        return;
    }

    keysetDialog = new KeySetDialog(this);
    keysetDialog->setWindowTitle("Configure keyset");
    keysetDialog->show();
    keysetDialog->exec();
}

void MainWindow::incognito()
{
    if(workInProgress)
    {
        error(ERR_WORK_RUNNING);
        return;
    }

    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Icon::Warning);
    msgBox.setText("Incognito will wipe out console unique id's and certificates from CAL0");
    msgBox.setInformativeText("WARNING : Make sure you have a backup of PRODINFO partition in case you want to restore CAL0 in the future.\n"
                              "\nDo you already have a backup and do you want to apply incognito now ?");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    int ret = msgBox.exec();

    if(ret == QMessageBox::Yes)
    {
        if(bKeyset && parseKeySetFile("keys.dat", &biskeys) >= 2)
            input->InitKeySet(&biskeys);
        ret = input->Incognito();
        if(ret < 0)
            error(ret);
        else
            QMessageBox::information(nullptr,"Incognito","Incognito successfully applied.");

        input->InitStorage();
    }

}

void MainWindow::on_rawdump_button_clicked(int crypto_mode)
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

	bypassMD5 = FALSE;

	// Create new file dialog
	QFileDialog fd(this);
	fd.setAcceptMode(QFileDialog::AcceptSave); // Ask overwrite
	QString save_filename(input->type == PARTITION ? input->partitionName : input->GetNxStorageTypeAsString());	
    QString ext("");
    if(crypto_mode == ENCRYPT)
        ext.append(".enc");
    else if (crypto_mode == DECRYPT)
        ext.append(".dec");
    else {
        ext.append(".bin");
    }

    QSettings MySettings;
    QString fileName = fd.getSaveFileName(this, "Save as", "default_dir\\" + save_filename + ext);
	if (!fileName.isEmpty())
	{
        QDir CurrentDir;
        MySettings.setValue("default_dir", CurrentDir.absoluteFilePath(fileName));

        bool do_crypto = false;
        if(crypto_mode && bKeyset && parseKeySetFile("keys.dat", &biskeys))
        {
            do_crypto = true;
            input->InitKeySet(&biskeys);
        }
        else
            input->InitKeySet();

		//New output storage
        selected_io = new NxStorage(fileName.toUtf8().constData(), (do_crypto && crypto_mode == ENCRYPT) ? &biskeys : NULL);

		// Open new thread to copy data
		workThread = new Worker(this, input, selected_io, DUMP, bypassMD5);
		startWorkThread();
	}
}

void MainWindow::on_rawdumpDec_button_clicked()
{
    on_rawdump_button_clicked(DECRYPT);
}

void MainWindow::on_rawdumpEnc_button_clicked()
{
    on_rawdump_button_clicked(ENCRYPT);
}

void MainWindow::dumpPartition(int crypto_mode)
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

	bypassMD5 = FALSE;

	QModelIndexList indexes = ui->partition_table->selectionModel()->selectedRows();
	for (int i = 0; i < indexes.count(); ++i)
	{
		// Get partition name
		QString cur_partition(ui->partition_table->item(indexes.at(i).row(), 0)->text());
        GptPartition *curPartition = input->GetPartitionByName(cur_partition.toUtf8().constData());
        QString ext("");
        if(nullptr != curPartition)
        {
            if(crypto_mode == ENCRYPT)
                ext.append(".enc");
            else if (crypto_mode == DECRYPT)
                ext.append(".dec");
        }

		// Create new file dialog        
		QFileDialog fd(this);
		fd.setAcceptMode(QFileDialog::AcceptSave); // Ask overwrite
        QSettings MySettings;
        QString fileName = fd.getSaveFileName(this, "Save as", "default_dir\\" + cur_partition + ext); // Default filename is partition name
		if (!fileName.isEmpty())
		{
            QDir CurrentDir;
            MySettings.setValue("default_dir", CurrentDir.absoluteFilePath(fileName));

            bool do_crypto = false;
            if(crypto_mode && bKeyset && parseKeySetFile("keys.dat", &biskeys))
            {
                do_crypto = true;
                input->InitKeySet(&biskeys);
            }
            else
                input->InitKeySet();

            //New output storage
            selected_io = new NxStorage(fileName.toUtf8().constData());
            if(crypto_mode == ENCRYPT)
            {
                do_crypto = true;
                selected_io->InitKeySet(&biskeys);
            }


			// Open new thread to copy data
			workThread = new Worker(this, input, selected_io, DUMP, bypassMD5, cur_partition.toUtf8().constData());
			startWorkThread();
		}

	}
}

void MainWindow::dumpDecPartition()
{
    //QMessageBox::critical(nullptr,"Error","dumpDecPartition");
    dumpPartition(DECRYPT);
}

void MainWindow::dumpEncPartition()
{
    //QMessageBox::critical(nullptr,"Error","dumpDecPartition");
    dumpPartition(ENCRYPT);
}

void MainWindow::restorePartition()
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}
	bypassMD5 = TRUE;

	QModelIndexList indexes = ui->partition_table->selectionModel()->selectedRows();
	for (int i = 0; i < indexes.count(); ++i)
	{
		// Get partition name & size
		QString cur_partition(ui->partition_table->item(indexes.at(i).row(), 0)->text());
		QString Scur_size(ui->partition_table->item(indexes.at(i).row(), 1)->text());
		u64 cur_size = input->IsValidPartition(cur_partition.toUtf8().constData());


		QString fileName = QFileDialog::getOpenFileName(this);
		if (!fileName.isEmpty())
		{
			selected_io = new NxStorage(fileName.toUtf8().constData());

			QString message, warnings;
			std::string Sbasename = remove_extension(base_name(std::string(fileName.toUtf8().constData())));
			QString basename(Sbasename.c_str());
			if(selected_io->size != cur_size) warnings.append(QString("- Input file size (%1) doesn't match partition size (%2)\n").arg(QString(GetReadableSize(selected_io->size).c_str())).arg(Scur_size));
			if(basename != cur_partition) warnings.append(QString("- Input filename (%1) doesn't match partition name (%2)\n").arg(basename).arg(cur_partition));
			if(selected_io->type != PARTITION ) warnings.append(QString("- Input file type (%1) doesn't match output type (PARTITION)\n").arg(QString(selected_io->GetNxStorageTypeAsString())));

			//QString type = input->isDrive ? "drive" : "file";
			message.append(QString("You are about to restore partition to existing rawnand %1\n").arg(input->isDrive ? "drive" : "file"));

			if(warnings.count()>0)
			{
				message.append("\nWARNINGS :\n");
				message.append(warnings);
			}

			message.append("\nAre you sure you want to continue ?");
			if(QMessageBox::question(this, "Warning", message, QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
			{
				return;
			}

            // Default is not to use crypto.
            input->InitKeySet();
            selected_io->InitKeySet();

            // Restoring to RAWNAND : key set provided & file to restore is not encrypted
            if((input->type == RAWNAND || input->type == RAWMMC) && bKeyset && !selected_io->isEncrypted)
            {
                // Only try to encrypt native encrypted partitions or full rawnand
                if(selected_io->type == RAWNAND || selected_io->type == RAWMMC|| (selected_io->type == PARTITION && (QString(selected_io->partitionName) == "PRODINFO" || QString(selected_io->partitionName) == "PRODINFOF" ||
                   QString(selected_io->partitionName) == "SAFE" || QString(selected_io->partitionName) == "SYSTEM" || QString(selected_io->partitionName) == "USER")))
                {
                    input->InitKeySet(&biskeys);
                    selected_io->InitKeySet(&biskeys);
                }

            }

            /*
            // Set crypto for decrypted partitions (if keyset provided)
            if(!selected_io->isEncrypted && selected_io->type == PARTITION && bKeyset &&
               (QString(selected_io->partitionName) == "PRODINFO" || QString(selected_io->partitionName) == "PRODINFOF" ||
                QString(selected_io->partitionName) == "SAFE" || QString(selected_io->partitionName) == "SYSTEM" || QString(selected_io->partitionName) == "USER"))
            {
                input->InitKeySet(&biskeys);
                selected_io->InitKeySet(&biskeys);
            } else {
                input->InitKeySet();
                selected_io->InitKeySet();
            }
            */

			// Open new thread to restore data
			workThread = new Worker(this, selected_io, input, RESTORE, bypassMD5, cur_partition.toUtf8().constData());
			startWorkThread();

		}
	}

}

void MainWindow::initButtons()
{
	ui->rawdump_button->setText("FULL DUMP");
	if(input->type == INVALID || input->type == UNKNOWN)
	{
		ui->rawdump_button->setEnabled(false);
		ui->fullrestore_button->setEnabled(false);
	}
    if((input->type == RAWNAND || input->type == RAWMMC) && nullptr != input->firstPartion)
	{
		ui->rawdump_button->setEnabled(true);
		if(!input->isSplitted) ui->fullrestore_button->setEnabled(true);
		else {
			ui->fullrestore_button->setEnabled(false);
			ui->rawdump_button->setText("JOIN DUMP");
		}
	}
	if(input->type == BOOT0 || input->type == BOOT1 || input->type == PARTITION)
	{
		if(input->type == PARTITION) ui->fullrestore_button->setEnabled(false);
		else ui->fullrestore_button->setEnabled(true);
		ui->rawdump_button->setEnabled(true);
	}
}

void MainWindow::inputSet(NxStorage *storage)
{
	input = storage;

	// Clear table
    ui->partition_table->setRowCount(0);
    ui->partition_table->setStatusTip(tr(""));

	ui->progressBar->setFormat("");
	ui->progressBar->setValue(0);

    ui->menuFile->actions().at(8)->setDisabled(true);
    ui->menuFile->actions().at(6)->setDisabled(true);
    ui->menuFile->actions().at(5)->setDisabled(true);
    ui->menuFile->actions().at(4)->setDisabled(true);
    ui->menuFile->actions().at(3)->setDisabled(true);
    ui->menuTools->actions().at(1)->setDisabled(true);
    ui->menuTools->actions().at(2)->setDisabled(true);

    QString path = QString::fromWCharArray(input->pathLPWSTR), input_label;
    QFileInfo fi(path);
    path = fi.fileName();
    if(input->isDrive && input->type == RAWMMC)
    {
        path.append(" [");
        path.append(n2hexstr(input->mmc.lba_start * NX_EMMC_BLOCKSIZE, 10).c_str());
        path.append(" -> ");
        path.append(n2hexstr((input->mmc.lba_end + 1) * NX_EMMC_BLOCKSIZE - 1, 10).c_str());
        path.append("]");
    }
    ui->filedisk_value->setText(path);
    ui->nxtype_value->setText(input->GetNxStorageTypeAsString());
    ui->size_value->setText(QString(GetReadableSize(input->size).c_str()));
    ui->fwversion_value->setStyleSheet("QLabel { color : #686868; }");
    ui->deviceid_value->setStyleSheet("QLabel { color : #686868; }");
    ui->fwversion_value->setStatusTip("");
    ui->fwversion_value->setText("N/A");
    ui->deviceid_value->setStatusTip("");
    ui->deviceid_value->setText("N/A");

    //createActions();
	initButtons();

	if(input->type == INVALID || input->type == UNKNOWN)
	{
        QString message("Input file/drive is not a valid NX Storage."), buff;
        if(input->b_MayBeNxStorage && input->size <= 0xA0000000)
        {
            message.append("\nMake sure the file name matches the partition's name.\nAccording to file size, file name could be :\n");
            for( NxPartition part : partInfoArr)
            {
                if(part.size == input->size) {
                    message.append("- ");
                    message.append(part.name);
                    message.append("\n");
                }
            }
        }
		if(input->isSplitted && input->raw_size == input->size)
			message.append("\nThe application was unable to locate backup GPT in splitted dump");
		else if(input->isSplitted)
			message.append(QString("\nSplitted dump total size (%1) doesn't match size deduced from primary GPT (%2)").arg(GetReadableSize(input->size).c_str(), GetReadableSize(input->raw_size).c_str()));

		QMessageBox::critical(nullptr,"Error",message);
		return;
	}

    // Save as menu
    ui->menuFile->actions().at(3)->setEnabled(true);

    // Decrypt & save as menu
    if(input->isEncrypted && bKeyset && !input->bad_crypto)
        ui->menuFile->actions().at(4)->setEnabled(true);

    // Encrypt & save as menu
    if(!input->isEncrypted && bKeyset) {
        if(input->type == RAWNAND || input->type == RAWMMC || input->type == BOOT0 || input->type == BOOT1 || (strlen(input->partitionName) > 0 &&
            (strcmp(input->partitionName, "PRODINFO") == 0 || strcmp(input->partitionName, "PRODINFOF") == 0 ||
             strcmp(input->partitionName, "SAFE") == 0 || strcmp(input->partitionName, "SYSTEM") == 0 ||
             strcmp(input->partitionName, "USER") == 0)))

            ui->menuFile->actions().at(5)->setEnabled(true);
    }
    // Restore from file
    if((input->type == RAWNAND || input->type == RAWMMC) && !input->isSplitted)
        ui->menuFile->actions().at(6)->setEnabled(true);

    // Properties menu
    ui->menuFile->actions().at(8)->setEnabled(true);

    // Incognito menu
    if(input->type == RAWNAND || input->type == RAWMMC || (NULL != input->partitionName && strcmp(input->partitionName, "PRODINFO") == 0))
    {
        ui->menuTools->actions().at(1)->setEnabled(true);
    }

    // List partitions for RAWNAND & RAWMMC
    if((input->type == RAWNAND || input->type == RAWMMC) && nullptr != input->firstPartion)
	{

        int i = 0;
		GptPartition *cur = input->firstPartion;
		while (nullptr != cur)
		{

            ui->partition_table->insertRow(ui->partition_table->rowCount());

            ui->partition_table->setItem(ui->partition_table->rowCount()-1, 0, new QTableWidgetItem(QString(cur->name)));
			u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;
			QString qSize = QString::number(size);
            ui->partition_table->setItem(ui->partition_table->rowCount()-1, 1, new QTableWidgetItem(GetReadableSize(size).c_str()));

            ui->partition_table->setItem(ui->partition_table->rowCount()-1, 2, new QTableWidgetItem(cur->isEncrypted ? "Yes" : "No"));

			cur = cur->next;
		}
		ui->partition_table->setStatusTip(tr("Right-click on partition to dump/restore to/from file."));
	}

    if(input->type == BOOT0 || input->type == BOOT1 || input->type == PARTITION)
	{
		ui->partition_table->setRowCount(1);
		if(input->type == PARTITION) {
            //wstring ws(input->pathLPWSTR);
            //std::string basename = base_name(string(ws.begin(), ws.end()));
            //ui->partition_table->setItem(0, 0, new QTableWidgetItem(basename.c_str()));
            ui->partition_table->setItem(0, 0, new QTableWidgetItem(input->partitionName));
		} else {
			char name[128];
			if(input->type == BOOT0)
				sprintf(name, "BOOT0 (autoRCM : %s)", input->autoRcm ? "on" : "off");
			else
				sprintf(name, "%s", input->GetNxStorageTypeAsString());
			ui->partition_table->setItem(0, 0, new QTableWidgetItem(name));
		}
		ui->partition_table->setItem(0, 1, new QTableWidgetItem(GetReadableSize(input->size).c_str()));
        ui->partition_table->setItem(0, 2, new QTableWidgetItem(input->isEncrypted ? "Yes" : "No"));
	}

    if(input->type == BOOT0 || input->type == RAWMMC)
    {
        ui->menuTools->actions().at(2)->setEnabled(true);
    }

    // Display storage information
    if(input->fw_detected)
        ui->fwversion_value->setText(QString(input->fw_version));
    else if(input->type == RAWNAND || input->type == RAWMMC ||
            (input->type == PARTITION && strcmp(input->partitionName, "SYSTEM") == 0))
    {
        if(input->isEncrypted && input->bad_crypto) {
            ui->fwversion_value->setText("BAD CRYPTO!");
            ui->fwversion_value->setStyleSheet("QLabel { color : red; }");
            ui->fwversion_value->setStatusTip("Error while decrypting content, wrong keys ? (CTRL+K to configure keyset)");
        }
        else {
            ui->fwversion_value->setText("KEYSET NEEDED!");
            ui->fwversion_value->setStatusTip("Unable to decrypt content (CTRL+K to configure keyset)");
        }
    }
    else
        ui->fwversion_value->setText("N/A");

    if (strlen(input->deviceId) > 0)
        ui->deviceid_value->setText(input->deviceId);
    else if(input->type == RAWNAND || input->type == RAWMMC || (input->type == PARTITION && strcmp(input->partitionName, "PRODINFO") == 0))
    {
        if(input->isEncrypted && input->bad_crypto) {
            ui->deviceid_value->setText("BAD CRYPTO!");
            ui->deviceid_value->setStyleSheet("QLabel { color : red; }");
            ui->deviceid_value->setStatusTip("Error while decrypting content, wrong keys ? (CTRL+K to configure keyset)");
        }
        else {
            ui->deviceid_value->setText("KEYSET NEEDED!");
            ui->deviceid_value->setStatusTip("Unable to decrypt content (CTRL+K to configure keyset)");
        }
    }
    else
        ui->deviceid_value->setText("N/A");
}


void MainWindow::on_partition_table_itemSelectionChanged()
{

	// Partition table context menu
	foreach (QAction *action, ui->partition_table->actions()) {
		ui->partition_table->removeAction(action);
	}

    if((input->type == RAWNAND || input->type == RAWMMC)&& nullptr != input->firstPartion)
	{
		ui->partition_table->setContextMenuPolicy(Qt::ActionsContextMenu);
		const QIcon dumpIcon = QIcon::fromTheme("document-open", QIcon(":/images/save.png"));
		QAction* dumpAction = new QAction(dumpIcon, "Dump to file...");
		dumpAction->setStatusTip(tr("Save as new file"));
		ui->partition_table->connect(dumpAction, SIGNAL(triggered()), this, SLOT(dumpPartition()));
		ui->partition_table->addAction(dumpAction);

        QList<QTableWidgetItem *> list = ui->partition_table->selectedItems();
        for(auto &item : list)
        {
            GptPartition *partition = input->GetPartitionByName(item->text().toUtf8().constData());
            if(NULL != partition && partition->isEncrypted && !partition->bad_crypto)
            {                
                const QIcon encIcon = QIcon::fromTheme("document-open", QIcon(":/images/decrypt.png"));
                QAction* dumpDecAction = new QAction(encIcon, "Decrypt && dump to file...");
                dumpDecAction->setStatusTip(tr("Save as new file"));
                if(!bKeyset)
                    dumpDecAction->setDisabled(true);
                ui->partition_table->connect(dumpDecAction, SIGNAL(triggered()), this, SLOT(dumpDecPartition()));
                ui->partition_table->addAction(dumpDecAction);
            }
            else if (NULL != partition && !partition->isEncrypted && (strcmp(partition->name, "PRODINFO") == 0 ||
                     strcmp(partition->name, "PRODINFOF") == 0 || strcmp(partition->name, "SAFE") == 0 ||
                     strcmp(partition->name, "SYSTEM") == 0 || strcmp(partition->name, "USER") == 0))
            {
                const QIcon decIcon = QIcon::fromTheme("document-open", QIcon(":/images/encrypt.png"));
                QAction* dumpEncAction = new QAction(decIcon, "Encrypt && dump to file...");
                dumpEncAction->setStatusTip(tr("Save as new file"));
                if(!bKeyset)
                    dumpEncAction->setDisabled(true);
                ui->partition_table->connect(dumpEncAction, SIGNAL(triggered()), this, SLOT(dumpEncPartition()));
                ui->partition_table->addAction(dumpEncAction);
            }
        }

		if(!input->isSplitted)
		{
            const QIcon restoreIcon = QIcon::fromTheme("document-open", QIcon(":/images/restore.png"));
			QAction* restoreAction = new QAction(restoreIcon, "Restore from file...");
			restoreAction->setStatusTip(tr("Open an existing file"));
			ui->partition_table->connect(restoreAction, SIGNAL(triggered()), this, SLOT(restorePartition()));
			ui->partition_table->addAction(restoreAction);
		}
	}
	else if(input->type == BOOT1 || input->type == PARTITION)
	{
		ui->partition_table->setContextMenuPolicy(Qt::NoContextMenu);
	}
	else if(input->type == BOOT0)
	{
		ui->partition_table->setContextMenuPolicy(Qt::ActionsContextMenu);
		QAction* action = new QAction(input->autoRcm ? "Disable autoRCM" : "Enable AutoRCM");
		action->setStatusTip(tr(input->autoRcm ? "Disable autoRCM" : "Enable AutoRCM"));
		ui->partition_table->connect(action, SIGNAL(triggered()), this, SLOT(toggleAutoRCM()));
		ui->partition_table->addAction(action);
	}

}

void MainWindow::driveSet(QString drive)
{    
	ui->progressBar->setFormat("Analysing input... please wait.");
	ui->progressBar->setValue(100);
	qApp->processEvents();

	// Open new thread to init storage (callback => inputSet(NxStorage))
	workThread = new Worker(this, drive);
	workThread->start();
}

void MainWindow::error(int err, QString label)
{
	if(err != ERR_WORK_RUNNING)
	{
        if(workInProgress) endWorkThread();
		ui->progressBar->setFormat("");
		ui->progressBar->setValue(0);
		if(label != nullptr)
		{
			QMessageBox::critical(nullptr,"Error", label);
			return;
		}
	}

	for (int i=0; i < (int)array_countof(ErrorLabelArr); i++)
	{
		if(ErrorLabelArr[i].error == err) {
			QMessageBox::critical(nullptr,"Error", QString(ErrorLabelArr[i].label));
			return;
		}
	}

	QMessageBox::critical(nullptr,"Error","Error " + QString::number(err));
}

void MainWindow::startWorkThread()
{
	startWork = std::chrono::system_clock::now();
	workInProgress = true;
	workThread->start();
	ui->progressBar->setFormat("Copying... (0%)");
	ui->progressBar->setValue(0);
	setProgressBarStyle();
	ui->remaining_time_label->setText("Remaining time : calculating");
	progressMD5 = false;

	ui->rawdump_button->setEnabled(false);
	ui->fullrestore_button->setEnabled(false);
	ui->stop_button->setEnabled(true);

	TaskBarProgress->setVisible(true);
	TaskBarProgress->setValue(0);
}

void MainWindow::endWorkThread()
{
	workInProgress = false;
	remainingTimeWork = std::chrono::system_clock::now();
	ui->remaining_time_label->setText("");
	if(nullptr != selected_io) delete(selected_io);

	initButtons();
	ui->stop_button->setEnabled(false);

	TaskBarProgress->setVisible(false);
	TaskBarProgress->setValue(0);
}

void MainWindow::updateProgress(int percent, u64 *bytesAmount)
{
	QString stepLabel("Copying...");
	if(progressMD5) stepLabel = QString("Verifying integrity...");
	ui->progressBar->setValue(percent);
	TaskBarProgress->setValue(percent);
	if(percent == 100)
	{
		if(progressMD5) ui->progressBar->setFormat("Done and verified ! ");
		else ui->progressBar->setFormat("Done. " + QString(GetReadableSize(*bytesAmount).c_str()) + " written");
	}
	else ui->progressBar->setFormat(stepLabel + " (" + QString::number(percent) + "%)");

	if(percent > 0)
	{
		auto time = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = time - (progressMD5 ? startWorkMD5 : startWork);
		std::chrono::duration<double> remaining_seconds = (elapsed_seconds / percent) * (100 - percent);
		remainingTimeWork = time + remaining_seconds;
	}

	if(percent == 100 && (progressMD5 || bypassMD5)) endWorkThread();
}

void MainWindow::MD5begin()
{
	progressMD5 = true;
	setProgressBarStyle("0FB3FF");
	ui->remaining_time_label->setText("Remaining time : calculating");
	startWorkMD5 = std::chrono::system_clock::now();
}

void MainWindow::setProgressBarStyle(QString color)
{
	if(nullptr == color) color = "06B025";
	QString st = QString (
				"QProgressBar::chunk {"
				"background-color: #" + color + ";"
												"}");
	st.append("QProgressBar {"
			  "border: 1px solid grey;"
			  "border-radius: 2px;"
			  "text-align: center;"
			  "background: #eeeeee;"
			  "}");
	ui->progressBar->setStyleSheet(st);
}

void MainWindow::createActions()
{   

    // Open file
    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    ui->menuFile->actions().at(0)->setIcon(openIcon);
    ui->menuFile->actions().at(0)->setShortcuts(QKeySequence::Open);
    ui->menuFile->actions().at(0)->setStatusTip(tr("Open an existing file"));
    connect(ui->menuFile->actions().at(0), &QAction::triggered, this, &MainWindow::open);

    // Open drive
    const QIcon openDIcon = QIcon::fromTheme("document-open", QIcon(":/images/drive.png"));
    ui->menuFile->actions().at(1)->setIcon(openDIcon);
    ui->menuFile->actions().at(1)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_D));
    ui->menuFile->actions().at(1)->setStatusTip(tr("Open a logical drive"));
    connect(ui->menuFile->actions().at(1), &QAction::triggered, this, &MainWindow::openDrive);

    // Save as
    const QIcon dumpIcon = QIcon::fromTheme("document-open", QIcon(":/images/save.png"));
    ui->menuFile->actions().at(3)->setIcon(dumpIcon);
    ui->menuFile->actions().at(3)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_S));
    ui->menuFile->actions().at(3)->setStatusTip(tr("Dump as file..."));
    connect(ui->menuFile->actions().at(3), &QAction::triggered, this, &MainWindow::on_rawdump_button_clicked);
    ui->menuFile->actions().at(3)->setDisabled(true);

    // Decrypt & Save as
    const QIcon decIcon = QIcon::fromTheme("document-open", QIcon(":/images/decrypt.png"));
    ui->menuFile->actions().at(4)->setIcon(decIcon);
    ui->menuFile->actions().at(4)->setShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_D));
    ui->menuFile->actions().at(4)->setStatusTip(tr("Decrypt & Dump as file..."));
    connect(ui->menuFile->actions().at(4), &QAction::triggered, this, &MainWindow::on_rawdumpDec_button_clicked);
    ui->menuFile->actions().at(4)->setDisabled(true);

    // Encrypt & Save as
    const QIcon encIcon = QIcon::fromTheme("document-open", QIcon(":/images/encrypt.png"));
    ui->menuFile->actions().at(5)->setIcon(encIcon);
    ui->menuFile->actions().at(5)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_E));
    ui->menuFile->actions().at(5)->setStatusTip(tr("Encrypt && Dump as file..."));
    connect(ui->menuFile->actions().at(5), &QAction::triggered, this, &MainWindow::on_rawdumpEnc_button_clicked);
    ui->menuFile->actions().at(5)->setDisabled(true);

    // Restore from file
    const QIcon resIcon = QIcon::fromTheme("document-open", QIcon(":/images/restore.png"));
    ui->menuFile->actions().at(6)->setIcon(resIcon);
    ui->menuFile->actions().at(6)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_R));
    ui->menuFile->actions().at(6)->setStatusTip(tr("Full restore from file..."));
    connect(ui->menuFile->actions().at(6), &QAction::triggered, this, &MainWindow::on_fullrestore_button_clicked);
    ui->menuFile->actions().at(6)->setDisabled(true);

    // Properties
    ui->menuFile->actions().at(8)->setDisabled(true);
    ui->menuFile->actions().at(8)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_I));
    ui->menuFile->actions().at(8)->setStatusTip(tr("Display useful information about current file/drive"));
    connect(ui->menuFile->actions().at(8), &QAction::triggered, this, &MainWindow::Properties);

    // Configure keyset
    const QIcon keyIcon = QIcon::fromTheme("document-open", QIcon(":/images/keyset.png"));
    ui->menuTools->actions().at(0)->setIcon(keyIcon);
    ui->menuTools->actions().at(0)->setShortcut(QKeySequence(Qt::CTRL +  Qt::Key_K));
    ui->menuTools->actions().at(0)->setStatusTip(tr("Configure keyset"));
    connect(ui->menuTools->actions().at(0), &QAction::triggered, this, &MainWindow::openKeySet);

    // Incognito
    const QIcon incoIcon = QIcon::fromTheme("document-open", QIcon(":/images/incognito.png"));
    ui->menuTools->actions().at(1)->setIcon(incoIcon);
    ui->menuTools->actions().at(1)->setShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_I));
    ui->menuTools->actions().at(1)->setStatusTip(tr("Wipe all console unique id's from CAL0"));
    ui->menuTools->actions().at(1)->setDisabled(true);
    connect(ui->menuTools->actions().at(1), &QAction::triggered, this, &MainWindow::incognito);

    // Toggle autoRCM
    ui->menuTools->actions().at(2)->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_A));
    ui->menuTools->actions().at(2)->setStatusTip(tr("Enable/Disable autoRCM (BOOT0 only)"));
    ui->menuTools->actions().at(2)->setDisabled(true);
    connect(ui->menuTools->actions().at(2), &QAction::triggered, this, &MainWindow::toggleAutoRCM);
}

void MainWindow::timer1000()
{
	if(workInProgress)
	{
		//elapsed time
		auto time = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = time - startWork;
		ui->elapsed_time_label->setText("Elapsed time : " + QString(GetReadableElapsedTime(elapsed_seconds).c_str()));

		//Remaining time
		if(remainingTimeWork >= time)
		{
			std::chrono::duration<double> remaining_seconds = remainingTimeWork - time;
			ui->remaining_time_label->setText("Remaining time : " + QString(GetReadableElapsedTime(remaining_seconds).c_str()));
		}
	}
}

void MainWindow::on_stop_button_clicked()
{
	if(!workInProgress) return;

	if(QMessageBox::question(this, "Warning", "Copy in progress. Are you sure you want to cancel ?", QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
	{
		return;
	}

	workThread->terminate();
	workThread->wait();
	endWorkThread();
	ui->progressBar->setFormat("");
	ui->progressBar->setValue(0);
}

void MainWindow::on_fullrestore_button_clicked()
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

	bypassMD5 = TRUE;

	// Create new file dialog
	QString fileName = QFileDialog::getOpenFileName(this);
	if (!fileName.isEmpty())
	{
		QString message;
		message.append("You are about to restore an existing " + QString(input->isDrive ? "drive" : "file") + "\nAre you sure you want to continue ?");
		if(QMessageBox::question(this, "Warning", message, QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
		{
			return;
		}

		//New output storage
		selected_io = new NxStorage(fileName.toUtf8().constData());

        if(!selected_io->isEncrypted && input->isEncrypted && bKeyset && parseKeySetFile("keys.dat", &biskeys))
        {
            selected_io->InitKeySet(&biskeys);
            input->InitKeySet(&biskeys);
        }
		// Open new thread to copy data
		workThread = new Worker(this, selected_io, input , RESTORE, bypassMD5);
		startWorkThread();
	}
}

void MainWindow::toggleAutoRCM()
{
	if(workInProgress)
	{
		error(ERR_WORK_RUNNING);
		return;
	}

	bool pre_autoRcm = input->autoRcm;

    if(input->type == RAWMMC && !pre_autoRcm && QMessageBox::question(this, "Warning", "Be aware that activating autoRCM on emuNAND will be inoperant since it only works on sysNAND.\nAre you sure you want to continue ?", QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
    {
        QMessageBox::information(this, "Information", "Operation canceled");
        return;
    }

	if(!input->setAutoRCM(input->autoRcm ? false : true))
		QMessageBox::critical(nullptr,"Error", "Error while toggling autoRCM");
	else {
		input->InitStorage();
		QMessageBox::information(this, "Success", "AutoRCM is "  + QString(input->autoRcm ? "enabled" : "disabled"));
		inputSet(input);
	}

}

void MainWindow::keySetSet()
{
    bKeyset = false;
    QFile file("keys.dat");
    if (file.exists() && parseKeySetFile("keys.dat", &biskeys) >= 2)
        bKeyset = true;

    if(nullptr != input && input->type != UNKNOWN && input->type != INVALID)
    {
        if(bKeyset)
        {
            input->InitKeySet(&biskeys);
            input->InitStorage();
        }
        inputSet(input);
    }
}

void MainWindow::on_moreinfo_button_clicked()
{
    if(nullptr != input && input->type != INVALID && input->type != UNKNOWN)
        Properties();
}
