#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtWidgets>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{    
    ui->setupUi(this);
    createActions();


    // Init partition table
    QTableWidget *partitionTable = ui->partition_table;
    partitionTable->resize(290, partitionTable->height());
    partitionTable->setRowCount(0);
    partitionTable->setColumnCount(2);
    partitionTable->setColumnWidth(0, 160);
    partitionTable->setColumnWidth(1, 80);
    QStringList header;
    header<<"Name"<<"Size";
    partitionTable->setHorizontalHeaderLabels(header);
    QFont font("Calibri", 10, QFont::Bold);
    partitionTable->horizontalHeader()->setFont(font);
    partitionTable->setSelectionBehavior(QAbstractItemView::SelectRows);


    // Init progress bar
    ui->progressBar->resize(265, ui->progressBar->height());
    ui->progressBar->setValue(0);
    ui->progressBar->setTextVisible(true);
    ui->progressBar->setFormat("");
    ui->progressBar->setAlignment(Qt::AlignCenter);
    setProgressBarStyle();


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
}

MainWindow::~MainWindow()
{
    delete ui;
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

         //std::string Sbasename = base_name(std::string(fileName.toUtf8().constData()));
         //ui->inputLabel->setText(QString(Sbasename.c_str()));
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
    //openDriveDialog->resize(320, 240);
    openDriveDialog->setWindowTitle("Logical drives");
    openDriveDialog->show();
    openDriveDialog->exec();
}

void MainWindow::on_rawdump_button_clicked()
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
    QString fileName = fd.getSaveFileName(this, "Save as", "rawnand.bin");
    if (!fileName.isEmpty())
    {
        //New output storage
        selected_io = new NxStorage(fileName.toUtf8().constData());

        // Open new thread to copy data
        workThread = new Worker(this, input, selected_io, DUMP, bypassMD5);
        startWorkThread();
    }
}

void MainWindow::dumpPartition()
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

        // Create new file dialog
        QFileDialog fd(this);
        fd.setAcceptMode(QFileDialog::AcceptSave); // Ask overwrite
        QString fileName = fd.getSaveFileName(this, "Save as", cur_partition); // Default filename is partition name
        if (!fileName.isEmpty())
        {
            //New output storage
            selected_io = new NxStorage(fileName.toUtf8().constData());

            // Open new thread to copy data            
            workThread = new Worker(this, input, selected_io, DUMP, bypassMD5, cur_partition.toUtf8().constData());
            startWorkThread();
        }

    }
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
            message.append(QString("You are about to restore partition an existing rawnand %1\n").arg(input->isDrive ? "drive" : "file"));

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

            // Open new thread to restore data
            workThread = new Worker(this, selected_io, input, RESTORE, bypassMD5, cur_partition.toUtf8().constData());
            startWorkThread();

        }
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

    createActions();

    if(input->type == INVALID || input->type == UNKNOWN)
    {
        QMessageBox::critical(nullptr,"Error","Input file/drive is not a valid NX storage type");
        ui->rawdump_button->setEnabled(false);
        ui->fullrestore_button->setEnabled(false);
        return;
    }

    if(input->type == RAWNAND && nullptr != input->firstPartion)
    {
        // Partition table context menu
        foreach (QAction *action, ui->partition_table->actions()) {
            ui->partition_table->removeAction(action);
        }
        ui->partition_table->setContextMenuPolicy(Qt::ActionsContextMenu);
        const QIcon dumpIcon = QIcon::fromTheme("document-open", QIcon(":/images/save.png"));
        const QIcon restoreIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
        QAction* dumpAction = new QAction(dumpIcon, "Dump to file...");
        QAction* restoreAction = new QAction(restoreIcon, "Restore from file...");
        //dumpAction->setShortcuts(QKeySequence::Open);
        //restoreAction->setShortcuts(QKeySequence::SaveAs);
        dumpAction->setStatusTip(tr("Save as new file"));
        restoreAction->setStatusTip(tr("Open an existing file"));
        ui->partition_table->connect(dumpAction, SIGNAL(triggered()), this, SLOT(dumpPartition()));
        ui->partition_table->connect(restoreAction, SIGNAL(triggered()), this, SLOT(restorePartition()));
        ui->partition_table->addAction(dumpAction);
        ui->partition_table->addAction(restoreAction);

        int i = 0;
        GptPartition *cur = input->firstPartion;
        while (nullptr != cur)
        {
           ui->partition_table->setRowCount(i+1);
           ui->partition_table->setItem(i, 0, new QTableWidgetItem(cur->name));
           u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;
           QString qSize = QString::number(size);
           ui->partition_table->setItem(i, 1, new QTableWidgetItem(GetReadableSize(size).c_str()));
           cur = cur->next;
           i++;
        }

        ui->partition_table->setStatusTip(tr("Right-click on partition to dump/restore to/from file."));

        ui->rawdump_button->setEnabled(true);
        ui->fullrestore_button->setEnabled(true);
    }

    if(input->type == BOOT0 || input->type == BOOT1 || input->type == PARTITION)
    {
        ui->partition_table->setContextMenuPolicy(Qt::NoContextMenu);
        ui->partition_table->setRowCount(1);
        if(input->type == PARTITION) {
            wstring ws(input->pathLPWSTR);
            std::string basename = base_name(string(ws.begin(), ws.end()));
            ui->partition_table->setItem(0, 0, new QTableWidgetItem(basename.c_str()));
        } else {
            ui->partition_table->setItem(0, 0, new QTableWidgetItem(input->GetNxStorageTypeAsString()));
        }
        ui->partition_table->setItem(0, 1, new QTableWidgetItem(GetReadableSize(input->size).c_str()));

        if(input->type == BOOT0)
        {
            QMenu *fileMenu = menuBar()->addMenu(tr("&Tools"));
            QAction *autoRcmAction = new QAction(input->autoRcm ? tr("&Disable autoRCM") : tr("&Enable autoRCM"), this);
            autoRcmAction->setStatusTip(tr("Open an existing file"));
            connect(autoRcmAction, &QAction::triggered, this, &MainWindow::toggleAutoRCM);
            fileMenu->addAction(autoRcmAction);
        }
    }

    if(input->type == PARTITION) ui->fullrestore_button->setEnabled(false);
    else ui->fullrestore_button->setEnabled(true);

    QString path = QString::fromWCharArray(input->pathLPWSTR), input_label;
    QFileInfo fi(path);
    input_label.append(fi.fileName() + " (");
    if(input->isSplitted) input_label.append("splitted dump, ");
    input_label.append(QString(GetReadableSize(input->size).c_str()) + ")");
    ui->inputLabel->setText(input_label);

    ui->rawdump_button->setEnabled(true);
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
    endWorkThread();
    ui->progressBar->setFormat("");
    ui->progressBar->setValue(0);
    if(label != nullptr)
    {
        QMessageBox::critical(nullptr,"Error", label);
        return;
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
}

void MainWindow::endWorkThread()
{
    workInProgress = false;
    remainingTimeWork = std::chrono::system_clock::now();
    ui->remaining_time_label->setText("");
    if(nullptr != selected_io) delete(selected_io);

    if(input->type != INVALID || input->type != UNKNOWN)
    {
        ui->rawdump_button->setEnabled(true);
        ui->fullrestore_button->setEnabled(true);
    }
    ui->stop_button->setEnabled(false);
}

void MainWindow::updateProgress(int percent, u64 *bytesAmount)
{
    QString stepLabel("Copying...");
    if(progressMD5) stepLabel = QString("Verifying integrity...");
    ui->progressBar->setValue(percent);
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
    menuBar()->clear();
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    //QToolBar *fileToolBar = addToolBar(tr("File"));
    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    QAction *openAct = new QAction(openIcon, tr("&Open file..."), this);
    openAct->setShortcuts(QKeySequence::Open);
    openAct->setStatusTip(tr("Open an existing file"));
    connect(openAct, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(openAct);

    const QIcon openDIcon = QIcon::fromTheme("document-open", QIcon(":/images/drive.png"));
    QAction *openDAct = new QAction(openDIcon, tr("&Open drive..."), this);
    openDAct->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_D));
    openDAct->setStatusTip(tr("Open a logical drive"));
    connect(openDAct, &QAction::triggered, this, &MainWindow::openDrive);
    fileMenu->addAction(openDAct);
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

        // Open new thread to copy data
        workThread = new Worker(this, selected_io, input , RESTORE, bypassMD5);
        startWorkThread();
    }
}
void MainWindow::toggleAutoRCM()
{
    bool pre_autoRcm = input->autoRcm;
    if(!input->setAutoRCM(input->autoRcm ? false : true))
        QMessageBox::critical(nullptr,"Error", "Error while toggling autoRCM");
    else {
        input->InitStorage();
        QMessageBox::information(this, "Success", "AutoRCM is "  + QString(input->autoRcm ? "enabled" : "disabled"));
        inputSet(input);
    }

}
