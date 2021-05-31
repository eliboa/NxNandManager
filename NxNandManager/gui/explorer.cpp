#include "explorer.h"
#include "ui_explorer.h"
#include <QFile>
#include <QtConcurrent/QtConcurrent>
#include "qutils.h"
#include "progress.h"
#include "mainwindow.h"

void clearFiles(QList<NxFile*> files) {
    for (auto f : files)
        delete f;
}

Explorer::Explorer(QWidget *parent, NxPartition *partition) :
    QDialog(parent),
    ui(new Ui::Explorer), m_model(this)
{
    ui->setupUi(this);
    m_partition = partition;
    m_parent = parent;
    auto main_win =  reinterpret_cast<MainWindow*>(parent);
    titleDB = main_win->m_titleDB;
    ncaDB = main_win->m_ncaDB;
    userDB = new NxUserDB(m_partition->nxStorage());
    keyset = main_win->biskeys;
    m_model.setUserDB(userDB);

    // Connect model to view
    ui->tableView->setModel(&m_model);
    connect(&m_model, &ExplorerModel::resizeRowToContents, ui->tableView, &QTableView::resizeRowToContents);
    // Selection model
    connect(ui->tableView->selectionModel(), &QItemSelectionModel::selectionChanged, [&](const QItemSelection &selected, const QItemSelection &deselected) {
        on_selection_changed();
    });

    // Signal connections
    qRegisterMetaType<QQueue<CpyElement>>("QQueue<CpyElement>");
    qRegisterMetaType<ProgressInfo>("ProgressInfo");
    qRegisterMetaType<Qt::Orientation>("Qt::Orientation");
    qRegisterMetaType<QVector<int>>("QVector<int>");
    qRegisterMetaType<QQueue<NxFile*>>("QQueue<NxFile*>");
    qRegisterMetaType<QList<NxFile*>>("QList<NxFile*>");
    qRegisterMetaType<QList<QPersistentModelIndex>>("QList<QPersistentModelIndex>");
    connect(this, SIGNAL(updateViewSignal()), this, SLOT(updateView()));
    setWindowFlags(Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);

    // Create status bar
    m_statusBar = new QStatusBar(this);
    ui->footerLayout->addWidget(m_statusBar);

    // Ensure filesystem is mounted
    if (partition->mount_fs())
        return;

    ui->currentDir_combo->addItem("/save (Saves)", "/save");
    ui->currentDir_combo->addItem("/Contents/registered (Installed titles)", "/Contents/registered");
    ui->currentDir_combo->addItem("/Contents/placehld (Downloaded titles)", "/Contents/placehld");
}

Explorer::~Explorer()
{
    cache_entries.clear();
    delete ui;
}

void Explorer::error(int err, QString label)
{
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

/*
 * Scan all files inside a directory (default mode is recursive)
 */
void Explorer::readDir(bool isRecursive)
{
    auto root_qstr = m_current_dir;
    current_entries.clear();

    // Read from cache
    auto cache = cache_entries.at(root_qstr);
    if (cache) {
        current_entries = *cache;
        return;
    }

    auto root = root_qstr.toStdWString();
    QQueue<wstring> queue;
    NxTitle *title = nullptr, *previous_title = nullptr;

    queue.enqueue(root.c_str());
    while (!queue.empty())
    {
        DIR dp;
        FILINFO fno;
        auto cur_dir = queue.dequeue();

        // Open directory
        auto open = m_partition->f_opendir(&dp, cur_dir.c_str()) == FR_OK;
        // Iterate entries
        while (open && !f_readdir(&dp, &fno) && fno.fname[0])
        {
            auto cur_path = wstring(cur_dir).append(L"/").append(fno.fname);
            if (fno.fattrib == FILE_ATTRIBUTE_DIRECTORY)
            {
                if (isRecursive) queue.enqueue(cur_path);
                continue;
            }
            auto file = new NxFile(m_partition, cur_path);
            if (!file->exists()) {
                delete file;
                continue;
            }

            // Get title name from title database (or from previous entry)
            if (file->titleID())
            {
                bool fromPrevious = previous_title && previous_title->u64_id == file->titleID();
                title = fromPrevious ? previous_title : titleDB->findTitleByID(file->titleID());
                if (title)
                {
                    file->setAdditionalString("title_name", title->name.toStdString());
                    if (!title->icon_url.isEmpty())
                        file->setAdditionalString("icon_url", title->icon_url.toStdString());
                    if (!fromPrevious) previous_title = title; // Save title
                }
            }
            current_entries << file;
        }
        f_closedir(&dp);
    }

    // Cache entries
    if (current_entries.count())
        cache_entries.add({root_qstr, current_entries});
}

void Explorer::updateView()
{
    setWindowTitle(" Explorer (" + QString::fromStdString(m_partition->partitionName()) + ":" + m_current_dir + ")");
    m_model.setModel(m_viewtype, current_entries);
    auto title_ix = m_model.getColumnIx(TitleColumn);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    if (title_ix >= 0)
        ui->tableView->horizontalHeader()->setSectionResizeMode(title_ix, QHeaderView::Stretch);
    ui->tableView->resizeColumnsToContents();
    ui->tableView->resizeRowsToContents();
    emit closeLoadingWdgt();
}

QList<NxFile*> Explorer::selectedFiles()
{
    QList<NxFile*> files;
    for (auto entry : ui->tableView->selectionModel()->selectedRows())
        files << m_model.entryAt(entry.row());

    return files;
}

QQueue<CpyElement> Explorer::getCopyQueue(QList<NxFile*> selectedFiles, bool force_dirOutput)
{
    QQueue<CpyElement> queue;
    if (!selectedFiles.count())
        return queue;

    bool isDirOutput = selectedFiles.count()>1 || force_dirOutput;
    QList<int> row_ixs;

    // File dialog
    QString caption = QString("Save to ").append(isDirOutput ? "directoy" : "file");
    QString target = "default_dir\\";

    if (!isDirOutput)        
        target.append(QString::fromStdWString(selectedFiles.at(0)->filename()));

    QFileDialog fd(this, caption, target);
    fd.setFileMode(isDirOutput ? QFileDialog::DirectoryOnly : QFileDialog::AnyFile);
    if (!isDirOutput)
        fd.setAcceptMode(QFileDialog::AcceptSave);
    if (!fd.exec())
        return queue;
    QString path = fd.selectedFiles().at(0);
    if (path.isEmpty())
        return queue;

    // Enqueue files to copy
    for (auto file : selectedFiles)
    {
        CpyElement el;
        el.nxFile = file;
        el.source = QString::fromStdWString(file->completePath());
        el.destination = path;
        if (isDirOutput)
            el.destination.append("\\" +  QString::fromStdWString(file->filename()));
        queue.enqueue(el);
    }
}

void Explorer::save(QList<NxFile*> selectedFiles)
{
    auto queue = getCopyQueue(selectedFiles);
    if (queue.isEmpty())
        return;

    // Init/open progress dialog & start work in a new thread
    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), &progressDialog, SLOT(updateProgress(const ProgressInfo)));
    connect(this, SIGNAL(consoleWrite(const QString)), &progressDialog, SLOT(consoleWrite(const QString)));
    progressDialog.show();

    QFutureWatcher<void> watcher;
    connect(&watcher, &QFutureWatcher<void>::finished, &progressDialog, &Progress::on_WorkFinished);
    QFuture<void> future = QtConcurrent::run(this, &Explorer::do_copy, queue);
    watcher.setFuture(future);

    progressDialog.exec();
}

void Explorer::do_copy(QQueue<CpyElement> queue)
{
    if (queue.isEmpty())
        return;

    bool isMultipleSelection = queue.count()>1;
    u32 buff_size = 0x400000; // 4 MB
    u8* buffer = (u8*)malloc(buff_size); // Allocate buffer

    ProgressInfo pi;
    pi.mode = COPY;
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesCount = 0;
    pi.bytesTotal  = 0;
    for (auto it : queue)
        pi.bytesTotal += it.nxFile->size();
    strcpy_s(pi.storage_name, isMultipleSelection ? "files" : QFileInfo(queue.at(0).destination).fileName().toStdString().c_str());
    emit sendProgress(pi);

    while (!queue.isEmpty())
    {
        auto item = queue.dequeue();
        auto source = item.source.toStdWString();

        QFile out_file(item.destination);
        auto error = [&](int err) {
            out_file.close();
            item.nxFile->close();
            free(buffer);
            emit Explorer::error(err);
        };

        if (!item.nxFile->open())
            return error(ERR_INPUT_HANDLE);

        if (!out_file.open(QIODevice::WriteOnly))
            return error(ERR_OUTPUT_HANDLE);

        ProgressInfo spi;
        if (isMultipleSelection)
        {
            spi.isSubProgressInfo = true;
            spi.mode = COPY;
            strcpy_s(spi.storage_name, QFileInfo(out_file).fileName().toStdString().c_str());
            spi.begin_time = std::chrono::system_clock::now();
            spi.bytesCount = 0;
            spi.bytesTotal = item.nxFile->size();
            emit sendProgress(spi);
        }

        UINT br;
        while (!item.nxFile->read((void*)buffer, buff_size, &br) && br)
        {
            auto bw = out_file.write((const char*)buffer, (qint64)br);
            if (bw < 0)
                return error(ERR_WHILE_WRITE);

            pi.bytesCount += (u64)bw;
            emit sendProgress(pi);
            if (isMultipleSelection) {
                spi.bytesCount += (u64)bw;
                emit sendProgress(spi);
            }
        }
        out_file.close();
        item.nxFile->close();
    }

    free(buffer);
    emit workFinished();
}

void Explorer::do_extractFS(QQueue<CpyElement> queue)
{
    if (queue.isEmpty())
        return;

    // Extract FS => Destination is a directory, the same for each file
    auto destination = QFileInfo(queue.at(0).destination).path();

    ProgressInfo pi;
    pi.mode = COPY;
    pi.bytesCount = 0;
    pi.bytesTotal  = 0;
    for (auto entry : queue) {
        NxSave save(entry.nxFile);
        for (auto file : save.listFiles())
            pi.bytesTotal += file.size;
    }
    pi.begin_time = std::chrono::system_clock::now();
    strcpy_s(pi.storage_name, "files");
    emit sendProgress(pi);

    u32 buff_size = 0x400000; // 4 MB
    u8* buffer = (u8*)malloc(buff_size); // Allocate buffer

    while (!queue.isEmpty())
    {
        auto item = queue.dequeue();
        NxSave save(item.nxFile);

        for (auto file : save.listFiles())
        {
            // Set destination path (destination/titleID or titleName/saveFS path)
            QString cur_des = destination;
            QString dir_name = "";
            if (item.nxFile->hasAdditionalString("title_name"))
            {
                dir_name = QString::fromStdString(item.nxFile->getAdditionalString("title_name"));
                // Normalize title name
                auto it = std::remove_if(dir_name.begin(), dir_name.end(), [](const QChar& c){return !c.isLetterOrNumber() && c != " ";});
                dir_name.chop(std::distance(it, dir_name.end()));
            }
            if (dir_name.isEmpty())
                dir_name = item.nxFile->titleIDString().length() ? QString::fromStdString(item.nxFile->titleIDString()) : QString::fromStdWString(item.nxFile->filename());
            cur_des.append("/" + dir_name + "/" + QString::fromStdString(file.completePath()));

            auto dest_info = QFileInfo(cur_des.toLocal8Bit());
            // Make destination path
            if (!QDir(dest_info.path()).exists() && !QDir().mkpath(dest_info.path())) {
                free(buffer);
                emit Explorer::error(ERR_CREATE_DIR_FAILED);
                emit workFinished();
                return;
            }

            // Open output file
            QString cur_file_path = QDir(cur_des).path() + "\\" + QString::fromStdString(file.filename);
            QFile out_file(dest_info.filePath());

            auto error = [&](int err) {
                out_file.close();
                free(buffer);
                emit Explorer::error(err);
            };

            if (!out_file.open(QIODevice::WriteOnly))
                return error(ERR_OUTPUT_HANDLE);

            ProgressInfo spi;
            spi.isSubProgressInfo = true;
            spi.mode = COPY;
            strcpy_s(spi.storage_name, QFileInfo(out_file).fileName().toStdString().c_str());
            spi.begin_time = std::chrono::system_clock::now();
            spi.bytesCount = 0;
            spi.bytesTotal = file.size;
            emit sendProgress(spi);

            u64 br;
            while (spi.bytesCount < spi.bytesTotal && (br = save.readSaveFile(file, buffer, 0, buff_size)) > 0)
            {
                auto bw = out_file.write((const char*)buffer, (qint64)br);
                if (bw < 0)
                    return error(ERR_WHILE_WRITE);

                pi.bytesCount += (u64)bw;
                emit sendProgress(pi);
                spi.bytesCount += (u64)bw;
                emit sendProgress(spi);
            }
            if (spi.bytesCount != spi.bytesTotal)
                return error(ERR_WHILE_WRITE);

            out_file.close();
        }
    }
    if (pi.bytesCount != pi.bytesTotal)
        emit Explorer::error(ERR_WHILE_WRITE);

    free(buffer);
    emit workFinished();
}

void Explorer::hactool_process(QQueue<QStringList> cmds)
{
    QString hactool = "res/hactool.exe";
    if (!QFile(hactool).exists())
        return error(0, "hactool.exe not found!");

    for (auto args : cmds)
    {   
        args << "-k" << "keys.dat" << "--disablekeywarns";

        QString cmd;
        for (auto a : args) cmd.append(a + " ");
        QProcess* process = new QProcess(this);
        connect(process, &QProcess::readyReadStandardOutput, [&](){ consoleWrite(process->readAllStandardOutput());});
        process->start(hactool, args);
        process->waitForFinished(-1);
    }
}

QStringList Explorer::hactool_fs_list(NxFile *nxFile)
{

    QStringList files, args;
    QString hactool = "res/hactool.exe";
    if (!QFile(hactool).exists())
        return files;
    if (!m_partition->is_vfs_mounted())
        return files;

    auto path = QString::fromStdWString(m_partition->getVolumeMountPoint()
            + nxFile->completePath().substr(1, nxFile->completePath().length() -1));

    if (nxFile->isNXA())
        path.append("/00");

    QFileInfo file(path);
    if (!file.exists())
        return files;

    args << file.absolutePath() + "/" + file.fileName();

    if (nxFile->isNCA())
        args << "--listromfs" << "-t" << "nca";
    else if (nxFile->isSAVE())
        args << "--listfiles" << "-t" << "save";
    else
        return files;

    args << "-k" << "keys.dat" << "--disablekeywarns";

    QProcess* process = new QProcess(this);
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [&](int exitCode, QProcess::ExitStatus exitStatus){
        if (exitStatus == QProcess::NormalExit)
        {
            QTextStream stream(process->readAllStandardOutput());
            QString line;
            while (stream.readLineInto(&line))
                if (line.startsWith("rom:") || line.startsWith("save:"))
                    files << line;
        }
    });
    process->start(hactool, args);
    process->waitForFinished(-1);
    return files;
}

void Explorer::on_selection_changed()
{
    auto selection = ui->tableView->selectionModel()->selectedRows();
    bool isMultipleSelection = selection.count()>1;
    auto setAllToolTip = [&](QWidget *it, QString s) { it->setStatusTip(s); it->setToolTip(s); };

    // Enable/disable buttons
    auto obj_disable = [](QList<QWidget*> o) {for (auto i : o) i->setDisabled(true); };
    obj_disable(QList<QWidget*>() << ui->saveButton << ui->decrypt_button << ui->listFs_button << ui->extractFs_button);
    if (!selection.count())
        return;

    auto view = ui->tableView;
    foreach (QAction *action, view->actions()) {
        view->removeAction(action);
        delete action;
    }
    auto enable_action = [&](QPushButton *obj, QString lbl, const char *slot) {
        QAction* action = new QAction(obj->icon(), lbl);
        action->setStatusTip(lbl);
        connect(action, &QAction::triggered, [=]() {
            QMetaObject::invokeMethod(this, slot, Q_ARG(QList<NxFile*>, selectedFiles()));
        });
        obj->disconnect();
        connect(obj, &QPushButton::clicked, [=](bool state) {
            QMetaObject::invokeMethod(this, slot, Q_ARG(QList<NxFile*>, selectedFiles()));
        });
        view->addAction(action);
        obj->setEnabled(true);
        setAllToolTip(obj, lbl);
    };

    QString selection_label = isMultipleSelection ? (QString("%1").arg(selection.count()) + " ") : "";
    if (selection.count())
        selection_label.append(isMultipleSelection ? "files " : "selected file ");

    enable_action(ui->saveButton, "Extract " + selection_label, "save");

    if (m_model.viewType() == Generic)
        return;
    if (m_model.viewType() == Nca)
        enable_action(ui->decrypt_button, "Extract & decrypt " + selection_label + "(hactool)", "decrypt");
    if (selection.count() == 1)
        enable_action(ui->listFs_button, "List files in " + QString(m_model.viewType() == UserSave ? "Save" : "RomFS"), "listFS");
    enable_action(ui->extractFs_button, "Extract files in " + QString(m_model.viewType() == UserSave ? "Save" : "RomFS"), "extractFS");

    /*
    QString status_tip;

    if(selection.count())
        status_tip = QString("%1 file%2 selected (total: %3)").arg(selection.count()).arg(selection.count()>1?"s":"").arg(table->rowCount());
    else
        status_tip = QString("%1 file%2 found (%3)").arg(table->rowCount()).arg(ui->tableView->rowCount()>1 ? "s" : "")
                                                    .arg(QString::fromStdString(GetReadableSize(m_view.total_filesize)));

    ui->tableView->setStatusTip(status_tip);
    m_statusBar->showMessage(status_tip);
    */
}

void Explorer::on_currentDir_combo_currentIndexChanged(int index)
{
    m_viewtype = Generic;
    m_current_dir = ui->currentDir_combo->itemData(index).toString();
    if (m_current_dir.contains("/save"))
        m_viewtype = m_partition->type() == USER ? UserSave : SystemSave;
    else if (m_current_dir.contains("/Contents"))
        m_viewtype = Nca;

    // Display loading widget
    if (m_loadingWdgt)
        delete m_loadingWdgt;
    m_loadingWdgt = new loadingWidget("Loading", this);
    connect(this, SIGNAL(closeLoadingWdgt()), m_loadingWdgt, SLOT(close()));

    auto watcher = new QFutureWatcher<void>();
    connect(watcher, &QFutureWatcher<void>::finished, [=](){
        emit updateViewSignal();
        delete watcher;
    });
    QFuture<void> future = QtConcurrent::run(this, &Explorer::readDir, true);
    watcher->setFuture(future);

    //    QList<NxFile*> files = readDir();
    //QtConcurrent::run(this, &Explorer::setView);
}

void Explorer::decrypt(QList<NxFile*> selectedFiles)
{
    if (!QFile("res/hactool.exe").exists())
        return error(0, "hactool.exe not found!");

    auto cpy_queue = getCopyQueue(selectedFiles);
    if (cpy_queue.isEmpty())
        return;

    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), &progressDialog, SLOT(updateProgress(const ProgressInfo)));    
    connect(this, SIGNAL(workFinished()), &progressDialog, SLOT(on_WorkFinished()));
    connect(this, SIGNAL(consoleWrite(const QString)), &progressDialog, SLOT(consoleWrite(const QString)));
    progressDialog.show();

    QFutureWatcher<void> watcher;
    // After copy lambda
    connect(&watcher, &QFutureWatcher<void>::finished, [&](){
        QQueue<QStringList> cmd_queue;
        for (auto el : cpy_queue)
        {
            QFileInfo dinfo(el.destination);
            if (!dinfo.exists())
                continue;

            auto new_dir_path = dinfo.dir().absolutePath();
            QStringList args;
            if (el.nxFile->isSAVE())
            {
                QString dir_name = "";
                if (el.nxFile->hasAdditionalString("title_name"))
                {
                    dir_name = QString::fromStdString(el.nxFile->getAdditionalString("title_name"));
                    auto it = std::remove_if(dir_name.begin(), dir_name.end(), [](const QChar& c){
                        return !c.isLetterOrNumber() && c != " ";
                    });
                    dir_name.chop(std::distance(it, dir_name.end()));
                }
                if (dir_name.isEmpty())
                    dir_name = el.nxFile->titleIDString().length() ? QString::fromStdString(el.nxFile->titleIDString()) : QString::fromStdWString(el.nxFile->filename());

                new_dir_path.append("/" + dir_name);

                int i(0);
                while(QFileInfo(new_dir_path).exists() && i < 100)
                {
                    if (!i) new_dir_path.append("_");
                    else new_dir_path.chop(1);
                    new_dir_path.append(QString::number(i++));
                }
                args << "-t" << "save" << "--outdir=" + new_dir_path << el.destination;
            }
            else if (el.nxFile->isNCA())
                args << "-t" << "nca" << "--plaintext=" + el.destination + ".decrypted" << el.destination;
            else
                continue;
            cmd_queue.enqueue(args);
        }

        QFutureWatcher<void> f_watcher;
        connect(&f_watcher, &QFutureWatcher<void>::finished, &progressDialog, &Progress::on_WorkFinished);
        QFuture<void> f = QtConcurrent::run(this, &Explorer::hactool_process, cmd_queue);
        f_watcher.setFuture(f);
    });
    QFuture<void> future = QtConcurrent::run(this, &Explorer::do_copy, cpy_queue);
    watcher.setFuture(future);

    progressDialog.exec();
}

void Explorer::listFS(QList<NxFile*> selectedFiles)
{
    if (!selectedFiles.count())
        return;

    auto entry = selectedFiles.at(0);
    if (entry->isSAVE())
    {
        NxSave save(entry);
        if (!save.exists() || !save.isSAVE()) {
            QMessageBox::critical(this, "Error", "Failed to open file");
            return;
        }
        auto files = save.listFiles();
        if (!files.size()) {
            QMessageBox::information(this, "Information", "No file found");
            return;
        }
        auto dialog = new QDialog(this, Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
        auto layout = new QVBoxLayout();
        dialog->setLayout(layout);
        auto listWdgt = new QTableWidget(dialog);
        layout->addWidget(listWdgt);
        listWdgt->setColumnCount(2);
        listWdgt->setEditTriggers(QAbstractItemView::NoEditTriggers);
        listWdgt->setHorizontalHeaderLabels(QStringList() << "File" << "Size");
        u64 total_size = 0;
        for (auto file : files) {
            auto ix = listWdgt->rowCount();
            listWdgt->insertRow(ix);
            listWdgt->setItem(ix, 0, new QTableWidgetItem(QString::fromStdString(file.path + "/" + file.filename)));
            listWdgt->setItem(ix, 1, new QTableWidgetItem(QString::fromStdString(GetReadableSize(file.size))));
            total_size += file.size;
        }
        listWdgt->resizeColumnsToContents();
        layout->addWidget(new QLabel(QString("%1 file%2 (%3)").arg(files.size()).arg(files.size()>1?"s":"")
                                     .arg(QString::fromStdString(GetReadableSize(total_size)))));
        auto size_hint = listWdgt->columnWidth(0) + listWdgt->columnWidth(1) + 80;
        dialog->resize(QSize(size_hint < this->width() ? size_hint : this->width(), files.size() > 5 ? 350 : 200));
        dialog->exec();
        delete dialog;
        return;
    }

    if (!QFile("res/hactool.exe").exists())
        return error(0, "hactool.exe not found!");

    QStringList files;
    if (!m_partition->is_vfs_mounted())
    {
        if(QMessageBox::question(nullptr, "Error", "Partition needs to be mounted as virtual disk.\n Click 'Yes' to mount partition.",
                 QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
        {
            connect(m_partition, &NxPartition::vfs_mounted_signal, [=]() { listFS(selectedFiles); });
            connect(m_partition, &NxPartition::vfs_callback, [&](long status){
                if (status == DOKAN_DRIVER_INSTALL_ERROR)
                    emit error(1, "Dokan driver not installed. Please mount from main window to install driver.");
                else if (status < -1000)
                    emit error((int)status);
                else if (status != DOKAN_SUCCESS)
                    emit error(1, QString::fromStdString(dokanNtStatusToStr(status)));
            });
            QtConcurrent::run(m_partition, &NxPartition::mount_vfs, true, '\0', nullptr);
            return;
        }
    }
    else files = hactool_fs_list(entry);
    if (files.isEmpty())
    {
        QMessageBox::information(this, "Information", "No file found");
        return;
    }
    auto dialog = new QDialog(this, Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
    auto layout = new QHBoxLayout();
    dialog->setLayout(layout);
    auto listWdgt = new QListWidget(dialog);
    layout->addWidget(listWdgt);

    for (auto file : files)
        listWdgt->insertItem(listWdgt->count(), new QListWidgetItem(file));

    dialog->exec();
}


void Explorer::extractFS(QList<NxFile*> selectedFiles)
{
    if (!selectedFiles.count())
        return;

    auto queue = getCopyQueue(selectedFiles, true);
    if (queue.isEmpty())
        return;

    // Init/open progress dialog & start work in a new thread
    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), &progressDialog, SLOT(updateProgress(const ProgressInfo)));
    progressDialog.show();

    QFutureWatcher<void> watcher;
    connect(&watcher, &QFutureWatcher<void>::finished, &progressDialog, &Progress::on_WorkFinished);
    QFuture<void> future = QtConcurrent::run(this, &Explorer::do_extractFS, queue);
    watcher.setFuture(future);

    progressDialog.exec();
}


ExplorerModel::ExplorerModel(QWidget* parent, viewTypeEnum viewType, QList<NxFile*> entries)
 : QAbstractTableModel(parent), m_parent(parent)
{
    setModel(viewType, entries);
}

void ExplorerModel::setModel(viewTypeEnum viewType, QList<NxFile*> entries)
{
    beginResetModel();
    for (auto entry : m_entries) {
        if (entry.user_icon)
            delete entry.user_icon;
        if (entry.title_icon)
            delete entry.title_icon;
    }
    m_entries.clear();

    m_view.type = viewType;
    bool has_title_icon = false;
    for (auto entry : entries) {
        explorerModelEntry modelEntry;
        modelEntry.file = entry;

        if (viewType == UserSave && m_userDB && entry->hasUserID()) {
            auto user = m_userDB->getUserByUserId(entry->userID());
            if (user.avatar_img)
                modelEntry.user_icon = new QIcon(QPixmap::fromImage(*user.avatar_img));
        }

        if (entry->hasAdditionalString("icon_url"))
            has_title_icon = true;

        m_entries << modelEntry;
    }

    if (has_title_icon)
        setTitleIconsFromUrl();

    endResetModel();
}

ExplorerModel::~ExplorerModel()  {
    //QAbstractTableModel::~QAbstractTableModel();
};


viewColumnType ExplorerModel::getColumnType(int column) const
{
    if (column == 0)
        return FileColumn;
    if (column == 1)
        return SizeColumn;
    if (column == 2)
        return m_view.type == Generic ? TypeColumn : TitleColumn;
    if (column == 3 && m_view.type != Generic)
        return TypeColumn;
    if (column == 4 && m_view.type != Generic)
        return UserColumn;

    return UnknownColumn;
}

int ExplorerModel::getColumnIx(viewColumnType viewType) const
{
    if (viewType == FileColumn)
        return 0;
    if (viewType == SizeColumn)
        return 1;
    if (viewType == TypeColumn)
        return  m_view.type == Generic ? 2 : 3;
    if (viewType == TitleColumn)
        return 2;
    if (viewType == UserColumn)
        return 4;
    return -1;
}

QVariant ExplorerModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (getColumnType(section))
        {
        case FileColumn:
            return QString("File");
        case SizeColumn:
            return QString("Size");
        case TitleColumn:
            return QString("Title");
        case TypeColumn:
            return QString("Type");
        case UserColumn:
            return QString("User");
        default:
            return QVariant();
        }
    }
    /*
    else if (role == Qt::SizeHintRole && orientation == Qt::Vertical) {
        auto entry = m_entries.at(section);
        if (entry.user_icon || entry.title_icon) {
            return QSize(50, 50);
        }
    }
    */
    return QVariant();

}

int ExplorerModel::columnCount(const QModelIndex &parent) const
{
    int count = 0;
    switch (m_view.type)
    {
    case UserSave:
        count = 5;
        break;
    case Nca:
        count = 4;
        break;
    default:
       count = 3;
    }
    return count;
}

QVariant ExplorerModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_entries.count() || index.row() < 0)
        return QVariant();

    auto entry = m_entries.at(index.row());
    auto file = entry.file;

    if (role == Qt::DisplayRole)
    {
        switch (getColumnType(index.column()))
        {
        case FileColumn:
            return QString::fromStdWString(file->filename());
        case SizeColumn:
            return QString::fromStdString(GetReadableSize(file->size()).c_str());
        case TitleColumn: {
            auto title_name = QString::fromStdString(file->getAdditionalString("title_name"));
            auto title_id = QString::fromStdString(file->titleIDString());
            return QString(!title_name.isEmpty() ? title_name + " (" + title_id + ")" : title_id);
        }
        case TypeColumn:
            return QString::fromStdString(file->contentTypeString());
        case UserColumn: {
            if(!file->hasUserID())
                return QVariant();
            auto user = m_userDB ? m_userDB->getUserByUserId(file->userID()) : NxUserIdEntry();
            return user.nickname.isEmpty() ? QString::fromStdString(file->userIDString()) : user.nickname;
        }
        default:
            return QVariant();
        }
    }
    else if (role == Qt::DecorationRole)
    {
        switch (getColumnType(index.column()))
        {
        case TitleColumn:
            return entry.title_icon ? entry.title_icon->pixmap(QSize(50, 50)) : QVariant();
        case UserColumn:
            return entry.user_icon ? entry.user_icon->pixmap(QSize(50, 50)) : QVariant();
        default:
            return QVariant();
        }
    }
    return QVariant();

}

void ExplorerModel::sort(int column, Qt::SortOrder order)
{
    auto col_type = getColumnType(column);
    if (col_type == UnknownColumn)
        return;
    emit layoutAboutToBeChanged();
    std::sort(m_entries.begin(), m_entries.end(), [=](const explorerModelEntry& a, const explorerModelEntry& b) {
        switch (col_type) {
        case FileColumn:
            return order == Qt::AscendingOrder ? a.file->completePath() < b.file->completePath() : a.file->completePath() > b.file->completePath();
        case SizeColumn:
            return order == Qt::AscendingOrder ? a.file->size() < b.file->size() : a.file->size() > b.file->size();
        case TitleColumn:
            return order == Qt::AscendingOrder ? a.file->titleID() < b.file->titleID() : a.file->titleID() > b.file->titleID();
        case TypeColumn:
            return order == Qt::AscendingOrder ? a.file->contentTypeString() < b.file->contentTypeString() : a.file->contentTypeString() > b.file->contentTypeString();
        case UserColumn:
            return order == Qt::AscendingOrder ? a.file->userIDString() < b.file->userIDString() : a.file->userIDString() > b.file->userIDString();
        default:
            ;// Do nothing
        }
        return false;
    });
    emit layoutChanged(QList<QPersistentModelIndex>(), QAbstractItemModel::VerticalSortHint);
}

void ExplorerModel::setTitleIconsFromUrl()
{
    typedef struct { u64 title_id; QString cache_file_path; QUrl icon_url; } iconQueue;
    QVector<iconQueue> icon_queue;
    for (int i(0); i < m_entries.count(); i++) if (m_entries.at(i).file->hasAdditionalString("icon_url")) {
        auto entry = m_entries[i];
        auto cache_file_path = "cache/" + QString::fromStdString(entry.file->titleIDString()) + ".jpg";
        QFile cache_file(cache_file_path);
        if (cache_file.exists()) {
            QImage img(cache_file_path, "JPG");
            if (!img.isNull()) {
                m_entries[i].title_icon = new QIcon(QPixmap::fromImage(img));
                auto m_idx = index(i, getColumnIx(TitleColumn));
                continue;
            }
            cache_file.remove();
        }
        for (auto queue : icon_queue) if (queue.title_id == entry.file->titleID())
            continue;
        icon_queue.append({entry.file->titleID(), cache_file_path, QUrl(QString::fromStdString(entry.file->getAdditionalString("icon_url"))) });
    }

    if (icon_queue.isEmpty())
        return;

    QDir cache_dir("cache");
    if (!cache_dir.exists() && !QDir().mkdir("cache"))
        return;

    for (auto entry : icon_queue) {
        QNetworkRequest request(entry.icon_url);
        auto reply = m_nm.get(request);
        if(reply->error())
            continue;

        connect(reply, &QNetworkReply::finished, [=]()
        {
            if (reply->error())
                return;

            auto data = reply->readAll();
            QFile file(entry.cache_file_path);
            if (file.open(QIODevice::WriteOnly)) {
                file.write(data);
                file.close();
            }

            for (int i(0); i < m_entries.count(); i++)
                if (!m_entries.at(i).title_icon && m_entries.at(i).file->titleID() == entry.title_id) {
                    auto entry = m_entries.at(i);
                    auto cache_file_path = "cache/" + QString::fromStdString(entry.file->titleIDString()) + ".jpg";
                    QFile cache_file(cache_file_path);
                    if (cache_file.exists()) {
                        QImage img(cache_file_path, "JPG");
                        if (!img.isNull()) {
                            m_entries[i].title_icon = new QIcon(QPixmap::fromImage(img));
                            auto m_idx = index(i, getColumnIx(TitleColumn));
                            emit dataChanged(m_idx, m_idx, {Qt::DecorationRole});
                            emit resizeRowToContents(i);
                            continue;
                        }
                        cache_file.remove();
                    }
                }
            reply->deleteLater();
        });

    }
}
void ExplorerModel::updateAll() {
    auto topLeft = index(0, 0, QModelIndex());
    auto bottomRight = index(rowCount()-1, columnCount()-1, QModelIndex());
    emit dataChanged(topLeft, bottomRight, {Qt::DisplayRole});
}
