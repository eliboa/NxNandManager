#include "explorer.h"
#include "ui_explorer.h"
#include <QFile>
#include <QtConcurrent/QtConcurrent>
#include "qutils.h"
#include "progress.h"
#include "mainwindow.h"

void clearFiles(NxFileList files) {
    for (auto f : files)
        delete f;
}

ExplorerModel::ExplorerModel(Explorer* parent, viewTypeEnum viewType, NxFileList entries)
 : QAbstractTableModel(parent), m_parent(parent)
{
    setModel(viewType, entries);
}

void ExplorerModel::setModel(viewTypeEnum viewType, NxFileList entries)
{
    beginResetModel();
    m_entries.clear();

    m_view.type = viewType;
    bool has_title_icon = false;
    for (auto entry : entries) {
        explorerModelEntry modelEntry;
        modelEntry.file = entry;

        if (viewType == UserSave && m_userDB && entry->hasUserID()) {
            auto user = m_userDB->getUserByUserId(entry->userID());
            if (user.avatar_img)
                modelEntry.user_icon_m = QPixmap::fromImage(*user.avatar_img).scaledToWidth(50, Qt::SmoothTransformation);
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
};


void ExplorerModel::insertEntry(NxFile* entry) {

    beginInsertRows(index(m_entries.count(),0), 1, 1);

    explorerModelEntry modelEntry;
    modelEntry.file = entry;
    bool has_icon = false;

    if (m_view.type == UserSave && m_userDB && entry->hasUserID()) {
        auto user = m_userDB->getUserByUserId(entry->userID());
        if (user.avatar_img) {
            modelEntry.user_icon_m = QPixmap::fromImage(*user.avatar_img).scaledToWidth(50, Qt::SmoothTransformation);
            has_icon = true;
        }
    }

    m_entries << modelEntry;

    if (entry->hasAdditionalString("icon_url")) {
        setTitleIconFromUrl(entry);
        has_icon = true;
    }
    //emit resizeRowToContents(m_entries.count()-1);
    if (has_icon)
        emit setRowHeight(m_entries.count()-1, 50);

    endInsertRows();
    emit resizeColumnsToContents();

}

void ExplorerModel::updateAll() {
    auto topLeft = index(0, 0, QModelIndex());
    auto bottomRight = index(rowCount()-1, columnCount()-1, QModelIndex());
    emit dataChanged(topLeft, bottomRight, {Qt::DisplayRole});
}

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
        case FileColumn: {
            auto path = QString::fromStdWString(file->completePath());
            auto len = path.length() - m_parent->curDir().length() -1;
            return path.right(len);
        }
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
            return !entry.title_icon_m.isNull() ? entry.title_icon_m : QVariant();
        case UserColumn:
            return !entry.user_icon_m.isNull() ? entry.user_icon_m : QVariant();
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

void ExplorerModel::setTitleIconFromUrl(NxFile* file)
{
    if (!file->hasAdditionalString("icon_url"))
        return;

    auto cache_file_path = "cache/" + QString::fromStdString(file->titleIDString()) + ".jpg";
    QFile cache_file(cache_file_path);
    if (cache_file.exists()) {
        QPixmap map(cache_file.fileName(), "JPG");
        if (!map.isNull()) {
            for (int i(0); i < m_entries.count(); i++)
                if (m_entries[i].title_icon_m.isNull() && m_entries.at(i).file->titleID() == file->titleID())
                    m_entries[i].title_icon_m = map.scaledToWidth(50, Qt::SmoothTransformation);
        }
        else cache_file.remove();
        return;
    }

    if (!EnsureOutputDir("cache"))
        return;

    QNetworkRequest request(QUrl(QString::fromStdString(file->getAdditionalString("icon_url"))));
    auto reply = m_nm.get(request);
    if(reply->error())
        return;

    connect(reply, &QNetworkReply::finished, [=]()
    {
        if (reply->error())
            return;
        reply->deleteLater();

        auto filepath = cache_file_path;
        auto data = reply->readAll();
        auto img = QImage::fromData(data, "JPG").scaledToWidth(150, Qt::SmoothTransformation);
        if (img.isNull())
            return;

        img.save(filepath, "JPG");
        for (int i(0); i < m_entries.count(); i++)
            if (m_entries.at(i).title_icon_m.isNull() && m_entries.at(i).file->titleID() == file->titleID()) {
                m_entries[i].title_icon_m = QPixmap::fromImage(img).scaledToWidth(50, Qt::SmoothTransformation);
                auto m_idx = index(i, getColumnIx(TitleColumn));
                emit dataChanged(m_idx, m_idx, {Qt::DecorationRole});
                emit setRowHeight(i, 50);
            }
    });
}

void ExplorerModel::setTitleIconsFromUrl()
{
    QVector<iconQueue> icon_queue;
    for (int i(0); i < m_entries.count(); i++) if (m_entries.at(i).file->hasAdditionalString("icon_url")) {
        auto entry = m_entries[i];
        auto cache_file_path = "cache/" + QString::fromStdString(entry.file->titleIDString()) + ".jpg";
        QFile cache_file(cache_file_path);
        if (cache_file.exists()) {
            QPixmap img(cache_file.fileName(), "JPG");
            if (!img.isNull()) {
                m_entries[i].title_icon_m = img.scaledToWidth(50, Qt::SmoothTransformation);
                continue;
            }
            cache_file.remove();
        }
        for (auto queue : icon_queue) if (queue.title_id == entry.file->titleID()) {
            icon_queue.append({entry.file->titleID(), cache_file_path,
                               QUrl(QString::fromStdString(entry.file->getAdditionalString("icon_url"))) });
            break;
        }
    }

    if (icon_queue.isEmpty())
        return;

    if (!EnsureOutputDir("cache"))
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
            reply->deleteLater();

            auto filepath = entry.cache_file_path;
            auto data = reply->readAll();
            auto img = QImage(data).scaledToWidth(150, Qt::SmoothTransformation);
            if (img.isNull())
                return;

            img.save(filepath, "JPG");
            for (int i(0); i < m_entries.count(); i++)
                if (m_entries.at(i).title_icon_m.isNull() && m_entries.at(i).file->titleID() == entry.title_id) {
                    auto entry = m_entries.at(i);
                    auto cache_file_path = "cache/" + QString::fromStdString(entry.file->titleIDString()) + ".jpg";
                        m_entries[i].title_icon_m = QPixmap::fromImage(img).scaledToWidth(50, Qt::SmoothTransformation);
                        auto m_idx = index(i, getColumnIx(TitleColumn));
                        emit dataChanged(m_idx, m_idx, {Qt::DecorationRole});
                        emit setRowHeight(i, 50);
                        continue;
                }
            emit resizeColumnsToContents();
        });

    }
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
    m_model.setUserDB(userDB);

    // Connect model to view
    ui->tableView->setModel(&m_model);
    connect(&m_model, &ExplorerModel::resizeRowToContents, ui->tableView, &QTableView::resizeRowToContents);
    //connect(&m_model, &ExplorerModel::resizeColumnsToContents, ui->tableView, &QTableView::resizeColumnsToContents);
    connect(&m_model, &ExplorerModel::resizeColumnsToContents, [&](){
        ui->tableView->resizeColumnsToContents();
        auto title_ix = m_model.getColumnIx(TitleColumn);
        if (title_ix >= 0)
            ui->tableView->horizontalHeader()->setSectionResizeMode(title_ix, QHeaderView::Stretch);
    });

    connect(&m_model, &ExplorerModel::setRowHeight, ui->tableView, &QTableView::setRowHeight);

    // Selection model
    connect(ui->tableView->selectionModel(), &QItemSelectionModel::selectionChanged, [&](const QItemSelection &selected, const QItemSelection &deselected) {
        on_selection_changed();
    });

    // Signal connections
    qRegisterMetaType<CpyQueue>("CpyQueue");
    qRegisterMetaType<ProgressInfo>("ProgressInfo");
    qRegisterMetaType<Qt::Orientation>("Qt::Orientation");
    qRegisterMetaType<QVector<int>>("QVector<int>");
    qRegisterMetaType<QQueue<NxFile*>>("QQueue<NxFile*>");
    qRegisterMetaType<NxFileList>("NxFileList");
    qRegisterMetaType<QList<QPersistentModelIndex>>("QList<QPersistentModelIndex>");
    connect(this, SIGNAL(updateViewSignal()), this, SLOT(updateView()));
    connect(this, &Explorer::error_signal, this, &Explorer::error);
    connect(this, &Explorer::listFS_signal, this, &Explorer::listFS);
    connect(this, &Explorer::extractFS_signal, this, &Explorer::extractFS);
    connect(this, &Explorer::loadingWdgtSetVisibleSignal, this, &Explorer::loadingWdgtSetVisible);
    connect(&m_vfsRunner, &VfsMountRunner::error, this, &Explorer::error);
    connect(&m_hactool, &HacToolNet::error, [&](QString e){ error(1, e); });

    setWindowFlags(Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
    connect(this, &Explorer::insertEntry, &m_model, &ExplorerModel::insertEntry);

    // Create status bar
    m_statusBar = new QStatusBar(this);
    ui->footerLayout->addWidget(m_statusBar);

    // Ensure filesystem is mounted
    if (partition->mount_fs())
        return;

    m_loading_movie= new QMovie(":/images/loading_wheel.gif");
    m_loading_movie->setScaledSize(QSize(30, 30));
    ui->loadingLabel->setMovie(m_loading_movie);
    ui->loadingLabel->show();
    m_loading_movie->start();
    ui->loadingLabel->hide();

    ui->currentDir_combo->addItem("/save (Saves)", "/save");
    ui->currentDir_combo->addItem("/Contents/registered (Installed titles)", "/Contents/registered");
    ui->currentDir_combo->addItem("/Contents/placehld (Downloaded titles)", "/Contents/placehld");
}

Explorer::~Explorer()
{
    delete ui;
    ui = nullptr;
    if (future.isRunning()) {
        watcher->disconnect();
        future.cancel();
        future.waitForFinished();
        delete watcher;
    }
    delete userDB;
    cache_entries.clear();
    delete m_loading_movie;
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

void Explorer::loadingWdgtSetVisible(bool visible)
{
    visible ? ui->loadingLabel->show() : ui->loadingLabel->hide();
    this->update();
}


void Explorer::askForVfsMount(std::function<void()> callback, const QString &question)
{
    connect(&m_vfsRunner, &VfsMountRunner::mounted, [&](){
        emit loadingWdgtSetVisible(false);
        if (callback)
            callback();
    });
    emit loadingWdgtSetVisible(true);
    m_vfsRunner.run(m_partition, !question.isEmpty() ? question :
            "Partition needs to be mounted as virtual disk.\n Click 'Yes' to mount partition.");
    return;
}

/*
 * Scan all files inside a directory (default mode is recursive)
 */
void Explorer::readDir(bool isRecursive)
{
    auto root_qstr = m_current_dir;
    current_entries.clear();

    if (isdebug) dbg_wprintf(L"Explorer::readDir() %ls\n", m_current_dir.toStdWString().c_str());

    // Read from cache
    auto cache = cache_entries.at(root_qstr);
    if (cache) {
        current_entries = *cache;
        for (auto entry : current_entries)
            emit insertEntry(entry);

        return;
    }

    auto root = root_qstr.toStdWString();
    QQueue<wstring> queue;
    NxTitle *title = nullptr, *previous_title = nullptr;

    queue.enqueue(root);
    while (!queue.empty())
    {
        DIR dp;
        FILINFO fno;
        auto cur_dir = queue.dequeue();
        if (isdebug) dbg_wprintf(L"Explorer::readDir() dequeue %ls\n", cur_dir.c_str());

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

            // Get extra info from title database (or from previous entry)
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
            else if (file->isNCA() && m_partition->type() == SYSTEM
                     && (title = ncaDB->findTitleByFileName(QString::fromStdWString(file->filename()))))
            {
                file->setTitleID(title->u64_id);
                file->setAdditionalString("title_name", title->name.toStdString());
                file->setContentType(title->content_type.toStdString());
            }

            // Explorer dialog closed ?
            if (!ui) {
                f_closedir(&dp);
                return;
            }
            emit insertEntry(file);
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
    //m_model.setModel(m_viewtype, current_entries);
    auto title_ix = m_model.getColumnIx(TitleColumn);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    if (title_ix >= 0)
        ui->tableView->horizontalHeader()->setSectionResizeMode(title_ix, QHeaderView::Stretch);
    ui->tableView->resizeColumnsToContents();
    ui->tableView->resizeRowsToContents();
    emit closeLoadingWdgt();
}

NxFileList Explorer::selectedFiles()
{
    NxFileList files;
    for (auto entry : ui->tableView->selectionModel()->selectedRows())
        files << m_model.entryAt(entry.row());

    return files;
}

CpyQueue Explorer::getCopyQueue(NxFileList selectedFiles, bool force_dirOutput)
{
    CpyQueue queue;
    if (!selectedFiles.count())
        return queue;

    if (isdebug) dbg_printf("Explorer::getCopyQueue() selection count: %d\n", selectedFiles.count());

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
        if (isdebug) dbg_wprintf(L"Explorer::getCopyQueue() enqueue %ls \n", file->completePath().c_str());
    }
    return queue;
}

void Explorer::do_copy(CpyQueue queue)
{
    if (queue.isEmpty()) return; // prevent nullptr exception

    u32 buff_size = 0x400000; // 4 MB
    u8* buffer = (u8*)malloc(buff_size); // Allocate buffer
    auto exit = [&](const QString &err = "", NxFile* file = nullptr) { // exit lamda
        free(buffer);
        if (file) file->close();
        if (!err.isEmpty()) emit error_signal(1, err);
        emit workFinished();
    };

    bool moreThan1File = queue.count()>1;
    ProgressInfo pi;
    pi.mode = COPY;
    pi.begin_time = chrono::system_clock::now();
    for (auto it : queue)
        pi.bytesTotal += it.nxFile->size();
    strcpy_s(pi.storage_name, moreThan1File ? QString("%1 files").arg(queue.count()).toStdString().c_str()
                                            : QFileInfo(queue.at(0).destination).fileName().toStdString().c_str());
    emit sendProgress(pi);

    while (!queue.isEmpty()) // Process queue
    {
        auto item = queue.dequeue();
        if (isdebug) dbg_wprintf(L"Explorer::do_copy() dequeue %ls\n", item.source.toStdWString().c_str());

        if (!item.nxFile->open())
            return exit("Failed to open " + QString::fromStdWString(item.nxFile->completePath()));

        QFile out_file(item.destination);
        if (!out_file.open(QIODevice::WriteOnly))
            return exit("Failed to open for writing " + item.destination, item.nxFile);

        ProgressInfo spi;
        spi.isSubProgressInfo = true;
        spi.mode = COPY;
        strcpy_s(spi.storage_name, QFileInfo(out_file).fileName().toStdString().c_str());
        spi.begin_time = chrono::system_clock::now();
        spi.bytesTotal = item.nxFile->size();
        if (moreThan1File) emit sendProgress(spi);

        UINT br; s64 bw;
        while (!item.nxFile->read((void*)buffer, buff_size, &br) && br)
        {
            if ((bw = out_file.write((const char*)buffer, (qint64)br)) < 0)
                return exit("Failed to write to " + item.destination, item.nxFile);

            pi.bytesCount += (u64)bw;
            spi.bytesCount += (u64)bw;
            if (moreThan1File) emit sendProgress(spi);
            emit sendProgress(pi);
        }
        out_file.close();
        item.nxFile->close();
    }
    exit();
}
void Explorer::do_extractFS_Hactool(CpyQueue queue)
{
    if (queue.isEmpty()) return; // prevent nullptr exception
    auto exit = [&](const QString &err = "") { // exit lamda
        if (!err.isEmpty()) emit error_signal(1, err);
        emit workFinished();
    };

    auto destination = queue.at(0).destination; // destination is a directory, the same for each file
    ProgressInfo pi;
    pi.mode = COPY;
    pi.bytesTotal = (pi.bytesCount = 0) + (u64)queue.count();
    pi.begin_time = chrono::system_clock::now();
    if (queue.count() == 1)
        strcpy_s(pi.storage_name, QString::fromStdWString(queue.at(0).nxFile->filename()).toStdString().c_str());
    else sprintf(pi.storage_name, "%d files", queue.count());
    emit sendProgress(pi);

    if (!pi.bytesTotal)
        return exit("No file to extract");

    while (!queue.isEmpty()) // Process queue
    {
        auto entry = queue.dequeue();
        auto file = entry.nxFile;
        auto cur_des = destination + "/" + (file->titleID() ? QString::fromStdString(file->normalizedTitleLabel())
                                                            : QString::fromStdWString(file->filename()));
        ProgressInfo spi;
        spi.isSubProgressInfo = true;
        spi.mode = COPY;
        strcpy_s(spi.storage_name, QString::fromStdWString(file->filename()).toStdString().c_str());
        spi.begin_time = chrono::system_clock::now();
        spi.bytesTotal = (spi.bytesCount = 0)++;
        if (pi.bytesTotal>1) emit sendProgress(spi);

        if (!EnsureOutputDir(cur_des, CreateAlways))
            return exit(QString("Failed to create dir %1").arg(cur_des));

        if (!m_hactool.extractFiles(entry.source, file->isNCA() ? HacToolNet::Nca : HacToolNet::Save, cur_des))
            return exit( m_hactool.lastError().isEmpty() ? "Hactoolnet : failed to extract file " + entry.source
                                                         :  m_hactool.lastError());
        spi.bytesCount++ && pi.bytesCount++;
        if (pi.bytesTotal>1) emit sendProgress(spi);
        emit sendProgress(pi);
    }
    exit();
}
void Explorer::do_extractFS(CpyQueue queue)
{
    if (queue.isEmpty()) return; // prevent nullptr exception

    u32 buff_size = 0x400000; // 4 MB
    u8* buffer = (u8*)malloc(buff_size); // Allocate buffer
    auto exit = [&](const QString &err = "") { // exit lamda
        free(buffer);
        if (!err.isEmpty()) emit error_signal(1, err);
        emit workFinished();
    };

    auto destination = queue.at(0).destination; // destination is a directory, the same for each file
    ProgressInfo pi;
    pi.mode = COPY;
    int file_count = 0;
    for (auto entry : queue) for (auto file : NxSave(entry.nxFile).listFiles()) {
        pi.bytesTotal += file.size;
        file_count++;
    }
    pi.begin_time = chrono::system_clock::now();
    sprintf(pi.storage_name, "%d files", file_count);
    emit sendProgress(pi);

    while (!queue.isEmpty())  // Process queue
    {
        auto item = queue.dequeue();
        NxSave save(item.nxFile);
        if (isdebug) dbg_wprintf(L"Explorer::do_extractFS() dequeue save %ls\n", save.completePath().c_str());

        for (auto file : save.listFiles())
        {
            QString cur_dest = destination + "/" + (item.nxFile->titleID() ? QString::fromStdString(item.nxFile->normalizedTitleLabel())
                                                                           : QString::fromStdWString(item.nxFile->filename()));
            if (!EnsureOutputDir(cur_dest, CreateAlways))
                return exit(QString("Failed to create dir %1").arg(cur_dest));

            QFile out_file(cur_dest.append("/" + QString::fromStdString(file.completePath())));
            if (!out_file.open(QIODevice::WriteOnly))
                return exit(QString("Failed to open file for writing: %1").arg(cur_dest));

            ProgressInfo spi;
            spi.mode = COPY;
            spi.bytesTotal = file.size;
            spi.isSubProgressInfo = true;
            spi.begin_time = chrono::system_clock::now();
            strcpy_s(spi.storage_name, QFileInfo(out_file).fileName().toStdString().c_str());
            emit sendProgress(spi);

            u64 br; s64 bw;
            while (spi.bytesCount < spi.bytesTotal && (br = save.readSaveFile(file, buffer, spi.bytesCount, buff_size)) > 0)
            {
                if ((bw = out_file.write((const char*)buffer, (qint64)br)) < 0)
                    return exit(QString("Failed to write file: %1").arg(cur_dest));

                pi.bytesCount += (u64)bw;
                emit sendProgress(pi);
                spi.bytesCount += (u64)bw;
                emit sendProgress(spi);
            }
            if (spi.bytesCount != spi.bytesTotal)
                return exit(QString("Failed to write file: %1").arg(cur_dest));

            out_file.close();
        }
    }
    exit();
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

void Explorer::on_selection_changed()
{
    auto selection = ui->tableView->selectionModel()->selectedRows();

    bool isMultipleSelection = selection.count()>1;
    auto view = ui->tableView;
    auto setAllToolTip = [&](QWidget *it, const QString &s) { it->setStatusTip(s); it->setToolTip(s); };

    // Dsable buttons
    for (auto o : QList<QWidget*>() << ui->saveButton << ui->decrypt_button << ui->listFs_button << ui->extractFs_button)
        o->setDisabled(true);

    // Disable actions
    for (auto a : view->actions()) {view->removeAction(a); delete a; }

    if (!selection.count())
        return;

    auto enable_action = [&](QPushButton *obj, QString lbl, const char *slot) {
        QAction* action = new QAction(obj->icon(), lbl);
        action->setStatusTip(lbl);
        connect(action, &QAction::triggered, [=]() { QMetaObject::invokeMethod(this, slot, Q_ARG(NxFileList, selectedFiles()));});
        connect(obj, &QPushButton::clicked, [=](bool) { QMetaObject::invokeMethod(this, slot, Q_ARG(NxFileList, selectedFiles()));});
        view->addAction(action);
        obj->setEnabled(true);
        setAllToolTip(obj, lbl);
    };

    QString selection_label = isMultipleSelection ? (QString("[%1 files]").arg(selection.count())) : "";

    // Enable buttons & actions
    auto fs_str = QString(m_model.viewType() == UserSave ? "saveFS" : "romFS");
    enable_action(ui->saveButton, "Save as... " + selection_label, "save");
    if (m_model.viewType() == Generic)
        return;
    if (m_model.viewType() == Nca)
        enable_action(ui->decrypt_button, "Decrypt and save as... " + selection_label, "decrypt");
    if (selection.count() == 1)
        enable_action(ui->listFs_button, "List files (from " + fs_str + ") " + selection_label, "listFS");
    enable_action(ui->extractFs_button, "Extract files (from " + fs_str + ") to directory..." + selection_label, "extractFS");

}

void Explorer::on_currentDir_combo_currentIndexChanged(int index)
{
    ui->currentDir_combo->setDisabled(true);
    m_viewtype = Generic;
    m_current_dir = ui->currentDir_combo->itemData(index).toString();
    if (m_current_dir.contains("/save"))
        m_viewtype = m_partition->type() == USER ? UserSave : SystemSave;
    else if (m_current_dir.contains("/Contents"))
        m_viewtype = Nca;

    setWindowTitle(" Explorer (" + QString::fromStdString(m_partition->partitionName()) + ":" + m_current_dir + ")");

    ui->warningLabel->setText("");
    ui->warningLabel->setToolTip("");
    ui->warningLabel->setStatusTip("");
    if (m_partition->type() == USER && m_viewtype == Nca && !HasGenericKey(&m_partition->nxStorage()->keyset, "header_key")) {
        ui->warningLabel->setText("Warning: header_key missing in keys.dat");
        QString tip = "Please re-import keys from prod.keys (generated by Lockpick RCM) => Options > Configure keyset";
        ui->warningLabel->setToolTip(tip);
        ui->warningLabel->setStatusTip(tip);
        ui->warningLabel->setStyleSheet("QLabel { color : red; }");
    }

    m_model.setModel(m_viewtype, NxFileList());
    auto title_ix = m_model.getColumnIx(TitleColumn);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    if (title_ix >= 0) {
        ui->tableView->horizontalHeader()->setSectionResizeMode(title_ix, QHeaderView::Stretch);
    }

    ui->loadingLabel->show();
    this->update();

    watcher = new QFutureWatcher<void>();
    connect(watcher, &QFutureWatcher<void>::finished, [&](){
        delete watcher;
        if (!ui)
            return;

        ui->loadingLabel->hide();
        ui->tableView->resizeRowsToContents();
        ui->currentDir_combo->setEnabled(true);
    });
    future = QtConcurrent::run(this, &Explorer::readDir, true);
    watcher->setFuture(future);
}

void Explorer::save(NxFileList selectedFiles)
{
    auto queue = getCopyQueue(selectedFiles);
    if (queue.isEmpty())
        return;

    if (isdebug) dbg_printf("Explorer::save() queue count: %d\n", queue.count());

    // Init/open progress dialog & start work in a new thread
    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), &progressDialog, SLOT(updateProgress(const ProgressInfo)));
    connect(this, SIGNAL(consoleWrite(const QString)), &progressDialog, SLOT(consoleWrite(const QString)));
    progressDialog.show();

    QFutureWatcher<void> watcher;
    connect(&watcher, &QFutureWatcher<void>::finished, &progressDialog, &Progress::on_WorkFinished);
    QFuture<void> future = QtConcurrent::run(this, &Explorer::do_copy, queue);
    watcher.setFuture(future);
    if (isdebug) dbg_printf("Explorer::save() selection count: %d, exec progress dialog\n", selectedFiles.count());
    progressDialog.exec();
}

void Explorer::decrypt(NxFileList selectedFiles)
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

void Explorer::listFS(NxFileList selectedFiles)
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
        QString title = QString::fromStdString(entry->hasAdditionalString("title_name") ? entry->getAdditionalString("title_name")
                                                                                        : entry->titleIDString());
        if (entry->hasUserID()) {
            auto user = userDB ? userDB->getUserByUserId(entry->userID()) : NxUserIdEntry();
            title.append(" (" + (user.nickname.isEmpty() ? QString::fromStdString(entry->userIDString()) : user.nickname) + ")");
        }
        dialog->setWindowTitle(title);
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

    if (!m_hactool.exists())
        return error(1, "hactoolnet.exe not found!");

    QStringList files;
    if (!m_partition->is_vfs_mounted())
        return askForVfsMount([=]() { emit listFS_signal(selectedFiles); });
    else files = m_hactool.listFiles(NxFilePath2VfsPath(m_partition, entry), entry->isNCA() ? HacToolNet::Nca : HacToolNet::Save);

    if (files.isEmpty())
        return (void) QMessageBox::information(this, "Information", "No file found");

    // filelist dialog
    auto dialog = new QDialog(this, Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
    auto layout = new QHBoxLayout();
    dialog->setLayout(layout);
    auto listWdgt = new QListWidget(dialog);
    layout->addWidget(listWdgt);
    for (auto file : files)
        listWdgt->insertItem(listWdgt->count(), new QListWidgetItem(file));
    dialog->exec();
}


void Explorer::extractFS(NxFileList selectedFiles)
{
    if (!selectedFiles.count())
        return;

    if (m_viewtype == Nca && !m_hactool.exists())
        return error(1, "hactoolnet.exe not found!");

    if (m_viewtype == Nca && !m_partition->is_vfs_mounted())
        return askForVfsMount([=]() { emit extractFS_signal(selectedFiles); });

    auto queue = getCopyQueue(selectedFiles, true);
    if (queue.isEmpty())
        return;

    if (m_viewtype == Nca) {
        // vfs prefix source path for each queued entry
        CpyQueue new_queue;
        for (auto entry : queue) {
            entry.source = NxFilePath2VfsPath(m_partition, entry.nxFile);
            new_queue << entry;
        }
        queue = new_queue;
    }

    // Init/open progress dialog & start work in a new thread
    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), &progressDialog, SLOT(updateProgress(const ProgressInfo)));
    progressDialog.show();
    QFutureWatcher<void> watcher;
    connect(&watcher, &QFutureWatcher<void>::finished, &progressDialog, &Progress::on_WorkFinished);
    QFuture<void> future = QtConcurrent::run(this, m_viewtype == Nca ? &Explorer::do_extractFS_Hactool
                                                                     : &Explorer::do_extractFS
                                                                     , queue);
    watcher.setFuture(future);
    progressDialog.exec();
}

