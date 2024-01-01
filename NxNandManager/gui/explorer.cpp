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
    qRegisterMetaType<QQueue<CpyElement>>("QQueue<CpyElement>");
    qRegisterMetaType<ProgressInfo>("ProgressInfo");
    qRegisterMetaType<NxSaveFile>("NxSaveFile");
    qRegisterMetaType<Qt::Orientation>("Qt::Orientation");
    qRegisterMetaType<QVector<int>>("QVector<int>");
    qRegisterMetaType<NxFile*>("NxFile*");
    qRegisterMetaType<QList<NxFile*>>("QList<NxFile*>");
    qRegisterMetaType<QList<QPersistentModelIndex>>("QList<QPersistentModelIndex>");
    connect(this, SIGNAL(updateViewSignal()), this, SLOT(updateView()));
    connect(this, &Explorer::error_signal, this, &Explorer::error);
    connect(this, &Explorer::listFS_signal, this, &Explorer::listFS);
    connect(this, &Explorer::extractFS_signal, this, &Explorer::extractFS);
    connect(this, &Explorer::loadingWdgtSetVisibleSignal, this, &Explorer::loadingWdgtSetVisible);
    connect(&m_hactool, &HacToolNet::error, [&](QString e){ emit error_signal(1, e); });

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

    if (m_partition->type() == USER) {
        ui->currentDir_combo->addItem("/save (Saves)", "/save");
        ui->currentDir_combo->addItem("/Contents/registered (Installed titles)", "/Contents/registered");
    } else {
        ui->currentDir_combo->addItem("/Contents/registered (Installed titles)", "/Contents/registered");
        ui->currentDir_combo->addItem("/save (Saves)", "/save");
    }
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
    if (m_loading_movie)
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
    if (m_vfsRunner != nullptr)
        delete m_vfsRunner;

    m_vfsRunner = new VfsMountRunner(m_partition);

    connect(m_vfsRunner, &VfsMountRunner::error, this, &Explorer::error);
    connect(m_vfsRunner, &VfsMountRunner::mounted, [=](){
        emit loadingWdgtSetVisible(false);
        if (callback)
            callback();
    });
    emit loadingWdgtSetVisible(true);    
    m_vfsRunner->run(!question.isEmpty() ? question :
            "Partition needs to be mounted as virtual disk (+ virtual FS).\n Click 'Yes' to mount partition.");
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
    QString target = "default_dir\\";
    if (!isDirOutput)
            target.append(QString::fromStdWString(selectedFiles.at(0)->filename()));

    QString path = FileDialog(this, isDirOutput ? save_to_dir : save_as, target);

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

    auto destination = QFileInfo(queue.at(0).destination).path(); // destination is a directory, the same for each file
    ProgressInfo pi;
    pi.mode = EXTRACT;
    pi.percent = -1; // Force simple progress
    pi.bytesTotal = (u64)queue.count();
    pi.begin_time = chrono::system_clock::now();

    if (!pi.bytesTotal)
        return exit("No file to extract");

    QString errors;
    u32 good_count = 0;
    while (!queue.isEmpty()) // Process queue
    {
        auto entry = queue.dequeue();
        auto file = entry.nxFile;
        auto cur_des = destination + explicitOutputPathForNxFile(file) + "/";

        strcpy_s(pi.storage_name, QString::fromStdWString(file->filename()).toStdString().c_str());
        emit sendProgress(pi);

        connect(&m_hactool, &HacToolNet::updateProgress, [&](const ProgressInfo spi){
            emit sendProgress(spi);
        });

        if (!m_hactool.extractFiles(entry.source, file->isNCA() ? HacToolNet::Nca : HacToolNet::Save, cur_des))
            errors.append(m_hactool.lastError().isEmpty() ? "Hactoolnet : failed to extract file " + entry.source
                                                         :  m_hactool.lastError() + "\n");
        else good_count++;

        pi.bytesCount++;
        emit sendProgress(pi);
    }


    sprintf(pi.storage_name, "from %d file%s", good_count, good_count>1 ? "s" : "");
    emit sendProgress(pi);

    return exit(errors);
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

    auto destination = QFileInfo(queue.at(0).destination).path(); // destination is a directory, the same for each file
    ProgressInfo pi;
    pi.mode = EXTRACT;
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

            QString cur_dest = explicitOutputPathForNxFile(item.nxFile);

            if (!EnsureOutputDir(cur_dest))
                return exit(QString("Failed to create dir %1").arg(cur_dest));

            // Avoid duplicating slashes
            string file_path(file.completePath());
            QFile out_file;

            if (file_path.at(0) == '/') {
                out_file.setFileName(cur_dest.append(QString::fromStdString(file_path)));
            } else {
                out_file.setFileName(cur_dest.append("/" + QString::fromStdString(file_path)));
            }

            // Ensure the out path is created
            QString out_dir = QFileInfo(out_file).absolutePath();

            if (!EnsureOutputDir(out_dir))
                return exit(QString("Failed to create dir %1").arg(out_dir));

            if (!out_file.open(QIODevice::WriteOnly))
                return exit(QString("Failed to open file for writing: %1").arg(cur_dest));

            ProgressInfo spi;
            spi.mode = EXTRACT;
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

void Explorer::do_decryptNCA_Hactool(CpyQueue queue)
{
    if (queue.isEmpty()) return; // prevent nullptr exception
    auto exit = [&](const QString &err = "") { // exit lamda
        if (!err.isEmpty()) emit error_signal(1, err);
        emit workFinished();
    };

    ProgressInfo pi;
    pi.mode = DECRYPT;
    pi.percent = -1; // Force simple progress
    pi.bytesTotal = (u64)queue.count();
    pi.begin_time = chrono::system_clock::now();

    if (!pi.bytesTotal)
        return exit("No file to extract");

    QString errors;
    u32 good_count = 0;
    while (!queue.isEmpty()) // Process queue
    {
        auto entry = queue.dequeue();
        auto file = entry.nxFile;

        strcpy_s(pi.storage_name, QString::fromStdWString(file->filename()).toStdString().c_str());
        emit sendProgress(pi);

        if (!m_hactool.plaintextNCA(entry.source, entry.destination))
            errors.append(m_hactool.lastError().isEmpty() ? "Hactoolnet : failed to decrypt NCA " + entry.source
                                                          :  m_hactool.lastError() + "\n");
        else good_count++;
        pi.bytesCount++;
        emit sendProgress(pi);
    }

    if (pi.bytesTotal > 1) {
        sprintf(pi.storage_name, "%d file%s", good_count, good_count>2 ? "s" : "");
        emit sendProgress(pi);
    }
    exit(errors);
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

void Explorer::concurrentSlotWithProgressDlg(void (Explorer::*functor)(CpyQueue), CpyQueue queue)
{
    Progress progressDialog(m_parent, m_partition->parent);
    connect(this, &Explorer::sendProgress, &progressDialog, &Progress::updateProgress);
    connect(this, &Explorer::workFinished, &progressDialog, &Progress::on_WorkFinished);
    connect(&m_hactool, &HacToolNet::consoleWrite, &progressDialog, &Progress::consoleWrite);
    QtConcurrent::run(this, functor, queue);
    progressDialog.exec();
    disconnect(&m_hactool, &HacToolNet::consoleWrite, &progressDialog, &Progress::consoleWrite);
}

void Explorer::on_selection_changed()
{
    auto selection = selectedFiles();

    bool isMultipleSelection = selection.count()>1;
    auto view = ui->tableView;

    // Disable buttons & actions
    auto buttons =  QList<QWidget*>() << ui->saveButton << ui->decrypt_button << ui->listFs_button << ui->extractFs_button;
    for (auto b : buttons) { b->setDisabled(true); b->disconnect(); }
    for (auto a : view->actions()) {view->removeAction(a); delete a; }

    auto enable_action = [=](QPushButton *obj, QString lbl, void(Explorer::*functor)(QList<NxFile*>), bool enable = true)
    {
        obj->setEnabled(enable);
        obj->setStatusTip(lbl);
        obj->setToolTip(lbl);
        if (!enable)
            return;

        connect(obj, &QPushButton::clicked, [=](bool) {
            (this->*functor)(selectedFiles());
        });
        QAction* action = new QAction(obj->icon(), lbl);
        action->setStatusTip(lbl);
        connect(action, &QAction::triggered, [=]() {
            (this->*functor)(selectedFiles());
        });
        view->addAction(action);
    };

    QString selection_label = isMultipleSelection ? QString("[%1 files]").arg(selection.count()) : "";

    // Enable buttons & actions
    QString fs_str(m_model.viewType() == UserSave ? "saveFS" : "romFS");
    enable_action(ui->saveButton, QString("Save as... %1").arg(selection_label), &Explorer::save, selection.count());
    enable_action(ui->decrypt_button, QString("Decrypt and save as... %1").arg(selection_label),
                  &Explorer::decrypt, m_model.viewType() == Nca && selection.count());
    enable_action(ui->listFs_button, QString("List files (from %1) %2").arg(fs_str).arg(selection_label),
                  &Explorer::listFS, selection.count() == 1 && m_model.viewType() != Generic);
    enable_action(ui->extractFs_button, QString("Extract files (from %1) to directory... %2").arg(fs_str).arg(selection_label),
              &Explorer::extractFS, m_model.viewType() != Generic && selection.count());

    if (isMultipleSelection || selection.isEmpty())
        return;

    auto enable_c2c_action = [=](QString lbl, viewColumnType type)
    {
        QAction* action = new QAction(lbl);
        connect(action, &QAction::triggered, [=]() {
            QClipboard *qcb = QApplication::clipboard();
            auto entry = m_model.entryAt(ui->tableView->selectionModel()->selectedRows().first().row());
            if (type == FileColumn)
                qcb->setText(QString::fromStdWString(entry->filename()));
            else if (type == SizeColumn)
                qcb->setText(QString::fromStdString(GetReadableSize(entry->size())));
            else if (type == TitleColumn)
                qcb->setText(QString::fromStdString(entry->titleIDString()));
            else if (type == TypeColumn)
                qcb->setText(QString::fromStdString(entry->contentTypeString()));
            else if (type == UserColumn)
                qcb->setText(QString::fromStdString(entry->userIDString()));

        });
        view->addAction(action);
    };

    //enum viewColumnType { FileColumn, SizeColumn, TitleColumn, TypeColumn, UserColumn, UnknownColumn };
    auto row_ix = ui->tableView->selectionModel()->selectedRows().first().row();
    auto entry = m_model.entryAt(row_ix);
    for (int i(0); i < m_model.columnCount(); i++)
        if (m_model.getColumnType(i) == FileColumn)
            enable_c2c_action("Copy filename to clipboard", FileColumn);
        else if (m_model.getColumnType(i) == SizeColumn)
            enable_c2c_action("Copy filesize to clipboard", SizeColumn);
        else if (m_model.getColumnType(i) == TitleColumn)
            enable_c2c_action("Copy titleID to clipboard", TitleColumn);
        else if (m_model.getColumnType(i) == TypeColumn)
            enable_c2c_action("Copy content type to clipboard", TypeColumn);
        else if (m_model.getColumnType(i) == UserColumn)
            enable_c2c_action("Copy userID to clipboard", UserColumn);

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

    setWindowTitle(" Explorer (" + QString::fromStdString(m_partition->partitionName()) + ":" + m_current_dir + ") - Beta version (WIP)");

    ui->warningLabel->setText("");
    ui->warningLabel->setToolTip("");
    ui->warningLabel->setStatusTip("");
    QString warning_txt;
    QString warning_tip;
    if (!m_hactool.exists()) {
        warning_txt = "hactoolnet.exe not found!";
        warning_tip = "Program path should be: " + m_hactool.pgm_path();
    }
    else if (m_partition->type() == USER && m_viewtype == Nca && !HasGenericKey(&m_partition->nxStorage()->keyset, "header_key")) {
        warning_txt = "Warning: header_key missing in keys.dat";
        warning_tip = "Please re-import keys from prod.keys (generated by Lockpick RCM) => Options > Configure keyset";

    }
    if (!warning_txt.isEmpty()) {
        ui->warningLabel->setText(warning_txt);
        ui->warningLabel->setStyleSheet("QLabel { color : red; }");
    }
    if (!warning_tip.isEmpty()) {
        ui->warningLabel->setToolTip(warning_tip);
        ui->warningLabel->setStatusTip(warning_tip);
    }

    m_model.setModel(m_viewtype, NxFileList());
    auto title_ix = m_model.getColumnIx(TitleColumn);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    if (title_ix >= 0) {
        ui->tableView->horizontalHeader()->setSectionResizeMode(title_ix, QHeaderView::Stretch);
    }

    ui->loadingLabel->show();
    on_selection_changed();
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
    if (!selectedFiles.count())
        return;

    if (!m_hactool.exists())
        return error(0, "hactoolnet.exe not found!");

    if (!m_partition->is_vfs_mounted() || (m_partition->is_vfs_mounted() && !m_partition->vfs()->virtualize_nxa))
        return askForVfsMount([=]() { decrypt(selectedFiles); });

    auto queue = getCopyQueue(selectedFiles);
    if (queue.isEmpty())
        return;

    for (int i(0); i < queue.count(); i++) // vfs prefix source pathes in queue
        queue[i].source = NxFilePath2VfsPath(m_partition, queue[i].nxFile);

    concurrentSlotWithProgressDlg(&Explorer::do_decryptNCA_Hactool, queue);
}

void Explorer::listFS(NxFileList selectedFiles)
{
    if (!selectedFiles.count())
        return;

    auto entry = selectedFiles.at(0);
    QString title = QString::fromStdWString(entry->filename());
    if (entry->hasAdditionalString("title_name"))
        title.append(" - "+QString::fromStdString(entry->getAdditionalString("title_name")));

    if (entry->hasUserID()) {
        auto user = userDB ? userDB->getUserByUserId(entry->userID()) : NxUserIdEntry();
        title.append(" (" + (user.nickname.isEmpty() ? QString::fromStdString(entry->userIDString()) : user.nickname) + ")");
    }

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
        dialog->setWindowTitle(title);
        auto layout = new QVBoxLayout();
        dialog->setLayout(layout);
        auto listWdgt = new QTableWidget(dialog);
        layout->addWidget(listWdgt);
        listWdgt->setColumnCount(2);
        listWdgt->setSelectionBehavior(QAbstractItemView::SelectRows);
        listWdgt->setSelectionMode(QAbstractItemView::SingleSelection);
        listWdgt->setEditTriggers(QAbstractItemView::NoEditTriggers);
        listWdgt->setHorizontalHeaderLabels(QStringList() << "File" << "Size");
        u64 total_size = 0;
        for (auto file : files) {
            auto ix = listWdgt->rowCount();
            listWdgt->insertRow(ix);
            auto it = new QTableWidgetItem(QString::fromStdString(file.path + "/" + file.filename));
            it->setData(Qt::UserRole, QVariant::fromValue(file));
            listWdgt->setItem(ix, 0, it);
            listWdgt->setItem(ix, 1, new QTableWidgetItem(QString::fromStdString(GetReadableSize(file.size))));
            total_size += file.size;
        }
        listWdgt->resizeColumnsToContents();
        listWdgt->setContextMenuPolicy(Qt::ActionsContextMenu);
        QAction* saveAction = new QAction(QIcon(":images/save2.png"), "Save file as...");
        saveAction->setStatusTip("Extract file from save");
        connect(saveAction, &QAction::triggered, [=]() {
            auto file = listWdgt->selectedItems().at(0)->data(Qt::UserRole).value<NxSaveFile>();

            QFileDialog fd(this, "Save file as...", "default_dir\\" + QString::fromStdString(file.filename));
            fd.setFileMode(QFileDialog::AnyFile);
            fd.setAcceptMode(QFileDialog::AcceptSave);
            if (!fd.exec())
                return;

            QFile output(fd.selectedFiles().at(0));
            if (output.exists())
                output.remove();

            if(!output.open(QIODevice::WriteOnly))
                emit error(1, QString("Failed to open %s for writing").arg(output.fileName()));

            u32 buff_size = 0x400000; // 4 MB
            u8* buffer = (u8*)malloc(buff_size); // Allocate buffer
            u64 offset = 0, br = 0;
            s64 bw = 0;
            while ((br = file.parent->readSaveFile(file, (void*)buffer, offset, buff_size)) > 0)
            {
                if ((bw = output.write((const char*)buffer, (qint64)br)) != (s64)br)
                    break;
                offset += br;
            }
            output.close();

            if (offset != file.size) {
                output.remove();
                emit error(1, QString("Failed to write %s").arg(output.fileName()));
            }
            else QMessageBox::information(this, "Success", "File saved.");
            free(buffer);
        });
        listWdgt->addAction(saveAction);

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
    if (!m_partition->is_vfs_mounted() || (m_partition->is_vfs_mounted() && !m_partition->vfs()->virtualize_nxa))
        return askForVfsMount([=]() { emit listFS_signal(selectedFiles); });
    else files = m_hactool.listFiles(NxFilePath2VfsPath(m_partition, entry), entry->isNCA() ? HacToolNet::Nca : HacToolNet::Save);

    if (files.isEmpty())
        return m_hactool.lastError().isEmpty() ? (void) QMessageBox::information(this, "Information", "No file found") : (void)0;

    // filelist dialog
    auto dialog = new QDialog(this, Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
    auto layout = new QHBoxLayout();
    dialog->setLayout(layout);
    dialog->setWindowTitle(title);
    auto listWdgt = new QTableWidget(dialog);
    listWdgt->setColumnCount(1);
    listWdgt->setEditTriggers(QAbstractItemView::NoEditTriggers);
    listWdgt->setHorizontalHeaderLabels(QStringList() << "File");
    layout->addWidget(listWdgt);
    for (auto file : files) {
        auto ix = listWdgt->rowCount();
        listWdgt->insertRow(ix);
        listWdgt->setItem(ix, 0, new QTableWidgetItem(file));
    }
    listWdgt->resizeColumnsToContents();
    auto size_hint = listWdgt->columnWidth(0) + 80;
    dialog->resize(QSize(size_hint < this->width() ? size_hint : this->width(), files.size() > 5 ? 350 : 200));
    dialog->exec();
}

void Explorer::extractFS(QList<NxFile*> selectedFiles)
{
    if (!selectedFiles.count())
        return;

    if (m_viewtype == Nca && !m_hactool.exists())
        return error(1, "hactoolnet.exe not found!");

    if (m_viewtype == Nca && (!m_partition->is_vfs_mounted() || (m_partition->is_vfs_mounted() && !m_partition->vfs()->virtualize_nxa)))
        return askForVfsMount([=]() {
            emit extractFS_signal(selectedFiles);
        });

    auto queue = getCopyQueue(selectedFiles, true);
    if (queue.isEmpty())
        return;

    if (m_viewtype == Nca) {
        for (int i(0); i < queue.count(); i++) // vfs prefix source pathes in queue
            queue[i].source = NxFilePath2VfsPath(m_partition, queue[i].nxFile);
    }

    concurrentSlotWithProgressDlg(m_viewtype == Nca ? &Explorer::do_extractFS_Hactool : &Explorer::do_extractFS, queue);
}

QString Explorer::explicitOutputPathForNxFile(NxFile* file)
{

    QString path = "/";
    if (file == nullptr)
        return path;

    if (file->titleID())
    {
        path.append(QString::fromStdString(file->titleIDString()));

        if (file->hasAdditionalString("title_name"))
            path.append(" " + QString::fromStdString(file->normalizedTitleLabel()));

        path.append("/");
    }
    if (file->hasUserID())
    {
        auto user = userDB ? userDB->getUserByUserId(file->userID()) : NxUserIdEntry();
        path.append((user.nickname.isEmpty() ? QString::fromStdString(file->userIDString()) : user.nickname) + "/");
    }
    path.append(QString::fromStdWString(file->filename()));

    return path;
}
