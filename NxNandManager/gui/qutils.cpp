#include "qutils.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QtConcurrent/QtConcurrent>
#include <QMessageBox>
#include "../NxSave.h"

bool EnsureOutputDir(const QString &dir_path)
{
    QString dir(dir_path);
    return EnsureOutputDir(dir, ExistingOK);
}
bool EnsureOutputDir(QString &dir_path, DirOutputMode mode)
{
    QFileInfo dir(dir_path);
    auto path = dir.absoluteFilePath();

    if (!QDir(path).exists()) {
        if (QDir().mkpath(path)) {
            dir_path = path;
            return true;
        }
        return false;
    }

    if (mode == CreateAlways) {
        for (int i(0); i < 99; i++) {
            auto cur_path = path + "_" + QStringLiteral("%1").arg(i, 2, 10, QLatin1Char('0'));
            if (!QDir(cur_path).exists() && QDir().mkpath(cur_path)) {
                dir_path = cur_path;
                return true;
            }
        }
        return false;
    }

    dir_path = path;
    return true;
}

QString NxFilePath2VfsPath(NxPartition *nxp, NxFile *file)
{
    QString path;
    if (!nxp->is_vfs_mounted())
        return path;

    path = QString::fromStdWString(nxp->getVolumeMountPoint()
           + file->completePath().substr(1, file->completePath().length() -1));
    if (file->isNXA())
        path.append("/00");

    return QFileInfo(path).absoluteFilePath();
}

QString FileDialog(QWidget *parent, fdMode mode, const QString& defaultName, const QString& filters)
{
    QFileDialog fd(parent);
    QString filePath;
    if (mode == open_file)
    {
        filePath = fd.getOpenFileName(parent, "Open file", "default_dir\\", filters);
    }
    else
    {
        fd.setAcceptMode(QFileDialog::AcceptSave); // Ask overwrite
        filePath = fd.getSaveFileName(parent, "Save as", "default_dir\\" + defaultName);
    }
    if (!filePath.isEmpty())
    {
        QSettings appSettings;
        QDir CurrentDir;
        appSettings.setValue("default_dir", CurrentDir.absoluteFilePath(filePath));
    }
    return filePath;
}

Resource::Resource(const QString &name, const QString &update_url) : m_name(name), m_update_url(update_url)
{
    m_nm = new QNetworkAccessManager(this);
    QString path = "res/" + name;
    QFile fs_file(path);

    // File doesn't exists
    if (!fs_file.exists())
    {
        // Update from url
        if (!m_update_url.isEmpty())
            updateFromUrl();

        // Set path to memory resource
        path.prepend(":");
    }

    m_file = new QFile(path);
}

void Resource::updateFromUrl()
{
    if (m_update_url.isEmpty())
        return;

    QDir cache_dir("res");
    if (!cache_dir.exists() && !QDir().mkdir("res"))
        return;

    QUrl url(m_update_url);
    QNetworkRequest request(url);
    auto reply = m_nm->get(request);
    if(reply->error())
        return;

    connect(reply, &QNetworkReply::finished, [=]()
    {
        if (reply->error())
            return;

        QFile file("res/" + m_name);
        if (!file.open(QIODevice::WriteOnly))
            return;

        if (file.write(reply->readAll()) < 0)
            return;

        // Recreate QFile member
        file.close();
        delete m_file;
        m_file = new QFile("res/" + m_name);

        reply->deleteLater();
        emit update_complete();
    });
}

NxTitleDB::NxTitleDB(const QString &json_file, const QString &update_url, int delay) :
    json_file(json_file), update_url(update_url), db_expiration_delay(delay)
{
    resource = new Resource(json_file, update_url);
    connect(resource, &Resource::update_complete, this, &NxTitleDB::populate_titles);
    connect(this, &NxTitleDB::update_signal, resource, &Resource::updateFromUrl);

    QtConcurrent::run(this, &NxTitleDB::populate_titles);
}
NxTitleDB::~NxTitleDB()
{
    delete resource;
}
void NxTitleDB::populate_titles()
{
    std::lock_guard<std::mutex> lock(_m_titles_mutex);
    QFile& file = *resource->get();
    if (!file.exists() || !file.open(QIODevice::ReadOnly))
        return;

    QJsonObject json = QJsonDocument::fromJson(file.readAll()).object();
    file.close();
    if (!json.contains("all_titles"))
        return;

    bool ok;
    m_titles.clear();
    for (auto title_obj : json["all_titles"].toObject())
    {
        auto title = title_obj.toObject();
        NxTitle nx_title;
        if (title.contains("id"))
        {
            nx_title.id = title["id"].toString();
            nx_title.u64_id = nx_title.id.toULongLong(&ok, 16);
            if (!ok)
                continue;
        }
        if (title.contains("name"))
            nx_title.name = title["name"].toString();
        if (title.contains("iconUrl"))
            nx_title.icon_url = title["iconUrl"].toString();

        if (nx_title.u64_id)
            m_titles.append(nx_title);
    }

    if (json.contains("timestamp") && json["timestamp"].toInt())
        checkUpdate(json["timestamp"].toInt());
}
void NxTitleDB::checkUpdate(int latest_timestamp)
{
    if (!latest_timestamp)
        return;
    if (std::time(nullptr) - latest_timestamp > db_expiration_delay)
        emit update_signal();
}
NxTitle* NxTitleDB::findTitleByID(u64 id)
{
    std::lock_guard<std::mutex> lock(_m_titles_mutex);
    if (!id)
        return nullptr;

    for (int i(0); i < m_titles.count(); i++)
    {
        if (m_titles[i].u64_id == id)
            return &m_titles[i];
        if (m_titles[i].u64_id > id)
            break;
    }

    _m_titles_mutex.unlock();
    // DLC, find base game
    u64 mask = 0xFFFFFFFFFFFF000;
    if (id >= 0x0100000000010000 && id != (id & mask))
        return findTitleByID(id & mask);
    return nullptr;
}
NxTitle* NxTitleDB::findTitleByID(QString id)
{
    bool ok;
    u64 u64_id = id.toULongLong(&ok, 16);
    if (!ok || !u64_id)
        return nullptr;

    return findTitleByID(u64_id);
}

NxUserDB::~NxUserDB()
{
    for (auto u : m_users) if (u.avatar_img)
        delete u.avatar_img;
}

void NxNcaDB::populate_titles()
{
    std::lock_guard<std::mutex> lock(_m_titles_mutex);
    QFile& file = *resource->get();
    if (!file.exists() || !file.open(QIODevice::ReadOnly))
        return;

    QJsonObject json = QJsonDocument::fromJson(file.readAll()).object();
    file.close();
    if (!json.contains("ncas"))
        return;

    bool ok;
    m_titles.clear();
    for (auto title_obj : json["ncas"].toArray())
    {
        auto title = title_obj.toObject();
        NxTitle nx_title;
        if (title.contains("title_id"))
        {
            nx_title.id = title["title_id"].toString();
            nx_title.u64_id = nx_title.id.toULongLong(&ok, 16);
            if (!ok)
                continue;
        }
        if (title.contains("title_label"))
            nx_title.name = title["title_label"].toString();
        if (title.contains("type"))
            nx_title.type = title["type"].toString();
        if (title.contains("nca_filename"))
            nx_title.filename.append(title["nca_filename"].toString());
        if (title.contains("type"))
            nx_title.content_type = title["type"].toString();

        if (nx_title.u64_id)
            m_titles.append(nx_title);
    }
    if (json.contains("timestamp") && json["timestamp"].toInt())
        checkUpdate(json["timestamp"].toInt());    
}

NxTitle* NxNcaDB::findTitleByFileName(QString filename)
{
    std::lock_guard<std::mutex> lock(_m_titles_mutex);
    QString f = filename;
    if (f.contains(".nca") && f.length() > 32)
        f = f.left(32);

    for (int i(0); i < m_titles.count(); i++)
        if (m_titles[i].filename.contains(f))
            return &m_titles[i];
    return nullptr;
}

NxUserDB::NxUserDB(NxStorage *nxStorage)
{
    if (!nxStorage)
        return;

    // Ensure SYSTEM filesystem is mounted
    NxPartition *system = nxStorage->getNxPartition(SYSTEM);
    if (!system || system->mount_fs() != SUCCESS)
        return;

    auto accounts = new NxSave(system, L"/save/8000000000000010");
    if (!accounts->exists() || !accounts->open()) {
        delete accounts;
        return;
    }

    NxSaveFile profiles;
    if (!accounts->getSaveFile(&profiles, "/su/avators/profiles.dat")) {
        delete accounts;
        return;
    }

    u8 *buffer = new u8[profiles.size];
    if (accounts->readSaveFile(profiles, buffer, 0, profiles.size) != profiles.size) {
        delete[] buffer;
        delete accounts;
        return;
    }

    // Populate User DB
    for (u32 ofs = 0x10; ofs + 0xC8 <= profiles.size; ofs += 0xC8)
    {
        profile_entry entry;
        memcpy(&entry, &buffer[ofs], 0xC8);

        if (!entry.user_id_save._u32)
            continue;

        auto &uid = entry.user_id_save;
        uid._u32 = __builtin_bswap32(uid._u32);
        for (int i(0); i < 6; i++) if (i != 2)
            uid._u16[i] = __builtin_bswap16(uid._u16[i]);
        u16 tmp = uid._u16[3];
        uid._u16[3] = uid._u16[5];
        uid._u16[5] = tmp;

        NxUserIdEntry user;
        user.user_id_str = QString::fromStdString(hexStr((u8*)&uid, 0x10));
        memcpy(user.user_id, &uid, 0x10);
        user.nickname = QString::fromStdString(entry.nickname);

        QString avatar_path = "/su/avators/";
        for (int i(0); i < 0x10; i++) {
            avatar_path.append(QStringLiteral("%1").arg(entry.user_id[i], 2, 16, QLatin1Char('0')));
            if (is_in(i, {3, 5, 7, 9}))
                avatar_path.append("-");
        }
        avatar_path.append(".jpg");
        NxSaveFile avatar;
        if (accounts->getSaveFile(&avatar, avatar_path.toStdString().c_str()) && avatar.size) {
            u8* img_buf = new u8[avatar.size];
            if (accounts->readSaveFile(avatar, img_buf, 0, avatar.size) == avatar.size) {
                user.avatar_img = new QImage();
                user.avatar_img->loadFromData(img_buf, (int)avatar.size);
            }
            delete[] img_buf;
        }
        m_users << user;
    }
    delete[] buffer;
    delete accounts;
}

NxUserIdEntry NxUserDB::getUserByUserId(u8 user_id[0x10])
{
    for (auto &user : m_users)
        if (!memcmp(user.user_id, user_id, 0x10))
            return user;

    return NxUserIdEntry();
}
void VfsMountRunner::run(NxPartition *p, const QString &YesNoQuestion)
{
    if (YesNoQuestion.length() && QMessageBox::question(nullptr, "Mount partition",
                                        YesNoQuestion, QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
        return;

    connect(p, &NxPartition::vfs_mounted_signal, this, &VfsMountRunner::mounted);
    connect(p, &NxPartition::vfs_callback, [&](long status){
        if (status == DOKAN_DRIVER_INSTALL_ERROR)
            emit error(1, "Dokan driver not installed. Please mount from main window to install driver.");
        else if (status < -1000)
            emit error((int)status, nullptr);
        else if (status != DOKAN_SUCCESS)
            emit error(1, QString::fromStdString(dokanNtStatusToStr(status)));
    });
    QtConcurrent::run(p, &NxPartition::mount_vfs, true, '\0', true, nullptr);
}
