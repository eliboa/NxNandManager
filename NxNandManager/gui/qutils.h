#ifndef QUTILS_H
#define QUTILS_H

#include <QWidget>
#include <QFileDialog>
#include <QFile>
#include <QSettings>
#include <QtNetwork>
#include "../res/utils.h"
#include "../NxFile.h"
#include <mutex>

enum DirOutputMode { CreateAlways, ExistingOK };
bool EnsureOutputDir(QString &dir_path, DirOutputMode mode = ExistingOK);
bool EnsureOutputDir(const QString &dir_path);

QString NxFilePath2VfsPath(NxPartition *nxp, NxFile *file);

enum fdMode { open_file, save_as, save_to_dir };
QString FileDialog(QWidget *parent, fdMode mode, const QString& defaultName = "", const QString& filters = "");

typedef struct _NxTitle {
    QString id;
    u64 u64_id;
    QString name;
    QString filename;
    QString icon_url;
    QString type;
    QString content_type;
    QString firmware;

    bool operator==(const _NxTitle &a) const {
        return u64_id == a.u64_id;
    }
    bool operator<(const _NxTitle &a) const {
        return u64_id > a.u64_id;
    }
    bool operator>(const _NxTitle &a) const {
        return u64_id > a.u64_id;
    }
} NxTitle;


class Resource : public QObject
{
     Q_OBJECT
public:
    QFile file;
    Resource(const QString &name, const QString &update_url = nullptr);
    ~Resource() { delete m_file; delete m_nm; }
    QFile* get() { return m_file; }

private:
    QFile* m_file;
    QNetworkAccessManager *m_nm;
    const QString m_name;
    const QString m_update_url;

signals:
    void update_complete();

public slots:
    void updateFromUrl();
};


class NxTitleDB : public QObject
{
     Q_OBJECT
public:
    NxTitleDB(const QString &json_file, const QString &update_url = nullptr, int expiration_delay = 86400);
    ~NxTitleDB();
    NxTitle* findTitleByID(QString id);
    NxTitle* findTitleByID(u64 id);

protected:
    std::mutex _m_titles_mutex;
    QVector<NxTitle> m_titles;
    Resource* resource;
    QString json_file;
    QString update_url;
    int db_expiration_delay; // default: 24h
    void checkUpdate(int latest_timestamp);

signals:
    void update_signal();

public slots:
    virtual void populate_titles();



};


class NxNcaDB : NxTitleDB
{
    Q_OBJECT
public:
    NxNcaDB(const QString &json_file_, const QString &update_url_ = nullptr, int expiration_delay = 86400) :
        NxTitleDB(json_file_, update_url_, expiration_delay) {}
    NxTitle* findTitleByFileName(QString filename);
    QVector<NxTitle*> findTitlesById(QString id);

public slots:
    void populate_titles() override;

public :
    bool is_Empty() { return m_titles.isEmpty(); }
};

typedef struct { u32 _u32; u16 _u16[6]; } uid;
typedef struct {
    u8 user_id[0x10];
    uid user_id_save;
    u64 last_edit_timestamp;
    char nickname[0x20];
    u8 _0x48[0x4];
    u8 icon_id[0x4];
    u8 _0x50[0x78];
} profile_entry;

typedef struct {
    QString nickname;
    u8 user_id[0x10];
    QString user_id_str;
    QImage *avatar_img = nullptr;

} NxUserIdEntry;

class NxUserDB
{
public :
    NxUserDB(NxStorage *nxStorage);
    ~NxUserDB();
    NxUserIdEntry getUserByUserId(u8 *user_id);
private:
    QVector<NxUserIdEntry> m_users;
};

class VfsMountRunner : public QObject
{
     Q_OBJECT
public:
    VfsMountRunner(NxPartition* partition) : m_partition(partition) { updateSettings(); }
    void updateSettings();
    void run(const QString &YesNoQuestion = nullptr);
    QString mounPoint() { return QString(m_mount_point).toUpper().append(":"); }

private:
    NxPartition *m_partition;
    wchar_t m_mount_point = '\0';
    bool m_readOnly = true;

signals:
    void error(int, QString);
    void mounted();
};
QString rtrimmed(const QString& str);
#endif // QUTILS_H
