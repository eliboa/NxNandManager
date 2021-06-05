#ifndef EXPLORER_H
#define EXPLORER_H

#include <QDialog>
#include "../NxStorage.h"
#include <QObject>
#include <QQueue>
#include <QtNetwork>
#include "loading_widget.h"
#include <QStatusBar>
#include <QEvent>
#include <QStatusTipEvent>
#include "qutils.h"
#include "../NxSave.h"
#include <QAbstractItemModel>
#include "hactoolnet.h"

namespace Ui {
class Explorer;
}

typedef struct {
    QString absolute_path;
    QString filename;
    u64  	fsize;			/* File size */
    WORD	fdate;			/* Modified date */
    WORD	ftime;			/* Modified time */
    BYTE	fattrib;		/* File attribute */
    bool    isNCA;
    bool    isSAVE;
    QString title_id;
    QString user_id;
    QString title_name;
    QString type;
    QString icon_url;
} NxFILINFO;

typedef struct _CpyElement {
    QString source;
    QString destination;
    UINT size;
    NxFile *nxFile;
} CpyElement;

enum viewTypeEnum { UserSave, SystemSave, Nca, Generic };
enum viewColumnType { FileColumn, SizeColumn, TitleColumn, TypeColumn, UserColumn, UnknownColumn };
typedef struct { u64 title_id; QString cache_file_path; QUrl icon_url; } iconQueue;

typedef struct {
    QString dir;
    QList<NxFile*> entries;
} NxFILCACHE_t;

void clearFiles(QList<NxFile*> files);
class NxFILCACHE
{
public:
    QList<NxFILCACHE_t> m_entries;
    int size() { return m_entries.count(); }
    QList<NxFile*>* at(QString dir) {
        for (int i(0); i< size(); i++) if (&m_entries[i].dir == dir)
            return &m_entries[i].entries;
        return nullptr;
    }
    void remove(QString dir) {
        for (int i(0); i< size(); i++) if (&m_entries[i].dir == dir) {
            clearFiles(m_entries.at(i).entries);
            m_entries.removeAt(i);
        }
    }
    void add(NxFILCACHE_t c) { m_entries.append(c); }
    void clear() {
        for (auto f : m_entries)
            clearFiles(f.entries);
        m_entries.clear();
    }
};

typedef struct {
    DWORD thread_id;
    QNetworkAccessManager* nm;
} nm_t;

Q_DECLARE_METATYPE(NxFile*)

typedef struct {
    NxFile* file = nullptr;
    QPixmap title_icon_m;
    QPixmap user_icon_m;
} explorerModelEntry;

class Explorer;
class ExplorerModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    ExplorerModel(Explorer* parent, viewTypeEnum viewType, QList<NxFile*> entries);
    ExplorerModel(Explorer* parent) : m_parent(parent) {}
    ~ExplorerModel() override;

private:
    // Private objects
    Explorer* m_parent;
    QVector<explorerModelEntry> m_entries;
    QNetworkAccessManager m_nm;
    struct {
        viewTypeEnum type = Generic;
        u64 total_filesize = 0;
        bool lock = false;
    } m_view;
    NxUserDB *m_userDB = nullptr;

    // Private functions
    void updateAll();
    viewColumnType getColumnType(int column) const;
    void setTitleIconsFromUrl();
    void setTitleIconFromUrl(NxFile* file);

public:
    // QAbstratTableModel redefinitions
    void setModel(viewTypeEnum viewType, QList<NxFile*> entries);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override { return m_entries.count(); }
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder ) override;

    // Getters
    NxFile* entryAt(int i) { return m_entries.at(i).file; }
    int count() { return m_entries.count(); }
    viewTypeEnum viewType() { return m_view.type; }
    int getColumnIx(viewColumnType viewType) const;

    // Setters
    void setUserDB(NxUserDB* db) { m_userDB = db; }

public slots:
    void insertEntry(NxFile*);

signals:
    void viewUpdated();
    void resizeRowToContents(int row);
    void resizeColumnsToContents();
    void setRowHeight(int row, int height);
};

typedef QQueue<CpyElement> CpyQueue;
typedef QList<NxFile*> NxFileList;

class Explorer : public QDialog
{
    Q_OBJECT
public:
    explicit Explorer(QWidget *parent, NxPartition *partition);
    ~Explorer();

private:
    // Private objects
    Ui::Explorer *ui;
    NxTitleDB *titleDB = nullptr;
    NxNcaDB *ncaDB = nullptr;
    NxUserDB *userDB = nullptr;
    QList<NxFile*> current_entries;
    NxPartition *m_partition;
    QWidget *m_parent;
    loadingWidget* m_loadingWdgt = nullptr;
    QString m_current_dir;
    viewTypeEnum m_viewtype = Generic;
    QStatusBar *m_statusBar = nullptr;
    ExplorerModel m_model;
    NxFILCACHE cache_entries;
    QFuture<void> future;
    QFutureWatcher<void> *watcher;
    QMovie *m_loading_movie;
    VfsMountRunner m_vfsRunner;
    HacToolNet m_hactool;

    // Private functions
    CpyQueue getCopyQueue(QList<NxFile*> selectedFiles, bool force_dirOutput = false);
    void getUsersInfo();
    NxUserIdEntry getUserByUserId(u8 *user_id);
    QList<NxFile*> selectedFiles();
    void loadingWdgtSetVisible(bool visible);

public:
    // Getters
    QString curDir() { return m_current_dir; }

signals:
    void sendProgress(const ProgressInfo pi);
    void workFinished();
    void closeLoadingWdgt();
    void consoleWrite(const QString);
    void updateViewSignal();
    void insertEntry(NxFile*);
    void error_signal(int, QString);
    void listFS_signal(QList<NxFile*>);
    void extractFS_signal(QList<NxFile*>);
    void loadingWdgtSetVisibleSignal(bool visible);

private slots:
    void save(QList<NxFile*> selectedFiles);
    void decrypt(QList<NxFile*> selectedFiles);
    void listFS(QList<NxFile*> selectedFiles);
    void extractFS(QList<NxFile*> selectedFiles);
    void askForVfsMount(std::function<void()> callback, const QString &question = "");
    void error(int err, QString label = nullptr);
    void updateView();
    void hactool_process(QQueue<QStringList> cmds);
    void on_currentDir_combo_currentIndexChanged(int index);
    void on_selection_changed();

    // thread safe slots
    void readDir(bool isRecursive = true);
    void do_copy(CpyQueue queue);
    void do_extractFS(CpyQueue queue);
    void do_extractFS_Hactool(CpyQueue queue);

protected:
  bool event(QEvent *e){
    if(e->type()==QEvent::StatusTip){
      QStatusTipEvent *ev = (QStatusTipEvent*)e;
      m_statusBar->showMessage(ev->tip());
      return true;
    }
    return QDialog::event(e);
  }
};
#endif // EXPLORER_H
