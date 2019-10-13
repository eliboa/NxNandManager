#ifndef OPENDRIVE_H
#define OPENDRIVE_H
#include <QMainWindow>
#include <QDialog>
#include <QtWidgets>
#include "worker.h"
#include "../res/utils.h"
#include "../NxStorage.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;

namespace Ui {
    class DialogOpenDrive;
}

class OpenDrive : public QDialog
{
    Q_OBJECT

public:
    explicit OpenDrive(QWidget *parent = nullptr);
    ~OpenDrive();
    Ui::DialogOpenDrive *ui;

    void ListDrives(QString drives);
    void ShowLabel();

private slots:
    void on_listWidget_itemDoubleClicked(QListWidgetItem *item);

public slots:
    void list_callback(QString);

private:


signals:
    void finished(QString);
};

class keyEnterReceiver : public QObject
{
    Q_OBJECT
protected:
    bool eventFilter(QObject* obj, QEvent* event);
};
#endif // OPENDRIVE_H
