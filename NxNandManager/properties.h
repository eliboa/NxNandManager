#ifndef PROPERTIES_H
#define PROPERTIES_H

#include <QMainWindow>
#include <QObject>
#include <QDialog>
#include <QtWidgets>
#include "utils.h"
#include "NxStorage.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;

namespace Ui {
    class DialogProperties;
}

class Properties : public QDialog
{
    Q_OBJECT
public:
    explicit Properties(NxStorage *input);
    ~Properties();
    Ui::DialogProperties *ui;

private:
    NxStorage *input;

signals:

public slots:
};

#endif // PROPERTIES_H
