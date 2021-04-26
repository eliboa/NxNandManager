#ifndef EXPLORER_H
#define EXPLORER_H

#include <QDialog>
#include "../NxStorage.h"
#include <QObject>


namespace Ui {
class Explorer;
}

class Explorer : public QDialog
{
    Q_OBJECT

public:
    explicit Explorer(QWidget *parent, NxPartition *partition);
    ~Explorer();

private:
    Ui::Explorer *ui;
};

#endif // EXPLORER_H
