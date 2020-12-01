#include "explorer.h"
#include "ui_explorer.h"

Explorer::Explorer(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Explorer)
{
    ui->setupUi(this);
}

Explorer::~Explorer()
{
    delete ui;
}
