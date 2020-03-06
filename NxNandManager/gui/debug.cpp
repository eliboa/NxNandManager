#include "debug.h"
#include "ui_debug.h"

Debug::Debug(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Debug)
{
    ui->setupUi(this);
    debug_instance = this;
    qRegisterMetaType<std::string>("std::string");
    connect(this, SIGNAL(log(std::string)), this, SLOT(writeDebugLine(std::string)));
}

Debug::~Debug()
{
    delete ui;
    if(nullptr != debug_instance)
        debug_instance = nullptr;
}

void Debug::writeDebugLine(std::string line)
{
    QString sDate = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    ui->console->appendPlainText(sDate + " : " + QString::fromStdString(line).simplified());
    QTextCursor cursor = ui->console->textCursor();
    cursor.movePosition(QTextCursor::End);
    ui->console->setTextCursor(cursor);
}

void writeDebugLine(std::string line)
{
    if (nullptr == debug_instance)
        return;
    //debug_instance->writeDebugLine(line);
    debug_instance->emit log(line);
}

void Debug::on_Debug_finished(int result)
{
    if(nullptr != debug_instance)
        debug_instance = nullptr;
}
