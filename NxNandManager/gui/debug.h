#ifndef DEBUG_H
#define DEBUG_H

#include <QDialog>
#include <QDateTime>

namespace Ui {
class Debug;
}

class Debug : public QDialog
{
    Q_OBJECT

public:
    explicit Debug(QWidget *parent, bool isdebug_old_value);
    ~Debug();

private slots:
    void on_Debug_finished(int result);

public slots:
    void writeDebugLine(std::string line);

signals:
    void log(std::string line);

private:
    Ui::Debug *ui;
    bool m_isdebug_old_value;

public:
    bool isOpen = true;
};

static Debug* debug_instance = nullptr;
void writeDebugLine(std::string line);
#endif // DEBUG_H
