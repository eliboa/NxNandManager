#ifndef DEBUG_H
#define DEBUG_H

#include <QDialog>


namespace Ui {
class Debug;
}

class Debug : public QDialog
{
    Q_OBJECT

public:
    explicit Debug(QWidget *parent = nullptr);
    ~Debug();

    void writeDebugLine(std::string line);

private slots:
    void on_Debug_finished(int result);

private:
    Ui::Debug *ui;
};

static Debug* debug_instance = nullptr;
void writeDebugLine(std::string line);
#endif // DEBUG_H
