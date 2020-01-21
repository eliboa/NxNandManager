#ifndef PROGRESS_H
#define PROGRESS_H

#include <QDialog>
#include <QtWinExtras>
#include <QMessageBox>
#include <QProgressBar>
#include <QWinTaskbarProgress>
#include "../NxStorage.h"

namespace Ui {
class Progress;
}

class Progress : public QDialog
{
    Q_OBJECT

public:
    explicit Progress(QWidget *parent = nullptr, NxStorage *workingStorage = nullptr);
    ~Progress();

signals:


public slots:
    void updateProgress(const ProgressInfo pi);
    void error(int err, QString label);
    void on_WorkFinished();
    void timer1000();
    void reject() override;

private slots:
    void on_pushButton_clicked();

private:
    // Pointers
    Ui::Progress *ui;
    QWidget* m_parent;
    NxStorage *m_workingStorage;
    QWinTaskbarButton *TaskBarButton;
    QWinTaskbarProgress *TaskBarProgress;

    // Member variables
    bool m_workerSet = false;
    bool m_isRunning = false;
    timepoint_t m_begin_time;
    timepoint_t m_remaining_time;
    ProgressInfo m_cur_pi;
    u64 m_bytesCountBuffer = 0;
    timepoint_t m_buf_time;
    u64 m_bytesProcessedPerSecond = 0;
    std::vector<u64> m_l_bytesProcessedPerSecond;

    // Methods
    void setProgressBarStyle(QProgressBar* progressBar, QString color);
};

#endif // PROGRESS_H
