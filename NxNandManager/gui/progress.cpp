#include "progress.h"
#include "ui_progress.h"

Progress::Progress(QWidget *parent, NxStorage *workingStorage) :
    QDialog(parent),
    ui(new Ui::Progress),
    m_parent(parent), m_workingStorage(workingStorage)
{
    ui->setupUi(this);
    this->setVisible(false);
    this->setWindowFlag(Qt::Popup);
    //this->setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    this->setWindowTitle("Progress");

    ui->progressBar1->setFormat("");
    ui->progressBar2->setFormat("");
    setProgressBarStyle(ui->progressBar1, "CFCFCF");
    setProgressBarStyle(ui->progressBar2, "CFCFCF");

    TaskBarButton = new QWinTaskbarButton(this);
    TaskBarButton->setWindow(windowHandle());
    TaskBarProgress = TaskBarButton->progress();



    m_buf_time = std::chrono::system_clock::now();
    // Init timer
    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timer1000()));
    timer->start(1000);
}

Progress::~Progress()
{
    delete ui;
}

void Progress::timer1000()
{
    auto time = std::chrono::system_clock::now();
    if(m_isRunning)
    {
        QString label;
        //elapsed time

        std::chrono::duration<double> elapsed_seconds = time - m_begin_time;
        label.append("Elapsed time: " + QString(GetReadableElapsedTime(elapsed_seconds).c_str()));

        //Remaining time
        if(m_remaining_time >= time)
        {
            std::chrono::duration<double> remaining_seconds = m_remaining_time - time;
            label.append(" / Remaining: " + QString(GetReadableElapsedTime(remaining_seconds).c_str()));
        }
        ui->elapsed_time_label->setText(label);
    }

    // Transfer rate
    if(m_isRunning && m_cur_pi.mode != MD5_HASH)
    {
        std::chrono::duration<double> elapsed_seconds = time - m_buf_time;
        m_bytesProcessedPerSecond = (m_cur_pi.bytesCount - m_bytesCountBuffer) / elapsed_seconds.count();
        m_bytesCountBuffer = m_cur_pi.bytesCount;
        m_buf_time = time;

        if (m_bytesProcessedPerSecond < 0x200)
            m_bytesProcessedPerSecond = 0;

        if (m_l_bytesProcessedPerSecond.size() == 6)
            m_l_bytesProcessedPerSecond.erase(m_l_bytesProcessedPerSecond.begin());
        m_l_bytesProcessedPerSecond.push_back(m_bytesProcessedPerSecond);

        m_bytesProcessedPerSecond = 0;
        for (auto& bytes : m_l_bytesProcessedPerSecond)
            m_bytesProcessedPerSecond += bytes;

        m_bytesProcessedPerSecond = m_bytesProcessedPerSecond / m_l_bytesProcessedPerSecond.size();

        ui->transfertRateLbl->setText("Transfer rate: " + (m_bytesProcessedPerSecond ? QString::fromStdString(GetReadableSize(m_bytesProcessedPerSecond)) : QString("0b")) + "/s");

    }
    else
    {
        ui->transfertRateLbl->setText("");
    }
}

void Progress::updateProgress(const ProgressInfo pi)
{
    m_isRunning = true;
    if (!this->isVisible())
    {
        this->setVisible(true);
        this->setFocus();
    }
    auto time = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = time - pi.begin_time;
    QString label;

    QProgressBar* progressBar;
    if(pi.isSubProgressInfo)
        progressBar = ui->progressBar2;
    else
    {
        if (is_in(pi.mode, {MD5_HASH}))
        {
            if (pi.bytesCount == pi.bytesTotal)
            {
                progressBar = ui->progressBar1;
                setProgressBarStyle(progressBar, "0FB3FF");
            }
            else progressBar = ui->progressBar2;
        }
        else
            progressBar = ui->progressBar1;
    }

    if (!pi.bytesCount)
    {
        progressBar->setValue(0);
        QString color;
        if(pi.mode == MD5_HASH) color = "0FB3FF";
        else if (pi.mode == ZIP) color = "FF6A00";
        else color = nullptr;
        setProgressBarStyle(progressBar, color);

        // Initialize Main Progress Bar
        if(!pi.isSubProgressInfo)
        {
            TaskBarProgress->setValue(0);

            // First init
            if (not_in(pi.mode, {MD5_HASH, ZIP}))
            {
                m_begin_time = pi.begin_time;
            }
        }
    }

    if (pi.bytesCount == pi.bytesTotal)
    {
        progressBar->setValue(100);
        label.append(pi.storage_name);
        if (pi.mode == MD5_HASH) label.append(" dumped & verified");
        else if (pi.mode == RESTORE) label.append(" restored");
        else if (pi.mode == RESIZE) label.append(" resized");
        else if (pi.mode == CREATE) label.append(" created");
        else if (pi.mode == ZIP) label.append(pi.isSubProgressInfo ? " zipped" : " archived");
        else if (pi.mode == FORMAT) label.append(" formatted");
        else label.append(" dumped");
        label.append(" (").append(GetReadableSize(pi.bytesTotal).c_str()).append(")");

        if (!pi.isSubProgressInfo)
        {
            TaskBarProgress->setValue(100);
            setProgressBarStyle(ui->progressBar2, "CFCFCF");
            ui->progressBar2->setValue(100);
            ui->progressBar2->setFormat("");
        }

    }
    else
    {                
        int percent = pi.bytesCount * 100 / pi.bytesTotal;
        progressBar->setValue(percent);        
        if (pi.mode == MD5_HASH) label.append("Computing hash for ");
        else if (pi.mode == RESTORE) label.append("Restoring to ");
        else if (pi.mode == RESIZE) label.append("Resizing ");
        else if (pi.mode == CREATE) label.append("Creating ");
        else if (pi.mode == FORMAT) label.append("Formatting ");
        else if (pi.mode == ZIP) label.append(pi.isSubProgressInfo ? "Archiving " : "Creating archive ");
        else label.append("Copying ");
        label.append(pi.storage_name);
        label.append("... ").append(GetReadableSize(pi.bytesCount).c_str());
        label.append(" /").append(GetReadableSize(pi.bytesTotal).c_str());
        label.append(" (").append(QString::number(percent)).append("%)");

        if(!pi.isSubProgressInfo) {
            std::chrono::duration<double> remaining_seconds = (elapsed_seconds / pi.bytesCount) * (pi.bytesTotal - pi.bytesCount);
            m_remaining_time = time + remaining_seconds;
            TaskBarProgress->setValue(percent);
        }
    }
    progressBar->setFormat(label);

    // Save current ProgressInfo
    if(!pi.isSubProgressInfo)
        m_cur_pi = pi;
}

void Progress::setProgressBarStyle(QProgressBar* progressBar, QString color)
{
    if(nullptr == color) color = "06B025";
    QString st = QString (
                "QProgressBar::chunk {"
                "background-color: #" + color + ";"
                                                "}");
    st.append("QProgressBar {"
              "border: 1px solid grey;"
              "border-radius: 2px;"
              "text-align: center;"
              "background: #eeeeee;"
              "}");
    progressBar->setStyleSheet(st);
}

void Progress::reject()
{
    if (m_isRunning)
    {
        if(QMessageBox::question(this, "Warning", "Work is in progress. Do you really want to quit ?\nConfirm to abort, cancel to keep current work running.", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
        {
            if (nullptr != m_workingStorage)
            {
                m_workingStorage->stopWork = true;
                return;
            }
            QDialog::reject();
        }
        return;
    }

    QDialog::done(result());
}

void Progress::error(int err, QString label)
{
    this->setResult(err);
    m_isRunning = false;
    if(label != nullptr)
    {
        QMessageBox::critical(nullptr,"Error", label);
        this->reject();
        return;
    }

    for (int i=0; i < (int)array_countof(ErrorLabelArr); i++)
    {
        if(ErrorLabelArr[i].error == err) {
            QMessageBox::critical(nullptr,"Error", QString(ErrorLabelArr[i].label));
            this->reject();
            return;
        }
    }
    QMessageBox::critical(nullptr,"Error","Error " + QString::number(err));
}
void Progress::on_WorkFinished()
{
    m_isRunning = false;
    setResult(QDialog::Accepted);
}

void Progress::on_pushButton_clicked()
{
    reject();
}
