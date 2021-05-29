#include "loading_widget.h"
#include "ui_loading_widget.h"
#include <QDateTime>
#include <QMovie>
#include <QTimer>

loadingWidget::loadingWidget(const QString init_message, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::loadingWidget)
{
    ui->setupUi(this);

    this->setWindowFlags(Qt::Tool | Qt::FramelessWindowHint);
    this->setAttribute(Qt::WA_TranslucentBackground);

    QMovie *movie = new QMovie(":/images/loader_bgFFFFFF.gif");
    ui->loadingLbl->setMovie(movie);
    ui->loadingLbl->show();
    movie->start();

    if (init_message.size())
        setLabel(init_message);

    m_latest_activity = QDateTime::currentSecsSinceEpoch();
    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(checkActivity()));
    timer->start(1000); // Every second
}

void loadingWidget::init_ProgressWidget(const QString init_message, int timeout_s)
{
    if (timeout_s)
        setTimeOut(timeout_s);

    if (init_message.size())
        setLabel(init_message);
    else
    {
        setLastActivity();
        show();
    }
}

loadingWidget::~loadingWidget()
{
    delete ui;
}

void loadingWidget::checkActivity()
{
    if (!isVisible())
        return;

    qint64 now = QDateTime::currentSecsSinceEpoch();
    if (now > m_latest_activity + m_timeout_s)
        hide();
}

void loadingWidget::setLastActivity()
{
    m_latest_activity = QDateTime::currentSecsSinceEpoch();
}

void loadingWidget::setLabel(const QString label)
{
    QString s_label = label.size() > 40 ? "..." + label.mid(label.size() - 37, 37) : label;
    ui->label->setText(s_label);
    setLastActivity();
    if (!isVisible())
        show();
}

void loadingWidget::closeEvent(QCloseEvent *e)
{
    hide();
    QDialog::closeEvent(e);
}
