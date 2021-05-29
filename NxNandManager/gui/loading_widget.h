#ifndef LOADING_WIDGET_H
#define LOADING_WIDGET_H

#include <QDialog>

namespace Ui {
class loadingWidget;
}

class loadingWidget : public QDialog
{
    Q_OBJECT

public:
    explicit loadingWidget(const QString init_message = "", QWidget *parent = nullptr);
    ~loadingWidget();

public:
    void setTimeOut(unsigned int seconds) { if (seconds) m_timeout_s = seconds; }

public slots:
    void init_ProgressWidget(const QString init_message = "", int timeout_s = 0);
    void setLabel(const QString label);
    void setLastActivity();
    void closeEvent(QCloseEvent *e) override;

private:
    Ui::loadingWidget *ui;
    qint64 m_latest_activity;
    unsigned int m_timeout_s = 60;

private slots:
    void checkActivity();

};

#endif // LOADING_WIDGET_H
