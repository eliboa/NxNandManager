#ifndef PROPERTIES_H
#define PROPERTIES_H

#include <QMainWindow>
#include <QObject>
#include <QWidget>

class Properties : public QObject
{
    Q_OBJECT
public:
    explicit Properties(QObject *parent = nullptr);

signals:

public slots:
};

#endif // PROPERTIES_H
