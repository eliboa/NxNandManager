#ifndef HACTOOLNET_H
#define HACTOOLNET_H

#include <QObject>
#include <QFile>
#include "../NxFile.h"
#include <QProcess>

class HacToolNet : public QObject
{
    Q_OBJECT
public:
    explicit HacToolNet();
    enum Type { Save, Nca };
    enum ErrorBehaviour { EmitSignal, SilentError };

private:
    QString last_error;
    const QString hactool_exe = "res/hactoolnet.exe";
    void process_exit(QProcess &process, std::function<void()> functor, ErrorBehaviour eb = EmitSignal);

public:
    QString lastError() { return last_error; }
    bool exists() { return QFile(hactool_exe).exists(); }
    QStringList listFiles(const QString &file, const Type type);
    bool extractFiles(const QString &file, const Type type, const QString &output_dir);

signals:
    void error(const QString);

public slots:
};

#endif // HACTOOLNET_H
