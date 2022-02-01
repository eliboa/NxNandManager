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
    enum ProcessFlag {
        NoProcessFlag   = 0x01,
        EmitErrorSignal = 0x02,
        ConsoleWrite    = 0x04,
    };
    Q_DECLARE_FLAGS(ProcessFlags, ProcessFlag)

private:
    // Private objects
    QString last_error;
    const QString hactool_exe = "res/hactoolnet.exe";

    // Private functions
    void process_exit(QProcess &process, std::function<void()> functor, ProcessFlags eb);

public:
    // Getters
    QString lastError() { return last_error; }
    bool exists() { return QFile(hactool_exe).exists(); }
    const QString pgm_path() { return hactool_exe; }

    // Public functions
    QStringList listFiles(const QString &file, const Type type);
    bool extractFiles(const QString &file, const Type type, const QString &output_dir);
    bool plaintextNCA(const QString &input_filepath, const QString &output_filepath);

signals:
    void error(const QString);
    void consoleWrite(const QString);
    void updateProgress(const ProgressInfo);

public slots:
};
Q_DECLARE_OPERATORS_FOR_FLAGS(HacToolNet::ProcessFlags);

#endif // HACTOOLNET_H
