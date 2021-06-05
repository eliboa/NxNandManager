#include "hactoolnet.h"
#include <QTextStream>
#include <QDir>

HacToolNet::HacToolNet()
{

}
void HacToolNet::process_exit(QProcess &process, std::function<void()> functor, ErrorBehaviour eb)
{
    connect(&process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [&](int exitCode, QProcess::ExitStatus exitStatus){
        if (exitCode != SUCCESS || exitStatus != QProcess::NormalExit) {
            auto error_string = QString("Hactoolnet error: %1").arg(exitCode);
            QTextStream stream(process.readAllStandardError());
            QString line;
            while (stream.readLineInto(&line)) if (line.startsWith("ERROR:"))
                error_string = "Hactoolnet error: " + line.right(line.length() - 7);
            last_error = error_string;
            if (eb == EmitSignal) emit error(error_string);
        }
        else if (functor) functor();
    });
}

QStringList HacToolNet::listFiles(const QString &file, const Type type)
{
    QStringList files, args;
    if (!this->exists() || !QFile(file).exists())
        return files;

    args << file;
    if (type == Nca)
        args << "--listromfs" << "-t" << "nca";
    else if (type == Save)
        args << "--listfiles" << "-t" << "save";
    else return files;
    args << "-k" << "keys.dat";

    if (isdebug) {
        QString cmd;
        for (auto arg : args) cmd.append(" " + arg);
        dbg_wprintf(L"Hactool cmd :%ls\n", cmd.toStdWString().c_str());
    }

    QProcess process(this);
    process_exit(process, [&](){
        QTextStream stream(process.readAllStandardOutput());
        QString line;
        while (stream.readLineInto(&line)) if (line.startsWith("/"))
                files << line;
    });
    process.start(hactool_exe, args);
    process.waitForFinished(-1); // Synchronous
    return files;
}

bool HacToolNet::extractFiles(const QString &file, const Type type, const QString &output_dir)
{
    last_error.clear();

    if (!this->exists() || !QFile(file).exists())
        return false;

    if (!QDir(output_dir).exists() && !QDir().mkpath(output_dir))
        return false;

    QStringList args;
    args << file;
    if (type == Nca)
        args << "--romfsdir" << output_dir << "-t" << "nca";
    else if (type == Save)
        args << "--outdir" << output_dir << "-t" << "save";
    else return false;
    args << "-k" << "keys.dat";

    QProcess process(this);
    process_exit(process, nullptr, SilentError);
    process.start(hactool_exe, args);
    process.waitForFinished(-1); // Synchronous
    return process.exitCode() == SUCCESS;
}
