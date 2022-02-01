#include "hactoolnet.h"
#include "qutils.h"
#include <QTextStream>
#include <QDir>
#include <QRegularExpression>

HacToolNet::HacToolNet()
{

}
void HacToolNet::process_exit(QProcess &process, std::function<void()> functor, ProcessFlags flags)
{
    if (flags.testFlag(ConsoleWrite))
    {
        process.setProcessChannelMode(QProcess::MergedChannels);
        connect(&process, &QProcess::readyReadStandardOutput, [&]() {
            QString out_message, line, progress_line;
            auto output = process.readAllStandardOutput();
            QTextStream stream(output), out_stream(&out_message);
            stream.setAutoDetectUnicode(true);
            while (stream.readLineInto(&line)) {
                if (line.startsWith('[')) {
                    // Catch progress line
                    QRegularExpression re("(\\d+)/(\\d+) (.+),\\d+ %");
                    auto match = re.match(line);
                    if (match.hasMatch()) {
                        ProgressInfo pi;
                        pi.isSubProgressInfo = true;
                        pi.bytesCount = match.captured(1).toULongLong();
                        pi.bytesTotal = match.captured(2).toULongLong();
                        pi.percent = match.captured(3).toInt();
                        auto m = match.captured(0);
                        emit updateProgress(pi);
                        continue;
                    }
                }
                else if (!line.contains('#') && !line.contains(0x8)
                         && !line.contains("Failed to match key")
                         && !line.contains("Invalid rights ID"))
                {
                    if (line.startsWith('\r') || line.startsWith('\n'))
                        line = line.trimmed();
                    else line = rtrimmed(line);
                    if (!line.isEmpty())
                        out_stream << line + "\n";

                    if (line.startsWith("ERROR:"))
                        last_error = "Hactoolnet error: " + line.right(line.length() - 7);
                }
            }
            if (!out_message.isEmpty())
                emit consoleWrite(out_message);

            if (isdebug && output.length())
                dbg_wprintf(L"%ls", QString(output).toStdWString().c_str());
        });
    }
    connect(&process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [&](int exitCode, QProcess::ExitStatus exitStatus){
        dbg_wprintf(L"HacToolNet process exit (%d), cmd: %s\n", exitCode, process.arguments().join(" ").toStdWString().c_str());
        if (exitCode != SUCCESS || exitStatus != QProcess::NormalExit) {
            if (last_error.isEmpty())
                last_error = QString("Hactoolnet error: %1").arg(exitCode);
            auto output = process.readAllStandardError();
            QTextStream stream(output);
            QString line;
            while (stream.readLineInto(&line)) if (line.startsWith("ERROR:")) {
                last_error = "Hactoolnet error: " + line.right(line.length() - 7);
                break;
            }
            if (flags.testFlag(EmitErrorSignal))
                emit error(last_error);

            if (isdebug && output.length())
                dbg_wprintf(L"--- Hactoolnet.exe output ---\n%ls\n", QString(output).toStdWString().c_str());
        }
        else if (functor)
            functor();
    });
}

QStringList HacToolNet::listFiles(const QString &file, const Type type)
{
    last_error.clear();

    QStringList files, args;
    if (!this->exists() || !QFile(file).exists())
        return files;

    args << file;
    if (type == Nca)
        args << "--listromfs" << "-t" << "nca";
    else if (type == Save)
        args << "--listfiles" << "-t" << "save";
    else return files;
    args << "-k" << "keys.dat" << "--titlekeys" << "keys.dat";

    if (isdebug) {
        QString cmd;
        for (auto arg : args) cmd.append(" " + arg);
        dbg_wprintf(L"Hactool cmd :%ls\n", cmd.toStdWString().c_str());
    }

    QProcess process(this);
    auto functor = [&](){
        QTextStream stream(process.readAllStandardOutput());
        QString line;
        while (stream.readLineInto(&line)) if (line.startsWith("/"))
                files << line;
    };
    process_exit(process, functor, EmitErrorSignal);
    process.start(hactool_exe, args);
    process.waitForFinished(-1); // Synchronous
    return files;
}

bool HacToolNet::extractFiles(const QString &file, const Type type, const QString &output_dir)
{
    last_error.clear();
    auto exit = [&](const QString err = "") {
        if (!err.isEmpty()) { last_error = err; return false; }
        return true;
    };

    if (!this->exists() || !QFile(file).exists())
        return exit("Unable to open " + file);

    QStringList args;
    args << file;
    if (type == Nca)
        args << "--listromfs" << "-t" << "nca";
    else if (type == Save)
        args << "--listfiles" << "-t" << "save";
    else return false;
    args << "-k" << "keys.dat" << "--titlekeys" << "keys.dat";

    bool hasFiles = false;
    QProcess l_process(this);
    process_exit(l_process, [&](){
        QTextStream stream(l_process.readAllStandardOutput());
        QString line;
        while (stream.readLineInto(&line)) if (line.startsWith("/")) {
            hasFiles = true;
            break;
        }
    }, NoProcessFlag);
    l_process.start(hactool_exe, args);
    l_process.waitForFinished(-1); // Synchronous
    if (!hasFiles)
        return exit("There's nothing to extract from " + file);

    if (!QDir(output_dir).exists() && !QDir().mkpath(output_dir))
        return exit("Failed to create output dir " + output_dir);

    args.clear();
    args << file;
    if (type == Nca)
        args << "--romfsdir" << output_dir << "-t" << "nca";
    else if (type == Save)
        args << "--outdir" << output_dir << "-t" << "save";
    args << "-k" << "keys.dat" << "--titlekeys" << "keys.dat";

    if (!EnsureOutputDir(output_dir))
        return exit(QString("Failed to create dir %1").arg(output_dir));

    QProcess process(this);
    process_exit(process, nullptr, ConsoleWrite);
    process.start(hactool_exe, args);
    process.waitForFinished(-1); // Synchronous

    return process.exitCode() == SUCCESS ? true : exit(last_error.isEmpty() ? "Failed to extract files from " + file
                                                                            : last_error + " (" + file + ")");
}

bool HacToolNet::plaintextNCA(const QString &input_filepath, const QString &output_filepath)
{
    last_error.clear();
    auto exit = [&](const QString err = "") {
        if (!err.isEmpty()) { last_error = err; return false; }
        return true;
    };

    if (!this->exists() || !QFile(input_filepath).exists())
        return exit("Unable to open " + input_filepath);;

    QStringList args;
    args << input_filepath << "--plaintext" << output_filepath  << "-t" << "nca";
    args << "-k" << "keys.dat" << "--titlekeys" << "keys.dat";

    QProcess process(this);
    process_exit(process, nullptr, ConsoleWrite);
    process.start(hactool_exe, args);
    process.waitForFinished(-1); // Synchronous    
    return process.exitCode() == SUCCESS ? true : exit(last_error.isEmpty() ? "Failed to extract " + input_filepath
                                                                            : last_error + " (" + input_filepath + ")");
}
