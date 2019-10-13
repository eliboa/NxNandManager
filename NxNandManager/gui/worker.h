#ifndef WORKER_H
#define WORKER_H

#define LIST_STORAGE    100
#define NEW_STORAGE     101
#define DUMP			102
#define RESTORE			103
#define DUMP_PART		104
#define RESTORE_PART    105

#include <QMainWindow>
#include <QThread>
#include <QFile>
#include <QMessageBox>
#include "../NxStorage.h"

class NxPartition;
class Worker : public QThread {
	Q_OBJECT
public:
    explicit Worker(QDialog *pParent);
	explicit Worker(QMainWindow *pParent, QString filename);
    explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxPartition* pNxInPart, QString filename, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxPartition* pNxInPart, NxStorage* pNxOutput, int crypto_mode);
    ~Worker();

protected:
    void dumpPartition(NxPartition* partition, QString file);
    void dumpStorage(NxStorage* storage, QString file);
    void restorePartition(NxPartition* out_partition, NxStorage* in_storage);
    void restoreStorage(NxStorage* out_storage, NxStorage* in_storage);
	void cancel();
    void connect_slots();

public slots:
	void run();
	void terminate();

signals:
    void finished();
	void finished(NxStorage*);
    void listCallback(QString);
	void error(int, QString s = nullptr);
    void sendProgress(int mode, QString storage_name, u64 *bytesCount, u64 *bytesTotal);
	void sendMD5begin();
	void sendCancel();

private:
	QMainWindow *parent;
	int work;
    int m_crypto_mode;
	bool bCanceled = false;
	QString file;
	NxStorage *storage;
	NxStorage *nxInput;
	NxStorage *nxOutput;
    NxPartition *nxInPart;
	u64 *bytesWritten;
	QString partition;
	bool bypassMD5;
	HANDLE hDisk, hDiskOut;

public:
    timepoint_t begin_time;
};

#endif // WORKER_H
