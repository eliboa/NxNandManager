#ifndef WORKER_H
#define WORKER_H

#define NEW_STORAGE     101
#define DUMP		    102
#define RESTORE		    103

#include <QMainWindow>
#include <QThread>
#include "NxStorage.h"

class Worker : public QThread {
	Q_OBJECT
public:
	explicit Worker(QMainWindow *pParent, QString filename);
	explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int mode, bool bbypassMD5, const char* partition_name = nullptr);
	~Worker();

protected:
	void dumpStorage(int mode);
	void cancel();

public slots:
	void run();
	void terminate();

signals:
	void finished(NxStorage*);
	void error(int, QString s = nullptr);
	void sendProgress(int, u64*);
	void sendMD5begin();
	void sendCancel();

private:
	QMainWindow *parent;
	int work;
	bool bCanceled = false;
	QString file;
	NxStorage *storage;
	NxStorage *nxInput;
	NxStorage *nxOutput;
	u64 *bytesWritten;
	QString partition;
	bool bypassMD5;
	HANDLE hDisk, hDiskOut;
};

#endif // WORKER_H
