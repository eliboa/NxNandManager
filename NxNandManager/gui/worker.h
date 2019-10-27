/*
 * Copyright (c) 2019 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WORKER_H
#define WORKER_H

#define LIST_STORAGE    100
#define NEW_STORAGE     101
#define DUMP			102
//#define RESTORE			103
#define DUMP_PART		104
#define RESTORE_PART    105
#define RESIZE          106

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
    explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, bool dump_rawnand, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, int new_size, bool format);
    explicit Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxPartition* pNxInPart, QString filename, int crypto_mode);
    explicit Worker(QMainWindow *pParent, NxPartition* pNxInPart, NxStorage* pNxOutput, int crypto_mode);
    ~Worker();

protected:
    void dumpPartition(NxPartition* partition, QString file);
    void dumpStorage(NxStorage* storage, QString file);
    void restorePartition(NxPartition* out_partition, NxStorage* in_storage);
    void restoreStorage(NxStorage* out_storage, NxStorage* in_storage);
    void resizeUser(NxStorage* storage, QString file);
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
    bool m_format;
    int m_new_size;
    bool m_dump_rawnand;

public:
    timepoint_t begin_time;
};

#endif // WORKER_H
