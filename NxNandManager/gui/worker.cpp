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

#include "worker.h"
#include "gui.h"

static Worker* worker_instance;
void updateProgressWrapper(ProgressInfo* ppi)
{
 worker_instance->updateProgress(ppi);
}

Worker::Worker(QDialog *pParent)
{
    worker_instance = this;
    work = LIST_STORAGE;
    connect(this, SIGNAL(listCallback(QString)), pParent, SLOT(list_callback(QString)));
}

Worker::Worker(QMainWindow *pParent, QString filename)
{
    worker_instance = this;
	work = NEW_STORAGE;
	parent = pParent;
	file = filename;
	connect(this, SIGNAL(finished(NxStorage*)), parent, SLOT(inputSet(NxStorage*)));
}

Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, bool dump_rawnand, int crypto_mode)
{
    worker_instance = this;
    work = DUMP;
    parent = pParent;
    nxInput = pNxInput;
    file = filename;
    m_crypto_mode = crypto_mode;
    m_dump_rawnand = dump_rawnand;
    connect_slots();
}

Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, int new_size, bool format)
{
    worker_instance = this;
    work = RESIZE;
    parent = pParent;
    nxInput = pNxInput;
    file = filename;
    m_format = format;
    m_new_size = new_size;
    connect_slots();
}

Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int crypto_mode)
{
    worker_instance = this;
    work = RESTORE;
    parent = pParent;
    nxInput = pNxInput;
    nxOutput = pNxOutput;
    m_crypto_mode = crypto_mode;
    connect_slots();

}
Worker::Worker(QMainWindow *pParent, NxPartition* pNxInPart, QString filename, int crypto_mode)
{
    worker_instance = this;
    work = DUMP_PART;
    parent = pParent;
    nxInPart = pNxInPart;
    file = filename;
    m_crypto_mode = crypto_mode;
    connect_slots();
}
Worker::Worker(QMainWindow *pParent, NxPartition* pNxOutPart, NxStorage* pNxInput, int crypto_mode)
{
    worker_instance = this;
    work = RESTORE_PART;
    parent = pParent;
    nxInPart = pNxOutPart;
    nxInput = pNxInput;
    m_crypto_mode = crypto_mode;
    connect_slots();
}

Worker::~Worker()
{
    delete worker_instance;
}

void Worker::connect_slots()
{
    begin_time = std::chrono::system_clock::now();
    connect(this, SIGNAL(error(int, QString)), parent, SLOT(error(int, QString)));
    connect(this, SIGNAL(sendProgress(int, QString, u64*, u64*)), parent, SLOT(updateProgress(int, QString, u64*, u64*)));
    connect(this, SIGNAL(sendProgress(ProgressInfo*)), parent, SLOT(updateProgress(ProgressInfo*)));
    connect(this, SIGNAL(finished()), parent, SLOT(endWorkThread()));    

}

void Worker::run()
{    
	if (work == NEW_STORAGE)
	{        
        storage = new NxStorage(file.toLocal8Bit().constData());
        QFile kfile("keys.dat");
        if (kfile.exists())
            storage->setKeys("keys.dat");

		emit finished(storage);
    }
    else switch (work) {
        case LIST_STORAGE : {
            QString drives = QString(ListPhysicalDrives().c_str());
            emit listCallback(drives);
            break;
        }
        case DUMP :
            dumpStorage(nxInput, file);
            break;
        case RESIZE :
            resizeUser(nxInput, file);
            break;
        case DUMP_PART :
            dumpPartition(nxInPart, file);
            break;
        case RESTORE :
            restoreStorage(nxOutput, nxInput);
            break;
        case RESTORE_PART :
            restorePartition(nxInPart, nxInput);
            break;
	}
}

void Worker::updateProgress(ProgressInfo* pi)
{
    memcpy(&m_pi, pi, sizeof(ProgressInfo));
    emit sendProgress(&m_pi);
}

void Worker::dumpPartition(NxPartition* partition, QString file)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    int rc = partition->dumpToFile(file.toLocal8Bit().constData(), m_crypto_mode, updateProgressWrapper);

    if (rc != SUCCESS)
        error(rc);

    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::dumpStorage(NxStorage* storage, QString file)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);

    int rc = storage->dumpToFile(file.toLocal8Bit().constData(), m_crypto_mode, updateProgressWrapper, m_dump_rawnand);

    if (rc != SUCCESS)
        error(rc);

    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::restorePartition(NxPartition* partition, NxStorage* in_storage)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);

    int rc = partition->restoreFromStorage(in_storage, m_crypto_mode, updateProgressWrapper);

    if (rc != SUCCESS)
        error(rc);

    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::restoreStorage(NxStorage* storage, NxStorage* in_storage)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED); 

    int rc = storage->restoreFromStorage(in_storage, m_crypto_mode, updateProgressWrapper);

    if (rc != SUCCESS)
        error(rc);

    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::resizeUser(NxStorage* storage, QString file)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    u32 user_new_size = m_new_size * 0x800; // Size in sectors. 1Mb = 0x800 sectors
    NxPartition *user = storage->getNxPartition(USER);
    u32 total_lba_count = user->lbaStart() + (user_new_size / 0x1000 + user_new_size + 66);
    u64 bytesCount = 0, bytesToRead = total_lba_count * NX_BLOCKSIZE;
    int rc = 0;

    emit sendProgress(RESIZE, QString(nxInput->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    while (!(rc = storage->resizeUser(file.toLocal8Bit().constData(), user_new_size, &bytesCount, &bytesToRead, m_format)))
    {
        if (bCanceled)
        {
            SetThreadExecutionState(ES_CONTINUOUS);
            storage->clearHandles();
            return;
        }
        emit sendProgress(RESIZE, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    }

    if (rc != NO_MORE_BYTES_TO_COPY)
        emit error(rc);
    else emit sendProgress(RESIZE, QString(storage->getNxTypeAsStr()), &bytesToRead, &bytesToRead);

    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::terminate()
{
    bCanceled = true;

    if(is_in(work, {DUMP_PART, RESTORE_PART}))
        nxInPart->stopWork = true;
    else if(is_in(work, {DUMP, RESIZE}))
        nxInput->stopWork = true;
    else if(work == RESTORE)
        nxOutput->stopWork = true;
}
