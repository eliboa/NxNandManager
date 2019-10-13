#include "worker.h"

Worker::Worker(QDialog *pParent)
{
    work = LIST_STORAGE;
    connect(this, SIGNAL(listCallback(QString)), pParent, SLOT(list_callback(QString)));
}

Worker::Worker(QMainWindow *pParent, QString filename)
{
	work = NEW_STORAGE;
	parent = pParent;
	file = filename;
	connect(this, SIGNAL(finished(NxStorage*)), parent, SLOT(inputSet(NxStorage*)));
}

Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, QString filename, int crypto_mode)
{
    work = DUMP;
    parent = pParent;
    nxInput = pNxInput;
    file = filename;
    m_crypto_mode = crypto_mode;
    connect_slots();
}
Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int crypto_mode)
{
    work = RESTORE;
    parent = pParent;
    nxInput = pNxInput;
    nxOutput = pNxOutput;
    m_crypto_mode = crypto_mode;
    connect_slots();

}
Worker::Worker(QMainWindow *pParent, NxPartition* pNxInPart, QString filename, int crypto_mode)
{
    work = DUMP_PART;
    parent = pParent;
    nxInPart = pNxInPart;
    file = filename;
    m_crypto_mode = crypto_mode;
    connect_slots();
}
Worker::Worker(QMainWindow *pParent, NxPartition* pNxOutPart, NxStorage* pNxInput, int crypto_mode)
{
    work = RESTORE_PART;
    parent = pParent;
    nxInPart = pNxOutPart;
    nxInput = pNxInput;
    m_crypto_mode = crypto_mode;
    connect_slots();
}

Worker::~Worker()
{
}

void Worker::connect_slots()
{
    begin_time = std::chrono::system_clock::now();
    connect(this, SIGNAL(error(int, QString)), parent, SLOT(error(int, QString)));
    connect(this, SIGNAL(sendProgress(int, QString, u64*, u64*)), parent, SLOT(updateProgress(int, QString, u64*, u64*)));
    connect(this, SIGNAL(finished()), parent, SLOT(endWorkThread()));
}

void Worker::run()
{    
	if (work == NEW_STORAGE)
	{        
        storage = new NxStorage(file.toUtf8().constData());
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

void Worker::terminate()
{
    bCanceled = true;
}

void Worker::dumpPartition(NxPartition* partition, QString file)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    u64 bytesCount = 0, bytesToRead = partition->size();
    begin_time = std::chrono::system_clock::now();
    int rc = 0;

    emit sendProgress(DUMP, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
    while (!(rc = partition->dumpToFile(file.toUtf8().constData(), m_crypto_mode, &bytesCount)))
    {
        emit sendProgress(DUMP, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
    }

    if (rc != NO_MORE_BYTES_TO_COPY)
        emit error(rc);

    else if (m_crypto_mode == MD5_HASH)
    {
        emit sendProgress(DUMP, QString(partition->partitionName().c_str()), &bytesToRead, &bytesToRead);
        HCRYPTHASH in_hash = partition->nxHandle->md5Hash();
        std::string in_sum = BuildChecksum(in_hash);
        bytesCount = 0;
        NxStorage out_storage = NxStorage(file.toUtf8().constData());
        begin_time = std::chrono::system_clock::now();

        // Send progress with bytesCount=0 to init progress
        emit sendProgress(MD5_HASH, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
        while (!out_storage.nxHandle->hash(&bytesCount))
        {
            emit sendProgress(MD5_HASH, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
        }

        if (bytesCount != bytesToRead)
            emit error(rc);

        else
        {
            emit sendProgress(MD5_HASH, QString(partition->partitionName().c_str()), &bytesToRead, &bytesToRead);

            HCRYPTHASH out_hash = out_storage.nxHandle->md5Hash();
            std::string out_sum = BuildChecksum(out_hash);
            if (in_sum.compare(out_sum))
                emit error(ERR_MD5_COMPARE);
        }
    }
    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::dumpStorage(NxStorage* storage, QString file)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    u64 bytesCount = 0, bytesToRead = storage->size();
    int rc = 0;

    emit sendProgress(DUMP, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    while (!(rc = storage->dumpToFile(file.toUtf8().constData(), m_crypto_mode, &bytesCount)))
    {
        emit sendProgress(DUMP, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    }

    if (rc != NO_MORE_BYTES_TO_COPY)
        emit error(rc);

    else if (m_crypto_mode == MD5_HASH)
    {
        HCRYPTHASH in_hash = storage->nxHandle->md5Hash();
        std::string in_sum = BuildChecksum(in_hash);
        bytesCount = 0;
        NxStorage out_storage = NxStorage(file.toUtf8().constData());
        begin_time = std::chrono::system_clock::now();
        // Send progress with bytesCount=0 to init progress
        emit sendProgress(MD5_HASH, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
        while (!out_storage.nxHandle->hash(&bytesCount))
        {
            emit sendProgress(MD5_HASH, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
        }

        if (bytesCount != bytesToRead)
            emit error(rc);

        else
        {
            emit sendProgress(MD5_HASH, QString(storage->getNxTypeAsStr()), &bytesToRead, &bytesToRead);
            HCRYPTHASH out_hash = out_storage.nxHandle->md5Hash();
            std::string out_sum = BuildChecksum(out_hash);
            if (in_sum.compare(out_sum))
                emit error(ERR_MD5_COMPARE);
        }
    }
    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::restorePartition(NxPartition* partition, NxStorage* in_storage)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    u64 bytesCount = 0, bytesToRead = partition->size();
    int rc = 0;

    emit sendProgress(RESTORE, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
    while (!(rc = partition->restoreFromStorage(in_storage, m_crypto_mode, &bytesCount)))
    {
        emit sendProgress(RESTORE, QString(partition->partitionName().c_str()), &bytesCount, &bytesToRead);
    }

    if (rc != NO_MORE_BYTES_TO_COPY)
        emit error(rc);

    emit sendProgress(RESTORE, QString(partition->partitionName().c_str()), &bytesToRead, &bytesToRead);
    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}

void Worker::restoreStorage(NxStorage* storage, NxStorage* in_storage)
{
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    u64 bytesCount = 0, bytesToRead = storage->size();
    int rc = 0;

    emit sendProgress(RESTORE, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    while (!(rc = storage->restoreFromStorage(in_storage, m_crypto_mode, &bytesCount)))
    {
        emit sendProgress(RESTORE, QString(storage->getNxTypeAsStr()), &bytesCount, &bytesToRead);
    }

    if (rc != NO_MORE_BYTES_TO_COPY)
        emit error(rc);

    emit sendProgress(RESTORE, QString(storage->getNxTypeAsStr()), &bytesToRead, &bytesToRead);
    SetThreadExecutionState(ES_CONTINUOUS);
    sleep(1);
    emit finished();
}
