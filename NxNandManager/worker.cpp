#include "worker.h"

Worker::Worker(QMainWindow *pParent, QString filename)
{
	work = NEW_STORAGE;
	parent = pParent;
	file = filename;
	connect(this, SIGNAL(finished(NxStorage*)), parent, SLOT(inputSet(NxStorage*)));

}

Worker::Worker(QMainWindow *pParent, NxStorage* pNxInput, NxStorage* pNxOutput, int mode, bool bbypassMD5, const char* partition_name)
{
	work = mode;
	parent = pParent;
	nxInput = pNxInput;
	nxOutput = pNxOutput;
	bypassMD5 = bbypassMD5;
	if(nullptr != partition_name) partition = QString(partition_name);

	connect(this, SIGNAL(error(int, QString)), parent, SLOT(error(int, QString)));
	connect(this, SIGNAL(sendProgress(int, u64*)), parent, SLOT(updateProgress(int, u64*)));
	connect(this, SIGNAL(sendMD5begin()), parent, SLOT(MD5begin()));
}

Worker::~Worker()
{
}

void Worker::run()
{
	if (work == NEW_STORAGE)
	{
		storage = new NxStorage(file.toUtf8().constData());
		emit finished(storage);
	} else {
		dumpStorage(work);
	}

}

void Worker::dumpStorage(int mode)
{
	u64 bytesToRead = nxInput->size, readAmount = 0, writeAmount = 0;
	BOOL bSuccess;
	int rc;

	// Crypto
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0, hHash_out = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	std::string md5hash, md5hashOut;
	DWORD cbHash = MD5LEN;
	BYTE rgbHash[MD5LEN];

	if (mode == DUMP && !bypassMD5)
	{
		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			emit error(ERR_CRYPTO_MD5);
			return;
		}

		// Create the hash
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			emit error(ERR_CRYPTO_MD5);
			return;
		}
	}


	int percent = 0;
	// Dump
	if (mode == DUMP)
	{
		while (rc = nxInput->DumpToStorage(nxOutput, partition.toUtf8().constData(), &readAmount, &writeAmount, &bytesToRead, !bypassMD5 ? &hHash : NULL))
		{
			if (rc < 0)
				break;

			if (bCanceled)
			{
				nxInput->ClearHandles();
				return;
			}

			int percent2 = (u64)writeAmount * 100 / (u64)bytesToRead;
			if (percent2 > percent)
			{
				percent = percent2;
				emit sendProgress(percent, &writeAmount);
			}
		}
	}
	// restore
	else {
		while (rc = nxOutput->RestoreFromStorage(nxInput, partition.toUtf8().constData(), &readAmount, &writeAmount, &bytesToRead))
		{
			if (rc < 0)
				break;

			if (bCanceled)
			{
				nxInput->ClearHandles();
				return;
			}

			int percent2 = (u64)writeAmount * 100 / (u64)bytesToRead;
			if (percent2 > percent)
			{
				percent = percent2;
				emit sendProgress(percent, &writeAmount);
			}
		}
	}

	if (rc != NO_MORE_BYTES_TO_COPY) {
		emit error(rc);
		return;
	}
	else if (writeAmount != bytesToRead)
	{
		char buff[256];
		sprintf_s(buff, 256, "ERROR : %I64d bytes to read but %I64d bytes written", bytesToRead, writeAmount);
		emit error(0, QString(buff));
		return;
	}
	if (mode == DUMP) nxInput->ClearHandles();
	else nxOutput->ClearHandles();

	if (mode == DUMP && !bypassMD5)
	{
		md5hash = BuildChecksum(hHash);
		// Compute then compare output checksums
		nxOutput->InitStorage();
		emit sendMD5begin();
		int p_percent = 0;
		u64 readAmout = 0;
		while (true)
		{
			int percent = nxOutput->GetMD5Hash(&hHash_out, &readAmout);
			if (percent < 0)
				break;

			if (percent > p_percent)
			{
				emit sendProgress(percent, 0);
				p_percent = percent;
			}

		}
		md5hashOut = BuildChecksum(hHash_out);
		if (md5hash != md5hashOut)
		{
			emit error(ERR_MD5_COMPARE);
		}

	}

	sleep(1000);
	return;
}

void Worker::terminate()
{
	bCanceled = true;
}
