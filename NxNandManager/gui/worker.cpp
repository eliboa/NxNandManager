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

void updateProgressWrapper(ProgressInfo pi)
{
 worker_instance->updateProgress(pi);
}

Worker::~Worker()
{
    delete worker_instance;
    WorkInProgress = false;
}

void Worker::run()
{
    switch (m_mode) {
    case new_storage :
    {
        connect(this, SIGNAL(finished(NxStorage*)), m_parent, SLOT(inputSet(NxStorage*)));
        m_WorkingStorage = new NxStorage(m_file.toLocal8Bit().constData());
        QFile kfile("keys.dat");
        if (kfile.exists())
            m_WorkingStorage->setKeys("keys.dat");

        emit finished(m_WorkingStorage);
        return;

    }
    case list_storage :
    {
        connect(this, SIGNAL(listCallback(QString)), m_parent, SLOT(list_callback(QString)));
        QString drives = QString(ListPhysicalDrives().c_str());
        emit listCallback(drives);
        return;
    }
    case get_disks :
    {
        qRegisterMetaType<std::vector<diskDescriptor>>("std::vector<diskDescriptor>");
        connect(this, SIGNAL(getDisks_callback(const std::vector<diskDescriptor>)), m_parent, SLOT(on_GetDisks_callback(const std::vector<diskDescriptor>)));
        std::vector<diskDescriptor> disks;
        GetDisks(&disks);
        emit getDisks_callback(disks);
        return;
    }}

    connect(this, SIGNAL(error(int, QString)), m_parent, SLOT(error(int, QString)));
    qRegisterMetaType<ProgressInfo>("ProgressInfo");
    connect(this, SIGNAL(sendProgress(const ProgressInfo)), m_parent, SLOT(updateProgress(const ProgressInfo)));
    connect(this, SIGNAL(finished()), m_parent, SLOT(on_WorkFinished()));

    int rc(SUCCESS);
    worker_instance = this;
    begin_time = std::chrono::system_clock::now();
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);

    switch (m_mode) {
    case dump :
    {
        m_outHandle = new NxHandle(m_file.toLocal8Bit().constData(), m_params.chunksize);
        rc = m_WorkingStorage->dump(m_outHandle, m_params, updateProgressWrapper);
        delete m_outHandle;
        break;
    }
    case restore :
    {
        rc = m_WorkingStorage->restore(m_inStorage, m_params, updateProgressWrapper);
        break;
    }
    case create_emunand :
    {
        if (m_params.emunand_type == rawBased)
            rc = m_WorkingStorage->createMmcEmuNand(m_file.toLocal8Bit().constData(), updateProgressWrapper, m_params.boot0_path, m_params.boot1_path);
        else {
            EmunandType i = static_cast<EmunandType>(m_params.emunand_type);
            rc = m_WorkingStorage->createFileBasedEmuNand(i, m_file.toLocal8Bit().constData(), updateProgressWrapper, m_params.boot0_path, m_params.boot1_path);
        }
        break;
    }
    case format_partition :
    {
        NxPartition *part = m_WorkingStorage->getNxPartition(m_params.partition);
        rc = part->formatPartition(updateProgressWrapper);
        break;
    }}

    if (rc != SUCCESS)
        emit error(rc);
    else
    {
        sleep(1);
        emit finished();
    }
    SetThreadExecutionState(ES_CONTINUOUS);
}

void Worker::updateProgress(ProgressInfo pi)
{    
    auto saveMainProgress = [](ProgressInfo p_pi)
    {
        buf64 = p_pi.bytesCount;
        memcpy(&s_pi, &p_pi, sizeof(ProgressInfo));
    };
    if (pi.show) emit sendProgress(pi);
    if(pi.isSubProgressInfo)
    {
        s_pi.bytesCount = buf64 + pi.bytesCount;
        if(s_pi.show) emit sendProgress(s_pi);

        if (pi.bytesCount == pi.bytesTotal) saveMainProgress(s_pi);
    }
    else if (pi.show) saveMainProgress(pi);
}

void Worker::terminate()
{
    if(nullptr != m_WorkingStorage)
        m_WorkingStorage->stopWork = true;
}

WorkerInstance::WorkerInstance(QWidget *parent, WorkerMode mode, params_t *params, NxStorage *workingStorage, const QString& output, NxStorage *input)
{
    m_ProgressDialog = new Progress(parent, workingStorage);
    /*
    if (mode == create_emunand)
    {
        m_Worker = new Worker(m_ProgressDialog, mode, output, workingStorage);
        return;
    }
    */
    m_Worker = new Worker(m_ProgressDialog, mode, params, workingStorage, output, input);
}
int WorkerInstance::exec()
{
    m_Worker->start();
    return m_ProgressDialog->exec();
}
