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
#pragma once
#ifndef WORKER_H
#define WORKER_H

#define NONE            000
#define LIST_STORAGE    100
#define NEW_STORAGE     101
#define DUMP			102
//#define RESTORE			103
#define DUMP_PART		104
#define RESTORE_PART    105
#define RESIZE          106
#define SDPART_EMUNAND  107

#include <QMainWindow>
#include <QtCore>
#include <QString>
#include <QThread>
#include <QFile>
#include <QMessageBox>
#include "progress.h"
#include "../NxStorage.h"

class NxStorage;
class Progress;

enum WorkerMode { dump, restore, new_storage, list_storage, create_emunand, format_partition, get_volumes, get_disks };

class Worker : public QThread {
	Q_OBJECT
public:
    explicit Worker(QWidget *parent, WorkerMode mode) : m_parent(parent), m_mode(mode) {}
    explicit Worker(QWidget *parent, WorkerMode mode, const QString& file, NxStorage *workingStorage = nullptr) : m_parent(parent), m_WorkingStorage(workingStorage), m_file(file), m_mode(mode) {}
    explicit Worker(QWidget *parent, WorkerMode mode, params_t *params, NxStorage *workingStorage = nullptr,
                    const QString& output = "", NxStorage *input = nullptr) : m_parent(parent), m_WorkingStorage(workingStorage),
                    m_inStorage(input), m_file(output), m_params(*params), m_mode(mode)  {}
    ~Worker();
    void updateProgress(const ProgressInfo);

public slots:
	void run();
	void terminate();

signals:
    void finished();
	void finished(NxStorage*);
    void listCallback(QString);
	void error(int, QString s = nullptr);
    void sendProgress(const ProgressInfo pi);
    void getDisks_callback(const std::vector<diskDescriptor> disks);

private:
    // Member vars
    QWidget *m_parent;
    NxStorage *m_WorkingStorage;
    NxStorage *m_inStorage;
    QString m_file;
    NxHandle *m_outHandle;
    params_t m_params;
    WorkerMode m_mode;

public:
    timepoint_t begin_time;
};

class WorkerInstance  {

public:
    WorkerInstance(QWidget *parent, WorkerMode mode, params_t *params, NxStorage *workingStorage = nullptr, const QString& output = "", NxStorage *input = nullptr);
    WorkerInstance(QWidget *parent, WorkerMode mode, const QString& file = "") { WorkerInstance(parent, mode, nullptr, nullptr, file, nullptr);}
    int exec();

private:
    Progress* m_ProgressDialog;
    Worker* m_Worker;
};


static Worker* worker_instance = nullptr;
static ProgressInfo s_pi;
static ProgressInfo s_sub_pi;
static u64 buf64 = 0;
static bool WorkInProgress = false;
#endif // WORKER_H
