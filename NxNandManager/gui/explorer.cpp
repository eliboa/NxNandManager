#include "explorer.h"
#include "ui_explorer.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <QSqlDatabase>
#include <QSqlDriver>
#include <QSqlError>
#include <QSqlQuery>
#include <QDebug>

QString findTitleFromNCA(const QString& filename)
{
    QSqlDatabase::database();
    QSqlQuery query;
    if(!query.exec("SELECT title_label FROM ncas WHERE id = '"+filename.left(32)+"'"))
        qDebug() << "ERROR: " << query.lastError().text();
    else if(query.first())
        return query.value(0).toString();
    return "";
}

Explorer::Explorer(QWidget *parent, NxPartition *partition) :
    QDialog(parent),
    ui(new Ui::Explorer)
{
    ui->setupUi(this);
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "Filename" << "TitleID" << "Title label" << "Content type");

    // Get data from Json
    QFile file("nca.json");
    QJsonArray ncas;
    if (file.open(QIODevice::ReadOnly))
    {
        ncas = QJsonDocument::fromJson(file.readAll()).object()["ncas"].toArray();
        file.close();
    }

    // Create db & fill nca table with data
    const QString DRIVER("QSQLITE");
    if(QSqlDatabase::isDriverAvailable(DRIVER)) {
        QSqlDatabase db = QSqlDatabase::addDatabase(DRIVER);
        db.setDatabaseName(":memory:");
        if(db.open())
        {
            QSqlQuery query("CREATE TABLE ncas (id VARCHAR(32) PRIMARY KEY, title_id CHAR(16), title_label VARCHAR(64), type VARCHAR(32))");
            if(query.isActive()) for (auto nca : ncas)
            {
                auto entry = [&] (const char* field) { return nca.toObject()[field].toString(); };
                QSqlQuery query_i;
                if (!query_i.exec("INSERT INTO ncas VALUES ('"+entry("nca_filename").left(32)+"', '"+ entry("title_id")+"', '"+entry("label")+"', '"+ entry("type")+"');"))
                    qDebug() << "ERROR: " << query_i.lastError().text();
            }
        }
    }

    // Fill tablewidget with files from /Contents/registered
    std::vector<fat32::dir_entry> entries;
    partition->fat32_dir(&entries, "/Contents/registered");
    for (auto entry : entries)
    {
        ui->tableWidget->insertRow(ui->tableWidget->rowCount());
        ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, 0, new QTableWidgetItem(QString(entry.filename.c_str())));
        QSqlQuery query;
        if(query.exec("SELECT title_id, title_label, type FROM ncas WHERE id = '"+QString::fromStdString(entry.filename).left(32)+"'") && query.first())
            for (int i(0); i < 4; i++) ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, i+1, new QTableWidgetItem(query.value(i).toString()));
        else qDebug() << "ERROR: " << query.lastError().text();
    }
    ui->tableWidget->resizeColumnsToContents();
}

Explorer::~Explorer()
{
    delete ui;
}
