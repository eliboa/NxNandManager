#include "dump.h"
#include "ui_dump.h"

Dump::Dump(QWidget *parent, NxStorage* input, int in_part) :
     QDialog(parent),
    ui(new Ui::Dump)
{
    ui->setupUi(this);

    if(input->isNxStorage())
        m_input = input;
    else return;

    if (in_part != UNKNOWN && nullptr != input->getNxPartition(in_part))
        m_par.partition = in_part;

    bool isNativeEncrypted = true;
    int type = UNKNOWN;

    if(m_par.partition != UNKNOWN)
    {
        m_in_size = input->getNxPartition(m_par.partition)->size();
        NxPartition *part = input->getNxPartition(m_par.partition);
        if (part->nxPart_info.isEncrypted)
            isNativeEncrypted = true;
        ui->inTypeValue->setText(QString(input->getNxTypeAsStr(m_par.partition)));
    }
    else
    {
        m_in_size = input->size();
        if (input->isSinglePartType())
        {
            NxPartition *part = input->getNxPartition();
            if (nullptr != part && part->nxPart_info.isEncrypted)
                isNativeEncrypted = true;
        }
        ui->inTypeValue->setText(QString(input->getNxTypeAsStr()));
    }
    ui->inPathValue->setText(QString::fromWCharArray(m_input->m_path));
    ui->inSizeValue->setText(QString::fromStdString(GetReadableSize(m_in_size)));

    m_good_crypto = isNativeEncrypted && m_input->isCryptoSet() && !m_input->badCrypto() ? true : false;
    if (m_good_crypto)
    {
        if (m_input->isEncrypted()) ui->decryptValue->setEnabled(true);
        else ui->encryptValue->setEnabled(true);
        ui->ptZeroesCheckBox->setEnabled(true);
        ui->formatUserCheckBox->setEnabled(true);
    }
    on_crypto_changed();

    if (m_in_size >= 0x3FFFFFFF)
    {
        int max = m_in_size / 0x400 / 0x400;
        ui->chunsizeValue->setMaximum(max);
        ui->chunsizeValue->setValue(max < 4096 ? 4096 : 0);
        ui->splitCheckBox->setEnabled(true);
    }
}

Dump::~Dump()
{
    delete ui;
}

void Dump::on_selectOutputBtn_clicked()
{
    QSettings MySettings;
    QFileDialog fd(this);
    QString fileName = fd.getSaveFileName(this, "Save as", "default_dir\\" + ui->inTypeValue->text() + ".bin");

    if (!fileName.isEmpty())
    {
        ui->outPathValue->setText(fileName);
    }
}

void Dump::on_splitCheckBox_stateChanged(int arg1)
{
    if (ui->splitCheckBox->isChecked())
    {
        ui->chunksizeLbl->setEnabled(true);
        ui->chunsizeValue->setEnabled(true);
    }
    else
    {
        ui->chunksizeLbl->setDisabled(true);
        ui->chunsizeValue->setDisabled(true);
    }
}

void Dump::on_ptZeroesCheckBox_stateChanged(int arg1)
{
    if (ui->ptZeroesCheckBox->isChecked())
        lock_md5CheckBox();
    else
        unlock_md5CheckBox();
}

void Dump::on_crypto_changed()
{           
    // Encrypt or decrypt
    if (!ui->noCryptotValue->isChecked())
    {
        lock_md5CheckBox();
        if(ui->encryptValue->isChecked())
            m_par.crypto_mode = ENCRYPT;
        else
            m_par.crypto_mode = DECRYPT;
    }
    else
    {
        m_par.crypto_mode = NO_CRYPTO;
        unlock_md5CheckBox();
    }
}
void Dump::on_encryptValue_toggled(bool checked) {
    if (checked) on_crypto_changed();
}
void Dump::on_decryptValue_toggled(bool checked) {
    if (checked) on_crypto_changed();
}
void Dump::on_noCryptotValue_toggled(bool checked) {
    if (checked) on_crypto_changed();
}
void Dump::lock_md5CheckBox(bool checked)
{
    if (ui->bypassMd5CheckBox->isEnabled())
        m_previous_bypassMD5 = ui->bypassMd5CheckBox->isChecked();
    ui->bypassMd5CheckBox->setDisabled(true);
    ui->bypassMd5CheckBox->setChecked(checked);
}
void Dump::unlock_md5CheckBox()
{
    if (ui->bypassMd5CheckBox->isEnabled()    || !ui->noCryptotValue->isChecked()     ||
            ui->ptZeroesCheckBox->isChecked() || ui->formatUserCheckBox->isChecked())
        return;

    ui->bypassMd5CheckBox->setChecked(m_previous_bypassMD5);
    ui->bypassMd5CheckBox->setEnabled(true);
}

void Dump::on_formatUserCheckBox_stateChanged(int arg1)
{
    if (ui->formatUserCheckBox->isChecked())
        lock_md5CheckBox();
    else
        unlock_md5CheckBox();
}

void Dump::on_pushButton_clicked()
{
    if (!ui->outPathValue->text().length())
    {
        QMessageBox::critical(nullptr,"Error","Path to output file is missing");
        return;
    }

    if (!ui->splitCheckBox->isChecked())
    {
        QFile outFile(ui->outPathValue->text());
        if (outFile.exists() && !outFile.remove())
        {
            QMessageBox::critical(nullptr,"Error","Failed to delete output file");
            return;
        }
        if (!outFile.open(QIODevice::WriteOnly))
        {
            QMessageBox::critical(nullptr,"Error","Failed to create output file");
            return;
        } else
        outFile.close();
    }

    if (ui->ptZeroesCheckBox->isChecked())
        m_par.passThroughZero = true;

    if (ui->zipCheckBox->isChecked())
        m_par.zipOutput = true;

    if (m_par.crypto_mode == NO_CRYPTO && !ui->bypassMd5CheckBox->isChecked())
        m_par.crypto_mode = MD5_HASH;

    if (ui->splitCheckBox->isChecked())
    {
        m_par.split_output = true;
        m_par.chunksize = (u64)ui->chunsizeValue->value() * 0x400 * 0x400;
    }

    // Do COPY
    WorkerInstance wi(this, WorkerMode::dump, &m_par, m_input, ui->outPathValue->text());
    wi.exec();
}
