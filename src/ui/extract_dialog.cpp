// extract_dialog.cpp
#include "ui/extract_dialog.h"

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

#include <QDir>
#include <QFileInfo>

ExtractDialog::ExtractDialog(QWidget* parent, const QString& archivePath,
                             const QString& defaultDir)
    : QDialog(parent), m_dir(defaultDir) {
    setWindowTitle(tr("Extraction path and options"));
    resize(480, 170);

    QString base = QFileInfo(archivePath).completeBaseName();
    QString suggested = defaultDir + "/" + base;

    m_dest = new QLineEdit(suggested, this);
    auto* browse = new QPushButton(tr("Browse…"), this);
    connect(browse, &QPushButton::clicked, this, [this] {
        QString d = QFileDialog::getExistingDirectory(this, tr("Destination folder"),
                                                      m_dest->text());
        if (!d.isEmpty()) m_dest->setText(d);
    });
    auto* destRow = new QWidget(this);
    auto* destLay = new QHBoxLayout(destRow);
    destLay->setContentsMargins(0, 0, 0, 0);
    destLay->addWidget(m_dest, 1);
    destLay->addWidget(browse);

    m_password = new QLineEdit(this);
    m_password->setEchoMode(QLineEdit::Password);

    m_openAfter = new QCheckBox(tr("Open extracted folder"), this);

    auto* form = new QFormLayout;
    form->addRow(tr("Destination folder"), destRow);
    form->addRow(tr("Password (if needed)"), m_password);
    form->addRow(m_openAfter);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(buttons);
}

QString ExtractDialog::destination() const { return m_dest->text(); }
QString ExtractDialog::password() const { return m_password->text(); }
bool ExtractDialog::openAfter() const { return m_openAfter->isChecked(); }
