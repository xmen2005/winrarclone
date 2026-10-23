// info_dialog.cpp
#include "ui/info_dialog.h"

#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>

InfoDialog::InfoDialog(QWidget* parent, const QString& title,
                       const QList<QPair<QString, QString>>& rows)
    : QDialog(parent) {
    setWindowTitle(title);
    resize(420, 320);
    auto* form = new QFormLayout;
    for (const auto& row : rows) {
        auto* value = new QLabel(row.second, this);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setWordWrap(true);
        form->addRow(row.first, value);
    }
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(buttons);
}
