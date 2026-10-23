// info_dialog.h — archive / entry information dialog
#pragma once
#include <QtWidgets/QDialog>

class InfoDialog : public QDialog {
    Q_OBJECT
public:
    InfoDialog(QWidget* parent, const QString& title,
               const QList<QPair<QString, QString>>& rows);
};
