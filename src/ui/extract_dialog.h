// extract_dialog.h — extraction destination dialog
#pragma once
#include <QtWidgets/QDialog>

class QCheckBox;
class QLineEdit;

class ExtractDialog : public QDialog {
    Q_OBJECT
public:
    ExtractDialog(QWidget* parent, const QString& archivePath, const QString& defaultDir);

    QString destination() const;
    QString password() const;
    bool openAfter() const;

private:
    QLineEdit* m_dest;
    QLineEdit* m_password;
    QCheckBox* m_openAfter;
    QString m_dir;
};
