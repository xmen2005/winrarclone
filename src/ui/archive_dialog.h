// archive_dialog.h — tabbed archive creation dialog (spec mockup 3)
#pragma once
#include "core/common.h"

using wrc::ArchiveOptions;
using wrc::Format;

#include <QtWidgets/QDialog>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QRadioButton;
class QSpinBox;

class ArchiveDialog : public QDialog {
    Q_OBJECT
public:
    // Fills `out` and returns true when the user accepted.
    static bool getOptions(QWidget* parent, const QString& defaultDir,
                           const QStringList& files, ArchiveOptions& out);

private slots:
    void updateRamWarning();
    void browseName();
    void formatChanged();

private:
    ArchiveDialog(QWidget* parent, const QString& defaultDir, const QStringList& files);

    QWidget* makeGeneralTab();
    QWidget* makeAdvancedTab();
    QWidget* makeSecurityTab();
    Format selectedFormat() const;
    uint64_t selectedDict() const;
    uint64_t selectedVolume() const;
    void syncExtension();

    QLineEdit* m_name;
    QRadioButton *m_fmtWsar, *m_fmtZip, *m_fmt7z;
    QComboBox* m_method;
    QComboBox* m_dict;
    QLabel* m_ramWarn;
    QComboBox* m_volume;
    QLineEdit* m_volumeCustom;
    QCheckBox *m_longRange, *m_exhaustive, *m_multiThread;
    QCheckBox *m_solid, *m_deleteAfter;
    QSpinBox* m_threads;
    QSpinBox* m_zstdLevel;
    QLineEdit *m_password, *m_password2;
    QCheckBox* m_encryptNames;
    QString m_dir;
};
