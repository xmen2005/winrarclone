// archive_dialog.cpp
#include "ui/archive_dialog.h"

#include "core/common.h"
#include "core/dictionary_mgr.h"

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>

#include <QFileInfo>

using namespace wrc;

static uint64_t parseSizeText(const QString& text) {
    QString t = text.trimmed().toUpper();
    uint64_t mult = 1;
    if (t.endsWith("GB")) { mult = 1ull << 30; t.chop(2); }
    else if (t.endsWith("MB")) { mult = 1ull << 20; t.chop(2); }
    else if (t.endsWith("KB")) { mult = 1ull << 10; t.chop(2); }
    else if (t.endsWith('G')) { mult = 1ull << 30; t.chop(1); }
    else if (t.endsWith('M')) { mult = 1ull << 20; t.chop(1); }
    else if (t.endsWith('K')) { mult = 1ull << 10; t.chop(1); }
    else if (t.endsWith('B')) { t.chop(1); }
    return uint64_t(t.toDouble()) * mult;
}

ArchiveDialog::ArchiveDialog(QWidget* parent, const QString& defaultDir,
                             const QStringList& files)
    : QDialog(parent), m_dir(defaultDir) {
    setWindowTitle(tr("Archive name and parameters"));
    resize(520, 460);

    auto* tabs = new QTabWidget(this);
    tabs->addTab(makeGeneralTab(), tr("General"));
    tabs->addTab(makeAdvancedTab(), tr("Advanced"));
    tabs->addTab(makeSecurityTab(), tr("Security && Password"));

    auto* buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel |
                                 QDialogButtonBox::Help);
    connect(buttons, &QDialogButtonBox::accepted, this, [this] {
        if (!m_password->text().isEmpty() && m_password->text() != m_password2->text()) {
            QMessageBox::warning(this, tr("Password"), tr("Passwords do not match."));
            return;
        }
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons->button(QDialogButtonBox::Help), &QPushButton::clicked, this, [this] {
        QMessageBox::information(
            this, tr("Help"),
            tr("Dictionary size is the compression window. Larger dictionaries "
               "usually mean better ratios on big repetitive data, at the cost of "
               "RAM (compression needs about 2x the dictionary size).\n"
               "AES-256 encryption requires a password."));
    });

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(tabs);
    layout->addWidget(buttons);

    connect(m_dict, &QComboBox::currentIndexChanged, this,
            &ArchiveDialog::updateRamWarning);
    connect(m_fmtWsar, &QRadioButton::toggled, this, &ArchiveDialog::formatChanged);
    connect(m_fmtZip, &QRadioButton::toggled, this, &ArchiveDialog::formatChanged);
    connect(m_fmt7z, &QRadioButton::toggled, this, &ArchiveDialog::formatChanged);

    // default archive name
    QString base = tr("Archive");
    if (!files.isEmpty()) {
        QString first = files.first();
        int slash = int(first.lastIndexOf('/'));
        if (slash >= 0) first = first.mid(slash + 1);
        int dot = int(first.lastIndexOf('.'));
        if (dot > 0) first = first.left(dot);
        if (!first.isEmpty()) base = first;
    }
    m_name->setText(base + ".wrc");
    updateRamWarning();
}

QWidget* ArchiveDialog::makeGeneralTab() {
    auto* w = new QWidget(this);
    auto* form = new QFormLayout(w);

    auto* nameRow = new QWidget(w);
    auto* nameLay = new QHBoxLayout(nameRow);
    nameLay->setContentsMargins(0, 0, 0, 0);
    m_name = new QLineEdit(nameRow);
    auto* browse = new QPushButton(tr("Browse…"), nameRow);
    nameLay->addWidget(m_name, 1);
    nameLay->addWidget(browse);
    form->addRow(tr("Archive name"), nameRow);
    connect(browse, &QPushButton::clicked, this, &ArchiveDialog::browseName);

    auto* fmtRow = new QWidget(w);
    auto* fmtLay = new QHBoxLayout(fmtRow);
    fmtLay->setContentsMargins(0, 0, 0, 0);
    m_fmtWsar = new QRadioButton("RAR5-style (.wrc)", fmtRow);
    m_fmtZip = new QRadioButton("ZIP", fmtRow);
    m_fmt7z = new QRadioButton("7Z", fmtRow);
    m_fmtWsar->setChecked(true);
    fmtLay->addWidget(m_fmtWsar);
    fmtLay->addWidget(m_fmtZip);
    fmtLay->addWidget(m_fmt7z);
    fmtLay->addStretch(1);
    form->addRow(tr("Archive format"), fmtRow);

    m_method = new QComboBox(w);
    m_method->addItem(tr("Store"));
    m_method->addItem(tr("Fastest"));
    m_method->addItem(tr("Fast"));
    m_method->addItem(tr("Normal"));
    m_method->setCurrentIndex(3);
    m_method->addItem(tr("Good"));
    m_method->addItem(tr("Best"));
    form->addRow(tr("Compression method"), m_method);

    m_dict = new QComboBox(w);
    const struct { uint64_t size; const char* label; } dicts[] = {
        {1ull << 20, "1 MB"},    {2ull << 20, "2 MB"},    {4ull << 20, "4 MB"},
        {8ull << 20, "8 MB"},    {16ull << 20, "16 MB"},  {32ull << 20, "32 MB"},
        {64ull << 20, "64 MB"},  {128ull << 20, "128 MB"},{256ull << 20, "256 MB"},
        {512ull << 20, "512 MB"},{1ull << 30, "1 GB"},    {2ull << 30, "2 GB"},
        {4ull << 30, "4 GB"},    {8ull << 30, "8 GB"},    {16ull << 30, "16 GB"},
        {32ull << 30, "32 GB"},  {64ull << 30, "64 GB"},
    };
    for (auto& d : dicts) m_dict->addItem(QString::fromUtf8(d.label), quint64(d.size));
    m_dict->setCurrentIndex(6);  // 64 MB default
    form->addRow(tr("Dictionary size"), m_dict);

    m_ramWarn = new QLabel(w);
    m_ramWarn->setWordWrap(true);
    m_ramWarn->setStyleSheet("color:#7a5b00; background:#fff3c2; border:1px solid #e0c96b;"
                             "border-radius:4px; padding:6px;");
    m_ramWarn->hide();
    form->addRow(m_ramWarn);

    auto* volRow = new QWidget(w);
    auto* volLay = new QHBoxLayout(volRow);
    volLay->setContentsMargins(0, 0, 0, 0);
    m_volume = new QComboBox(volRow);
    m_volume->addItem(tr("No split"), quint64(0));
    m_volume->addItem("700 MB (CD)", quint64(700ull << 20));
    m_volume->addItem("4.7 GB (DVD)", quint64(4700ull << 20));
    m_volume->addItem("8.5 GB (DL-DVD)", quint64(8500ull << 20));
    m_volume->addItem(tr("Custom…"), quint64(0));
    m_volumeCustom = new QLineEdit(volRow);
    m_volumeCustom->setPlaceholderText(tr("size, e.g. 100M"));
    m_volumeCustom->setEnabled(false);
    volLay->addWidget(m_volume, 1);
    volLay->addWidget(m_volumeCustom, 1);
    connect(m_volume, &QComboBox::currentIndexChanged, volRow, [this] {
        m_volumeCustom->setEnabled(m_volume->currentText() == tr("Custom…"));
    });
    form->addRow(tr("Split to volumes"), volRow);

    auto* opts = new QWidget(w);
    auto* optsLay = new QVBoxLayout(opts);
    optsLay->setContentsMargins(0, 0, 0, 0);
    m_longRange = new QCheckBox(tr("Long Range Search"), opts);
    m_exhaustive = new QCheckBox(tr("Exhaustive Search"), opts);
    m_multiThread = new QCheckBox(tr("Multi-threaded"), opts);
    m_multiThread->setChecked(true);
    optsLay->addWidget(m_longRange);
    optsLay->addWidget(m_exhaustive);
    optsLay->addWidget(m_multiThread);
    form->addRow(tr("Options"), opts);

    return w;
}

QWidget* ArchiveDialog::makeAdvancedTab() {
    auto* w = new QWidget(this);
    auto* form = new QFormLayout(w);
    m_deleteAfter = new QCheckBox(tr("Delete files after archiving"), w);
    m_threads = new QSpinBox(w);
    m_threads->setRange(0, 128);
    m_threads->setValue(0);
    m_threads->setSpecialValueText(tr("Auto"));
    form->addRow(m_deleteAfter);
    form->addRow(tr("Threads"), m_threads);
    auto* note = new QLabel(
        tr("Dictionary-mode compression (.wrc Normal/Good/Best) streams files "
           "through one shared dictionary window and is serial by design; "
           "Store/Fastest/Fast (Deflate) compress files in parallel."),
        w);
    note->setWordWrap(true);
    form->addRow(note);
    return w;
}

QWidget* ArchiveDialog::makeSecurityTab() {
    auto* w = new QWidget(this);
    auto* form = new QFormLayout(w);
    m_password = new QLineEdit(w);
    m_password->setEchoMode(QLineEdit::Password);
    m_password2 = new QLineEdit(w);
    m_password2->setEchoMode(QLineEdit::Password);
    m_encryptNames = new QCheckBox(tr("Encrypt file names"), w);
    form->addRow(tr("Enter password"), m_password);
    form->addRow(tr("Reenter password"), m_password2);
    form->addRow(m_encryptNames);
    auto* note = new QLabel(
        tr("AES-256-CBC with PBKDF2-HMAC-SHA256 (200k iterations).\n"
           "Encrypted archives keep Mark-of-the-Web inheritance on extraction."),
        w);
    note->setWordWrap(true);
    form->addRow(note);
    return w;
}

Format ArchiveDialog::selectedFormat() const {
    if (m_fmtZip->isChecked()) return Format::Zip;
    if (m_fmt7z->isChecked()) return Format::SevenZip;
    return Format::Wsar;
}

uint64_t ArchiveDialog::selectedDict() const {
    return uint64_t(m_dict->currentData().toULongLong());
}

uint64_t ArchiveDialog::selectedVolume() const {
    if (m_volume->currentText() == tr("Custom…"))
        return parseSizeText(m_volumeCustom->text());
    return uint64_t(m_volume->currentData().toULongLong());
}

void ArchiveDialog::syncExtension() {
    QString text = m_name->text();
    int dot = int(text.lastIndexOf('.'));
    const wchar_t* ext = selectedFormat() == Format::Zip       ? L".zip"
                         : selectedFormat() == Format::SevenZip ? L".7z"
                                                                : L".wrc";
    if (dot > 0) text = text.left(dot);
    m_name->setText(text + QString::fromWCharArray(ext));
}

void ArchiveDialog::formatChanged() { syncExtension(); }

void ArchiveDialog::browseName() {
    const char* filter = selectedFormat() == Format::Zip       ? "ZIP (*.zip)"
                         : selectedFormat() == Format::SevenZip ? "7Z (*.7z)"
                                                                : "WSAR (*.wrc)";
    QString f = QFileDialog::getSaveFileName(this, tr("Archive name"), m_dir + "/" +
                                                                     m_name->text(),
                                             QString::fromUtf8(filter));
    if (!f.isEmpty()) m_name->setText(f);
}

void ArchiveDialog::updateRamWarning() {
    DictionaryCheck c = DictionaryManager::validate(selectedDict());
    if (c.withinSafeThreshold()) {
        m_ramWarn->hide();
        return;
    }
    m_ramWarn->setText(tr("Required RAM (~%1) exceeds the safe threshold of the "
                          "available %2.\nPick a smaller dictionary or confirm to "
                          "continue anyway.")
                           .arg(QString::fromStdWString(humanSize(c.requiredRam)))
                           .arg(QString::fromStdWString(humanSize(c.availableRam))));
    m_ramWarn->show();
}

bool ArchiveDialog::getOptions(QWidget* parent, const QString& defaultDir,
                               const QStringList& files, ArchiveOptions& out) {
    ArchiveDialog dlg(parent, defaultDir, files);
    if (dlg.exec() != QDialog::Accepted) return false;
    out = ArchiveOptions{};
    std::wstring name = dlg.m_name->text().toStdWString();
    if (QFileInfo(dlg.m_name->text()).isRelative())
        name = dlg.m_dir.toStdWString() + L"\\" + name;
    out.archivePath = name;
    out.format = dlg.selectedFormat();
    out.method = Method(dlg.m_method->currentIndex());
    out.dictSize = dlg.selectedDict();
    out.volumeSize = dlg.selectedVolume();
    out.longRangeSearch = dlg.m_longRange->isChecked();
    out.exhaustiveSearch = dlg.m_exhaustive->isChecked();
    out.multiThread = dlg.m_multiThread->isChecked();
    out.deleteAfter = dlg.m_deleteAfter->isChecked();
    out.threads = dlg.m_threads->value();
    out.password = dlg.m_password->text().toStdWString();
    out.encryptNames = dlg.m_encryptNames->isChecked();
    return true;
}
