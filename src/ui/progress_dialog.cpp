// progress_dialog.cpp
#include "ui/progress_dialog.h"

#include <QtWidgets/QBoxLayout>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QMessageBox>

#include <chrono>

using namespace wrc;

namespace {
std::wstring secsToClock(double s) {
    if (s < 0 || s > 3600.0 * 24 * 365) return L"--:--:--";
    int t = int(s);
    wchar_t buf[32];
    swprintf(buf, 32, L"%02d:%02d:%02d", t / 3600, (t / 60) % 60, t % 60);
    return buf;
}
}  // namespace

ProgressDialog::ProgressDialog(QWidget* parent)
    : QDialog(parent, Qt::WindowTitleHint | Qt::WindowSystemMenuHint | Qt::WindowMinMaxButtonsHint | Qt::WindowCloseButtonHint) {
    setWindowTitle(tr("Working…"));
    setModal(true);
    resize(520, 300);

    auto* layout = new QVBoxLayout(this);

    m_fileLabel = new QLabel(tr("Preparing…"), this);
    m_fileLabel->setWordWrap(true);
    layout->addWidget(m_fileLabel);

    auto* grid = new QGridLayout();
    auto makeLabel = [](const QString& text) {
        auto* l = new QLabel(text);
        l->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        return l;
    };
    grid->addWidget(makeLabel(tr("Elapsed")), 0, 0);
    m_elapsed = new QLabel(tr("00:00:00"));
    grid->addWidget(m_elapsed, 0, 1);
    grid->addWidget(makeLabel(tr("Remaining")), 0, 2);
    m_remaining = new QLabel(tr("--:--:--"));
    grid->addWidget(m_remaining, 0, 3);
    grid->addWidget(makeLabel(tr("Speed")), 0, 4);
    m_speed = new QLabel(tr("—"));
    grid->addWidget(m_speed, 0, 5);
    layout->addLayout(grid);

    layout->addWidget(new QLabel(tr("Current file"), this));
    m_fileBar = new QProgressBar(this);
    m_fileBar->setRange(0, 100);
    layout->addWidget(m_fileBar);

    layout->addWidget(new QLabel(tr("Total progress"), this));
    m_totalBar = new QProgressBar(this);
    m_totalBar->setRange(0, 100);
    layout->addWidget(m_totalBar);

    auto* info = new QGridLayout();
    info->addWidget(makeLabel(tr("Compressed size")), 0, 0);
    m_compressed = new QLabel(tr("—"));
    info->addWidget(m_compressed, 0, 1);
    info->addWidget(makeLabel(tr("Ratio")), 0, 2);
    m_ratio = new QLabel(tr("—"));
    info->addWidget(m_ratio, 0, 3);
    info->addWidget(makeLabel(tr("Dictionary")), 0, 4);
    m_dict = new QLabel(tr("—"));
    info->addWidget(m_dict, 0, 5);
    layout->addLayout(info);

    layout->addStretch(1);

    auto* buttons = new QHBoxLayout();
    auto* backgroundBtn = new QPushButton(tr("Background"), this);
    m_pauseBtn = new QPushButton(tr("Pause"), this);
    auto* cancelBtn = new QPushButton(tr("Cancel"), this);
    buttons->addWidget(backgroundBtn);
    buttons->addStretch(1);
    buttons->addWidget(m_pauseBtn);
    buttons->addWidget(cancelBtn);
    layout->addLayout(buttons);

    connect(backgroundBtn, &QPushButton::clicked, this, &ProgressDialog::onBackground);
    connect(m_pauseBtn, &QPushButton::clicked, this, &ProgressDialog::onPause);
    connect(cancelBtn, &QPushButton::clicked, this, &ProgressDialog::onCancel);
    connect(this, &ProgressDialog::progressChanged, this, &ProgressDialog::applyProgress);
}

ProgressDialog::~ProgressDialog() {
    m_ctrl = 3;
    if (m_worker.joinable()) m_worker.join();
}

void ProgressDialog::setDictLabel(uint64_t dictSize) {
    m_dict->setText(QString::fromStdWString(humanSize(dictSize)));
}

void ProgressDialog::execJob(std::function<std::string(ProgressDialog&)> job) {
    m_result.clear();
    m_ctrl = 1;
    m_pauseBtn->setText(tr("Pause"));
    m_started = true;
    m_worker = std::thread([this, job] {
        std::string res;
        try {
            res = job(*this);
        } catch (const CancelledError&) {
            res = "__cancelled__";
        } catch (const std::exception& ex) {
            res = ex.what();
        }
        std::string captured = res;
        QMetaObject::invokeMethod(
            this,
            [this, captured] { finish(captured); },
            Qt::QueuedConnection);
    });
    exec();
    if (m_worker.joinable()) m_worker.join();
    m_started = false;
}

bool ProgressDialog::control() {
    while (m_ctrl.load() == 2) {
        if (m_ctrl.load() == 3) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return m_ctrl.load() != 3;
}

void ProgressDialog::applyProgress(const wrc::Progress& p) {
    m_fileLabel->setText(QString::fromStdWString(p.currentFile.empty()
                                                     ? L"Preparing…"
                                                     : p.currentFile));
    m_elapsed->setText(QString::fromStdWString(secsToClock(p.elapsed)));
    m_remaining->setText(QString::fromStdWString(secsToClock(p.eta)));
    m_speed->setText(QString::fromStdWString(formatSpeed(p.speed)));
    int f = int(p.fileRatio * 100);
    if (f < 0) f = 0;
    if (f > 100) f = 100;
    m_fileBar->setValue(f);
    int t = int(p.totalRatio * 100);
    if (t < 0) t = 0;
    if (t > 100) t = 100;
    m_totalBar->setValue(t);
    m_compressed->setText(QString::fromStdWString(humanSize(p.bytesCompressed) + L" / " +
                                                  humanSize(p.bytesTotal)));
    if (p.bytesTotal > 0)
        m_ratio->setText(QString::number(double(p.bytesCompressed) * 100.0 /
                                             double(p.bytesTotal),
                                         'f', 0) +
                         "%");
    else
        m_ratio->setText(tr("—"));
}

void ProgressDialog::onPause() {
    if (m_ctrl.load() == 2) {
        m_ctrl = 1;
        m_pauseBtn->setText(tr("Pause"));
    } else if (m_ctrl.load() == 1) {
        m_ctrl = 2;
        m_pauseBtn->setText(tr("Resume"));
    }
}

void ProgressDialog::onBackground() { hide(); }

void ProgressDialog::onCancel() {
    if (QMessageBox::question(this, tr("Cancel"), tr("Cancel the operation?")) ==
        QMessageBox::Yes) {
        m_ctrl = 3;
    }
}

void ProgressDialog::finish(const std::string& result) {
    m_result = result;
    if (result.empty() || result == "__cancelled__") {
        accept();
        return;
    }
    QMessageBox::critical(this, tr("Error"),
                          QString::fromStdString(result), QMessageBox::Ok);
    reject();
}
