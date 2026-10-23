// progress_dialog.h — live progress (spec mockup 4: ratio, size, speed, ETA)
#pragma once
#include "core/common.h"

#include <atomic>
#include <functional>
#include <thread>

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>

class ProgressDialog : public QDialog {
    Q_OBJECT
public:
    explicit ProgressDialog(QWidget* parent);
    ~ProgressDialog() override;

    // Runs `job` on a worker thread; the dialog shows live progress and blocks
    // until the job completes. Returns the job's error string ("" = success).
    void execJob(std::function<std::string(ProgressDialog&)> job);

    // Control function for the core engine (pause + cancel aware).
    bool control();

    void setDictLabel(uint64_t dictSize);

signals:
    void progressChanged(wrc::Progress p);

public slots:
    void applyProgress(const wrc::Progress& p);

private slots:
    void onPause();
    void onBackground();
    void onCancel();

private:
    void finish(const std::string& result);

    QProgressBar* m_fileBar;
    QProgressBar* m_totalBar;
    QLabel* m_fileLabel;
    QLabel* m_elapsed;
    QLabel* m_remaining;
    QLabel* m_speed;
    QLabel* m_compressed;
    QLabel* m_ratio;
    QLabel* m_dict;
    QPushButton* m_pauseBtn;

    std::thread m_worker;
    std::atomic<uint32_t> m_ctrl{1};  // 1 run, 2 pause, 3 cancel
    std::string m_result;
    bool m_started = false;
};

Q_DECLARE_METATYPE(wrc::Progress)
