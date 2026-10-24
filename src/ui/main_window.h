// main_window.h — classic WinRAR main window (spec §2.a)
#pragma once
#include "core/common.h"
#include "ui/progress_dialog.h"

#include <functional>

#include <QtWidgets/QMainWindow>

class QLabel;
class QLineEdit;
class QTreeWidget;
class QTreeWidgetItem;
class QMenu;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();
    void openArchivePath(const std::wstring& path) { loadArchive(path); }

protected:
    void dragEnterEvent(QDragEnterEvent* ev) override;
    void dropEvent(QDropEvent* ev) override;

private slots:
    // toolbar / commands
    void onAdd();
    void onExtractTo();
    void onTest();
    void onView();
    void onDelete();
    void onInfo();
    void onRepair();
    // navigation
    void onUp();
    void onAddressActivated();
    void onItemActivated(QTreeWidgetItem* item, int col);
    void onSelectionChanged();
    void onContextMenu(const QPoint& pos);
    // misc
    void onOpenArchive();
    void onBrowseFolder();
    void onSelectAll();
    void onInvertSelection();
    void onToggleShell();
    void onAbout();

private:
    enum class Mode { Browse, ArchiveView };

    void buildMenus();
    void buildToolbar();
    void buildCentral();
    void refreshBrowse();
    void refreshArchive();
    void loadArchive(const std::wstring& path);
    void closeArchive();
    void setMode(Mode m);
    void setStatus();
    void setPath(const QString& path);
    QString currentDir() const;
    std::vector<std::wstring> selectedBrowsePaths() const;
    std::vector<std::wstring> selectedEntryNames() const;
    QTreeWidgetItem* addRow(const QList<QString>& cols, const QVariant& role1,
                            const QVariant& role2);

    // generic background job runner
    void runJob(const QString& title, uint64_t dictSize,
                std::function<std::string(ProgressDialog&)> job,
                const std::function<void()>& onSuccess = {});

    Mode m_mode = Mode::Browse;
    QString m_path;  // current directory (Browse) or archive path (ArchiveView)
    wrc::ArchiveInfo m_info;
    std::wstring m_password;  // cached password for the open archive

    QTreeWidget* m_tree;
    QLineEdit* m_address;
    QLabel *m_statusSel, *m_statusTotal, *m_statusDict;
    QAction *m_actAdd, *m_actExtract, *m_actTest, *m_actView, *m_actDelete,
        *m_actInfo, *m_actRepair;
    QMenu* m_favoritesMenu;
    QStringList m_recent;
};
