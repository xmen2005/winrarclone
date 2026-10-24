// main_window.cpp
#include "ui/main_window.h"

#include "core/compressor.h"
#include "core/decompressor.h"
#include "core/dictionary_mgr.h"
#include "core/formats/wsar_format.h"
#include "ui/archive_dialog.h"
#include "ui/extract_dialog.h"
#include "ui/info_dialog.h"
#include "ui/progress_dialog.h"
#include "utils/file_system.h"
#include "os_integration/context_menu.h"

#include <QtWidgets/QApplication>
#include <QtWidgets/QFileIconProvider>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileInfo>
#include <QGuiApplication>
#include <QItemSelectionModel>
#include <QMimeData>
#include <QSettings>
#include <QStandardPaths>
#include <QStyle>
#include <QUrl>

#include <shellapi.h>

using namespace wrc;

// role data
static const int kRoleKind = Qt::UserRole;        // "dir" / "file" / "entry"
static const int kRolePath = Qt::UserRole + 1;    // browse: full path
static const int kRoleEntry = Qt::UserRole + 2;   // archive: entry name

MainWindow::MainWindow() {
    setWindowIcon(style()->standardIcon(QStyle::SP_DriveHDIcon));
    setWindowTitle(tr("WinRAR Clone — Archive Manager"));
    resize(1000, 640);

    QSettings s;
    m_recent = s.value("recent").toStringList();

    buildMenus();
    buildToolbar();
    buildCentral();
    setStatus();

    setPath(QDir::homePath());
    refreshBrowse();
}

// --------------------------------------------------------------------- menus
void MainWindow::buildMenus() {
    QMenu* file = menuBar()->addMenu(tr("&File"));
    file->addAction(style()->standardIcon(QStyle::SP_DirOpenIcon), tr("Open archive…"),
                    this, &MainWindow::onOpenArchive, QKeySequence::Open);
    file->addAction(style()->standardIcon(QStyle::SP_DirIcon), tr("Browse folder…"),
                    this, &MainWindow::onBrowseFolder);
    file->addSeparator();
    file->addAction(tr("E&xit"), this, &MainWindow::close, QKeySequence::Quit);

    QMenu* commands = menuBar()->addMenu(tr("&Commands"));
    commands->addAction(m_actAdd = new QAction(tr("Add"), this));
    commands->addAction(m_actExtract = new QAction(tr("Extract To"), this));
    commands->addAction(m_actTest = new QAction(tr("Test"), this));
    commands->addAction(m_actView = new QAction(tr("View"), this));
    commands->addAction(m_actDelete = new QAction(tr("Delete"), this));
    commands->addAction(m_actInfo = new QAction(tr("Info"), this));
    commands->addAction(m_actRepair = new QAction(tr("Repair"), this));
    commands->addSeparator();
    commands->addAction(tr("Select all"), this, &MainWindow::onSelectAll,
                        QKeySequence::SelectAll);
    commands->addAction(tr("Invert selection"), this, &MainWindow::onInvertSelection);

    QMenu* tools = menuBar()->addMenu(tr("&Tools"));
    tools->addAction(tr("Copy path to clipboard"), this, [this] {
        QGuiApplication::clipboard()->setText(m_path);
    });

    m_favoritesMenu = menuBar()->addMenu(tr("&Favorites"));
    connect(m_favoritesMenu, &QMenu::aboutToShow, this, [this] {
        m_favoritesMenu->clear();
        for (const QString& p : m_recent)
            m_favoritesMenu->addAction(p, this, [this, p] {
                if (isArchiveFile(p.toStdWString()))
                    loadArchive(p.toStdWString());
                else {
                    setPath(p);
                    refreshBrowse();
                }
            });
        if (m_recent.isEmpty()) m_favoritesMenu->addAction(tr("(empty)"))->setEnabled(false);
    });

    QMenu* options = menuBar()->addMenu(tr("&Options"));
    QAction* shell = options->addAction(tr("Integrate into Windows shell"));
    shell->setCheckable(true);
    shell->setChecked(shell::isIntegrated());
    connect(shell, &QAction::toggled, this, &MainWindow::onToggleShell);

    QMenu* help = menuBar()->addMenu(tr("&Help"));
    help->addAction(tr("About"), this, &MainWindow::onAbout);
}

void MainWindow::buildToolbar() {
    QToolBar* tb = addToolBar(tr("Main"));
    tb->setMovable(false);
    tb->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);

    auto addBtn = [&](QAction* a, const QIcon& icon) {
        a->setIcon(icon);
        tb->addAction(a);
    };
    addBtn(m_actAdd, style()->standardIcon(QStyle::SP_FileDialogNewFolder));
    addBtn(m_actExtract, style()->standardIcon(QStyle::SP_ArrowDown));
    addBtn(m_actTest, style()->standardIcon(QStyle::SP_BrowserReload));
    addBtn(m_actView, style()->standardIcon(QStyle::SP_FileDialogContentsView));
    addBtn(m_actDelete, style()->standardIcon(QStyle::SP_TrashIcon));
    addBtn(m_actInfo, style()->standardIcon(QStyle::SP_FileDialogInfoView));
    addBtn(m_actRepair, style()->standardIcon(QStyle::SP_DialogApplyButton));

    connect(m_actAdd, &QAction::triggered, this, &MainWindow::onAdd);
    connect(m_actExtract, &QAction::triggered, this, &MainWindow::onExtractTo);
    connect(m_actTest, &QAction::triggered, this, &MainWindow::onTest);
    connect(m_actView, &QAction::triggered, this, &MainWindow::onView);
    connect(m_actDelete, &QAction::triggered, this, &MainWindow::onDelete);
    connect(m_actInfo, &QAction::triggered, this, &MainWindow::onInfo);
    connect(m_actRepair, &QAction::triggered, this, &MainWindow::onRepair);
}

void MainWindow::buildCentral() {
    QWidget* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(4);

    // address bar
    auto* addrRow = new QWidget(central);
    auto* addrLay = new QHBoxLayout(addrRow);
    addrLay->setContentsMargins(0, 0, 0, 0);
    auto* up = new QToolButton(addrRow);
    up->setIcon(style()->standardIcon(QStyle::SP_ArrowUp));
    up->setToolTip(tr("Up one level"));
    connect(up, &QToolButton::clicked, this, &MainWindow::onUp);
    m_address = new QLineEdit(addrRow);
    m_address->setClearButtonEnabled(true);
    connect(m_address, &QLineEdit::returnPressed, this, &MainWindow::onAddressActivated);
    addrLay->addWidget(up);
    addrLay->addWidget(m_address, 1);
    layout->addWidget(addrRow);

    // file list
    m_tree = new QTreeWidget(central);
    QStringList headers{tr("Name"), tr("Original Size"), tr("Compressed Size"),
                        tr("Ratio"), tr("Modified"), tr("Attr"), tr("CRC32")};
    m_tree->setColumnCount(7);
    m_tree->setHeaderLabels(headers);
    m_tree->header()->resizeSection(0, 320);
    m_tree->setAlternatingRowColors(true);
    m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_tree->setRootIsDecorated(false);
    m_tree->setAcceptDrops(true);
    m_tree->setDragDropMode(QAbstractItemView::DropOnly);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tree, &QTreeWidget::itemActivated, this, &MainWindow::onItemActivated);
    connect(m_tree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onItemActivated);
    connect(m_tree->selectionModel(), &QItemSelectionModel::selectionChanged, this,
            &MainWindow::onSelectionChanged);
    connect(m_tree, &QTreeWidget::customContextMenuRequested, this,
            &MainWindow::onContextMenu);
    layout->addWidget(m_tree, 1);

    setCentralWidget(central);

    // status bar
    m_statusSel = new QLabel(this);
    m_statusTotal = new QLabel(this);
    m_statusDict = new QLabel(this);
    statusBar()->addWidget(m_statusSel, 1);
    statusBar()->addWidget(m_statusTotal, 1);
    statusBar()->addPermanentWidget(m_statusDict);
}

// -------------------------------------------------------------------- modes
void MainWindow::setMode(Mode m) {
    m_mode = m;
    m_actExtract->setEnabled(m == Mode::ArchiveView);
    m_actTest->setEnabled(m == Mode::ArchiveView);
    m_actRepair->setEnabled(m == Mode::ArchiveView);
    m_actView->setEnabled(m == Mode::ArchiveView);
}

void MainWindow::setPath(const QString& path) {
    m_path = QDir::toNativeSeparators(QDir::cleanPath(path));
    m_address->setText(m_path);
}

QString MainWindow::currentDir() const {
    return m_mode == Mode::ArchiveView ? QFileInfo(m_path).absolutePath() : m_path;
}

QTreeWidgetItem* MainWindow::addRow(const QList<QString>& cols, const QVariant& role1,
                                    const QVariant& role2) {
    auto* it = new QTreeWidgetItem(m_tree);
    for (int i = 0; i < cols.size() && i < 7; ++i) {
        it->setText(i, cols[i]);
        if (i >= 1 && i <= 3) it->setTextAlignment(i, Qt::AlignRight | Qt::AlignVCenter);
    }
    it->setData(0, kRoleKind, role1);
    it->setData(0, kRolePath, role2);
    return it;
}

void MainWindow::refreshBrowse() {
    m_tree->clear();
    m_info = ArchiveInfo{};
    setMode(Mode::Browse);
    QFileIconProvider icons;
    QDir dir(m_path);
    QFileInfoList entries =
        dir.entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::System,
                          QDir::DirsFirst | QDir::Name);
    for (const QFileInfo& fi : entries) {
        if (fi.fileName() == "..") continue;
        QList<QString> cols;
        cols << fi.fileName()
             << (fi.isDir() ? QStringLiteral("—")
                            : QString::fromStdWString(humanSize(uint64_t(fi.size()))))
             << QStringLiteral("—") << QStringLiteral("—")
             << fi.lastModified().toString("yyyy-MM-dd HH:mm")
             << (fi.isDir() ? QStringLiteral("D") : QStringLiteral("A"))
             << QStringLiteral("");
        auto* it = addRow(cols, fi.isDir() ? "dir" : "file",
                          QDir::toNativeSeparators(fi.absoluteFilePath()));
        it->setIcon(0, icons.icon(fi));
    }
    setStatus();
}

void MainWindow::refreshArchive() {
    m_tree->clear();
    setMode(Mode::ArchiveView);
    for (const auto& e : m_info.entries) {
        uint64_t ratioPct = e.size ? e.packedSize * 100 / e.size : 0;
        QList<QString> cols;
        wchar_t crc[16] = L"";
        if (!e.isDir) swprintf(crc, 16, L"%08X", e.crc32);
        cols << QString::fromStdWString(e.name)
             << (e.isDir ? QStringLiteral("—")
                         : QString::fromStdWString(humanSize(e.size)))
             << (e.isDir ? QStringLiteral("—")
                         : QString::fromStdWString(humanSize(e.packedSize)))
             << (e.isDir ? QStringLiteral("—") : QString::number(ratioPct) + "%")
             << QDateTime::fromSecsSinceEpoch(qint64(e.mtime))
                    .toString("yyyy-MM-dd HH:mm")
             << QString::fromStdWString(e.isDir ? L"D" : L"A")
             << QString::fromWCharArray(crc);
        auto* it = addRow(cols, e.isDir ? "edir" : "entry",
                          QString::fromStdWString(e.name));
        it->setIcon(0, style()->standardIcon(e.isDir ? QStyle::SP_DirIcon
                                                     : QStyle::SP_FileIcon));
    }
    setStatus();
}

void MainWindow::loadArchive(const std::wstring& path) {
    std::wstring password = m_password;
    ArchiveInfo info;
    std::string err;
    for (int attempt = 0; attempt < 3; ++attempt) {
        err = listArchive(path, password, info);
        if (err != "password required") break;
        bool ok = false;
        QString pw = QInputDialog::getText(
            this, tr("Password"), tr("This archive is encrypted.\nEnter password:"),
            QLineEdit::Password, QString(), &ok);
        if (!ok) return;
        password = pw.toStdWString();
    }
    if (!err.empty()) {
        QMessageBox::warning(this, tr("Open archive"), QString::fromStdString(err));
        return;
    }
    // data-encrypted archives list fine but need the password for operations
    bool anyEnc = false;
    for (auto& e : info.entries)
        if (e.encrypted) anyEnc = true;
    if (anyEnc && password.empty()) {
        bool ok = false;
        QString pw = QInputDialog::getText(
            this, tr("Password"),
            tr("This archive contains encrypted files.\nEnter password:"),
            QLineEdit::Password, QString(), &ok);
        if (ok) password = pw.toStdWString();
    }
    m_password = password;
    m_info = info;
    m_path = QDir::toNativeSeparators(QString::fromStdWString(path));
    m_address->setText(m_path);
    refreshArchive();

    m_recent.removeAll(m_path);
    m_recent.prepend(m_path);
    while (m_recent.size() > 10) m_recent.removeLast();
    QSettings().setValue("recent", m_recent);
}

void MainWindow::closeArchive() {
    QString dir = QFileInfo(m_path).absolutePath();
    m_info = ArchiveInfo{};
    m_password.clear();
    setPath(dir);
    refreshBrowse();
}

// ------------------------------------------------------------------ helpers
std::vector<std::wstring> MainWindow::selectedBrowsePaths() const {
    std::vector<std::wstring> out;
    for (auto* it : m_tree->selectedItems())
        out.push_back(it->data(0, kRolePath).toString().toStdWString());
    return out;
}

std::vector<std::wstring> MainWindow::selectedEntryNames() const {
    std::vector<std::wstring> out;
    for (auto* it : m_tree->selectedItems()) {
        QString kind = it->data(0, kRoleKind).toString();
        if (kind == "entry" || kind == "edir")
            out.push_back(it->data(0, kRolePath).toString().toStdWString());
    }
    return out;
}

void MainWindow::setStatus() {
    uint64_t selBytes = 0;
    int selCount = m_tree->selectionModel() ? int(m_tree->selectionModel()->selectedRows().size()) : 0;
    if (m_mode == Mode::ArchiveView) {
        for (auto* it : m_tree->selectedItems()) {
            QString name = it->data(0, kRolePath).toString();
            for (auto& e : m_info.entries)
                if (QString::fromStdWString(e.name) == name && !e.isDir)
                    selBytes += e.size;
        }
        m_statusSel->setText(tr("Selected %1 file(s), %2 bytes")
                                 .arg(selCount)
                                 .arg(QString::fromStdWString(humanSize(selBytes))));
        m_statusTotal->setText(tr("Total %1 files, %2 bytes")
                                   .arg(int(m_info.entries.size()))
                                   .arg(QString::fromStdWString(humanSize(
                                       m_info.totalOriginal))));
        m_statusDict->setText(tr("Dictionary: %1")
                                  .arg(QString::fromStdWString(humanSize(
                                      m_info.dictSize))));
    } else {
        int total = m_tree->topLevelItemCount();
        m_statusSel->setText(tr("Selected %1 file(s)").arg(selCount));
        m_statusTotal->setText(tr("Total %1 items").arg(total));
        m_statusDict->setText("");
    }
}

void MainWindow::runJob(const QString& title, uint64_t dictSize,
                        std::function<std::string(ProgressDialog&)> job,
                        const std::function<void()>& onSuccess) {
    auto* dlg = new ProgressDialog(this);
    if (dictSize) dlg->setDictLabel(dictSize);
    dlg->setWindowTitle(title);
    bool ok = dlg->execJob(job);
    dlg->deleteLater();
    if (ok && onSuccess) onSuccess();
}

// ------------------------------------------------------------------ actions
void MainWindow::onOpenArchive() {
    QString f = QFileDialog::getOpenFileName(
        this, tr("Open archive"), currentDir(),
        tr("Archives (*.wrc *.zip *.7z *.rar *.001);;All files (*.*)"));
    if (f.isEmpty()) return;
    loadArchive(QDir::toNativeSeparators(f).toStdWString());
}

void MainWindow::onBrowseFolder() {
    QString d = QFileDialog::getExistingDirectory(this, tr("Browse folder"), currentDir());
    if (d.isEmpty()) return;
    setPath(d);
    refreshBrowse();
}

void MainWindow::onAdd() {
    if (m_mode == Mode::ArchiveView) {
        // append files to the open archive
        QStringList files = QFileDialog::getOpenFileNames(this, tr("Add files"),
                                                          currentDir());
        if (files.isEmpty()) return;
        std::vector<std::wstring> inputs;
        for (auto& f : files) inputs.push_back(f.toStdWString());
        QString archive = m_path;
        std::wstring pw = m_password;
        runJob(tr("Adding files…"), m_info.dictSize,
               [archive, inputs, pw](ProgressDialog& d) {
                   return appendFiles(archive.toStdWString(), pw, inputs,
                                      [&](const Progress& p) {
                                          emit d.progressChanged(p);
                                      },
                                      [&] { return d.control(); });
               },
               [this] { loadArchive(m_path.toStdWString()); });
        return;
    }
    auto selected = selectedBrowsePaths();
    if (selected.empty()) {
        QMessageBox::information(this, tr("Add"),
                                 tr("Select files or folders to archive first."));
        return;
    }
    QStringList files;
    for (auto& p : selected) files << QString::fromStdWString(p);
    ArchiveOptions opt;
    if (!ArchiveDialog::getOptions(this, currentDir(), files, opt)) return;
    QString archive = QString::fromStdWString(opt.archivePath);
    runJob(tr("Creating archive…"), opt.dictSize,
           [opt, archive](ProgressDialog& d) {
               std::string err;
               try {
                   uint64_t ti = 0, to = 0;
                   createArchive(opt, nullptr,
                                 [&](const Progress& p) { emit d.progressChanged(p); },
                                 [&] { return d.control(); }, ti, to);
               } catch (const CancelledError&) {
                   return std::string("__cancelled__");
               } catch (const std::exception& ex) {
                   return std::string(ex.what());
               }
               return std::string();
           },
           [this, archive] { loadArchive(archive.toStdWString()); });
}

void MainWindow::onExtractTo() {
    if (m_mode != Mode::ArchiveView) return;
    auto sel = selectedEntryNames();
    ExtractDialog dlg(this, m_path, currentDir());
    if (dlg.exec() != QDialog::Accepted) return;
    QString dest = dlg.destination();
    std::wstring password = dlg.password().toStdWString();
    if (password.empty()) password = m_password;
    QString archive = m_path;
    bool openIt = dlg.openAfter();
    runJob(tr("Extracting…"), m_info.dictSize,
           [archive, dest, password, sel](ProgressDialog& d) {
               try {
                   std::vector<std::wstring> files;
                   std::string err = extractArchive(
                       archive.toStdWString(), dest.toStdWString(), password,
                       [&](const Progress& p) { emit d.progressChanged(p); },
                       [&] { return d.control(); }, &files);
                   return err;
               } catch (const CancelledError&) {
                   return std::string("__cancelled__");
               } catch (const std::exception& ex) {
                   return std::string(ex.what());
               }
           },
           [dest, openIt] {
               if (openIt) QDesktopServices::openUrl(QUrl::fromLocalFile(dest));
           });
}

void MainWindow::onTest() {
    if (m_mode != Mode::ArchiveView) return;
    QString archive = m_path;
    std::wstring pw = m_password;
    int bad = -1;
    runJob(tr("Testing archive…"), m_info.dictSize,
           [archive, &bad, pw](ProgressDialog& d) -> std::string {
               try {
                   std::string err = testArchive(
                       archive.toStdWString(), pw,
                       [&](const Progress& p) { emit d.progressChanged(p); },
                       [&] { return d.control(); }, bad);
                   if (!err.empty()) return err;
               } catch (const CancelledError&) {
                   return "__cancelled__";
               }
               return std::string();
           },
           [this, &bad] {
               if (bad < 0) return;
               if (bad == 0)
                   QMessageBox::information(this, tr("Test"), tr("All files are OK"));
               else
                   QMessageBox::warning(this, tr("Test"),
                                        tr("%1 file(s) failed").arg(bad));
           });
}

void MainWindow::onView() {
    if (m_mode != Mode::ArchiveView) return;
    auto sel = selectedEntryNames();
    if (sel.empty() || sel[0].empty()) return;
    std::wstring name = sel[0];
    std::wstring archive = m_path.toStdWString();
    std::wstring tempDir =
        QStandardPaths::writableLocation(QStandardPaths::TempLocation).toStdWString();
    std::vector<std::wstring> files;
    std::string err;
    try {
        if (detectFormat(archive) == Format::Wsar) {
            err.clear();
            std::vector<std::wstring> out;
            if (!wsar::extract(archive, tempDir, m_password, {name}, nullptr,
                               [] { return true; }, out, err))
                err = "extract failed";
            files = out;
        } else {
            err = extractArchive(archive, tempDir, m_password, nullptr,
                                 [] { return true; }, &files);
        }
    } catch (const std::exception& ex) {
        err = ex.what();
    }
    if (!err.empty()) {
        QMessageBox::warning(this, tr("View"), QString::fromStdString(err));
        return;
    }
    for (auto& f : files) {
        std::wstring base = fileNameOf(f);
        std::wstring want = name.substr(name.find_last_of(L'/') + 1);
        if (base == want) {
            ShellExecuteW(nullptr, L"open", toExtendedPath(f).c_str(), nullptr,
                          nullptr, SW_SHOWNORMAL);
            return;
        }
    }
}

void MainWindow::onDelete() {
    if (m_mode == Mode::ArchiveView) {
        auto sel = selectedEntryNames();
        if (sel.empty()) return;
        if (QMessageBox::question(this, tr("Delete"),
                                  tr("Delete %1 entries from the archive?").arg(int(sel.size()))) !=
            QMessageBox::Yes)
            return;
        QString archive = m_path;
        std::wstring pw = m_password;
        runJob(tr("Deleting…"), m_info.dictSize,
               [archive, sel, pw](ProgressDialog& d) {
                   return deleteEntries(archive.toStdWString(), pw, sel,
                                        [&](const Progress& p) {
                                            emit d.progressChanged(p);
                                        },
                                        [&] { return d.control(); });
               },
               [this] { loadArchive(m_path.toStdWString()); });
        return;
    }
    auto sel = selectedBrowsePaths();
    if (sel.empty()) return;
    if (QMessageBox::question(this, tr("Delete"),
                              tr("Move %1 item(s) to the Recycle Bin?").arg(int(sel.size()))) !=
        QMessageBox::Yes)
        return;
    for (auto& p : sel) deleteToRecycleBin(p);
    refreshBrowse();
}

void MainWindow::onInfo() {
    if (m_mode == Mode::ArchiveView) {
        auto sel = selectedEntryNames();
        QList<QPair<QString, QString>> rows;
        rows << QPair<QString, QString>(tr("Archive"), m_path);
        rows << QPair<QString, QString>(tr("Format"),
                                        m_info.format == Format::Zip     ? "ZIP"
                                        : m_info.format == Format::SevenZip ? "7Z"
                                                                            : "WSAR (RAR5-style)");
        rows << QPair<QString, QString>(tr("Dictionary"),
                                        QString::fromStdWString(humanSize(m_info.dictSize)));
        rows << QPair<QString, QString>(
            tr("Total"), QString::fromStdWString(humanSize(m_info.totalOriginal) + L" → " +
                                                 humanSize(m_info.totalPacked)));
        if (!sel.empty()) {
            for (auto& e : m_info.entries) {
                if (QString::fromStdWString(e.name) != QString::fromStdWString(sel[0]))
                    continue;
                wchar_t crc[16] = L"";
                if (!e.isDir) swprintf(crc, 16, L"%08X", e.crc32);
                rows << QPair<QString, QString>(tr("Name"), QString::fromStdWString(e.name));
                rows << QPair<QString, QString>(tr("Size"),
                                                QString::fromStdWString(humanSize(e.size)));
                rows << QPair<QString, QString>(
                    tr("Packed"), QString::fromStdWString(humanSize(e.packedSize)));
                rows << QPair<QString, QString>(tr("CRC32"), QString::fromWCharArray(crc));
                rows << QPair<QString, QString>(
                    tr("Modified"),
                    QDateTime::fromSecsSinceEpoch(qint64(e.mtime)).toString());
                rows << QPair<QString, QString>(
                    tr("Encrypted"), e.encrypted ? tr("AES-256") : tr("no"));
            }
        }
        InfoDialog(this, tr("Archive information"), rows).exec();
        return;
    }
    auto sel = selectedBrowsePaths();
    if (sel.empty()) return;
    QFileInfo fi(QString::fromStdWString(sel[0]));
    QList<QPair<QString, QString>> rows;
    rows << QPair<QString, QString>(tr("Name"), fi.fileName());
    rows << QPair<QString, QString>(tr("Size"),
                                    QString::fromStdWString(humanSize(uint64_t(fi.size()))));
    rows << QPair<QString, QString>(tr("Modified"), fi.lastModified().toString());
    rows << QPair<QString, QString>(tr("Path"), fi.absoluteFilePath());
    InfoDialog(this, tr("File information"), rows).exec();
}

void MainWindow::onRepair() {
    if (m_mode != Mode::ArchiveView) return;
    QString archive = m_path;
    std::wstring pw = m_password;
    int kept = -1, dropped = -1;
    runJob(tr("Repairing archive…"), m_info.dictSize,
           [archive, &kept, &dropped, pw](ProgressDialog& d) -> std::string {
               try {
                   std::string err = repairArchive(
                       archive.toStdWString(), pw,
                       [&](const Progress& p) { emit d.progressChanged(p); },
                       [&] { return d.control(); }, kept, dropped);
                   if (!err.empty()) return err;
               } catch (const CancelledError&) {
                   return "__cancelled__";
               }
               return std::string();
           },
           [this, &kept, &dropped] {
               if (kept >= 0)
                   QMessageBox::information(this, tr("Repair"),
                                            tr("Kept %1 entries, dropped %2")
                                                .arg(kept)
                                                .arg(dropped));
               loadArchive(m_path.toStdWString());
           });
}

// --------------------------------------------------------------- navigation
void MainWindow::onUp() {
    if (m_mode == Mode::ArchiveView) {
        closeArchive();
        return;
    }
    QDir d(m_path);
    if (d.cdUp()) {
        setPath(d.absolutePath());
        refreshBrowse();
    }
}

void MainWindow::onAddressActivated() {
    QString p = QDir::toNativeSeparators(QDir::cleanPath(m_address->text()));
    if (isArchiveFile(p.toStdWString()) && QFile::exists(p)) {
        loadArchive(p.toStdWString());
        return;
    }
    if (QDir(p).exists()) {
        setPath(p);
        refreshBrowse();
        return;
    }
    QMessageBox::warning(this, tr("Path"), tr("Path does not exist."));
}

void MainWindow::onItemActivated(QTreeWidgetItem* it, int) {
    QString kind = it->data(0, kRoleKind).toString();
    if (kind == "dir") {
        setPath(it->data(0, kRolePath).toString());
        refreshBrowse();
        return;
    }
    if (kind == "file") {
        QString p = it->data(0, kRolePath).toString();
        if (isArchiveFile(p.toStdWString())) {
            loadArchive(p.toStdWString());
            return;
        }
        ShellExecuteW(nullptr, L"open", toExtendedPath(p.toStdWString()).c_str(),
                      nullptr, nullptr, SW_SHOWNORMAL);
        return;
    }
    // archive entry → view
    onView();
}

void MainWindow::onSelectionChanged() { setStatus(); }

void MainWindow::onSelectAll() { m_tree->selectAll(); }

void MainWindow::onInvertSelection() {
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) {
        auto* it = m_tree->topLevelItem(i);
        it->setSelected(!it->isSelected());
    }
}

void MainWindow::onContextMenu(const QPoint& pos) {
    QMenu menu(this);
    menu.addAction(m_actAdd);
    menu.addAction(m_actExtract);
    menu.addAction(m_actTest);
    menu.addAction(m_actView);
    menu.addSeparator();
    menu.addAction(m_actDelete);
    menu.addAction(m_actInfo);
    menu.addAction(m_actRepair);
    menu.exec(m_tree->viewport()->mapToGlobal(pos));
}

void MainWindow::onToggleShell() {
    QAction* a = qobject_cast<QAction*>(sender());
    if (!a) return;
    if (a->isChecked())
        shell::integrate();
    else
        shell::unintegrate();
    QMessageBox::information(this, tr("Shell integration"),
                             tr("Windows Explorer context menu updated."));
}

void MainWindow::onAbout() {
    QMessageBox::about(
        this, tr("About"),
        tr("<b>WinRAR Clone Engine 7.0.0</b><br>"
           "Open-source clone of the classic WinRAR 7.0 workflow.<br><br>"
           "• Formats: WSAR (RAR5-style) / ZIP / 7Z + extraction via libarchive<br>"
           "• Dictionaries up to 64 GB with RAM safety checks<br>"
           "• AES-256 encryption, encrypted file names<br>"
           "• Long paths up to 65,535 chars (\\\\?\\)<br>"
           "• Mark-of-the-Web propagation on extraction<br>"
           "• Non-blocking multithreaded compression<br><br>"
           "MIT License — see repository for details."));
}

// ---------------------------------------------------------------- drag&drop
void MainWindow::dragEnterEvent(QDragEnterEvent* ev) {
    if (ev->mimeData()->hasUrls()) ev->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* ev) {
    QStringList files;
    for (const QUrl& u : ev->mimeData()->urls()) {
        QString p = u.toLocalFile();
        if (!p.isEmpty()) files << QDir::toNativeSeparators(p);
    }
    if (files.isEmpty()) return;
    // dropping an archive opens it; otherwise treat as "add"
    if (files.size() == 1 && isArchiveFile(files[0].toStdWString()) &&
        m_mode == Mode::Browse) {
        loadArchive(files[0].toStdWString());
        return;
    }
    if (m_mode == Mode::ArchiveView) {
        std::vector<std::wstring> inputs;
        for (auto& f : files) inputs.push_back(f.toStdWString());
        QString archive = m_path;
        std::wstring pw = m_password;
        runJob(tr("Adding files…"), m_info.dictSize,
               [archive, inputs, pw](ProgressDialog& d) {
                   return appendFiles(archive.toStdWString(), pw, inputs,
                                      [&](const Progress& p) {
                                          emit d.progressChanged(p);
                                      },
                                      [&] { return d.control(); });
               },
               [this] { loadArchive(m_path.toStdWString()); });
        return;
    }
    ArchiveOptions opt;
    if (!ArchiveDialog::getOptions(this, currentDir(), files, opt)) return;
    QString archive = QString::fromStdWString(opt.archivePath);
    runJob(tr("Creating archive…"), opt.dictSize,
           [opt](ProgressDialog& d) {
               try {
                   uint64_t ti = 0, to = 0;
                   createArchive(opt, nullptr,
                                 [&](const Progress& p) { emit d.progressChanged(p); },
                                 [&] { return d.control(); }, ti, to);
               } catch (const CancelledError&) {
                   return std::string("__cancelled__");
               } catch (const std::exception& ex) {
                   return std::string(ex.what());
               }
               return std::string();
           },
           [this, archive] { loadArchive(archive.toStdWString()); });
}
