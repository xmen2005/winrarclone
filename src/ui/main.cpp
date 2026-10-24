// main.cpp - WinRAR Clone GUI entry point
#include "ui/main_window.h"
#include "ui/progress_dialog.h"

#include "core/common.h"
#include "core/compressor.h"
#include "core/decompressor.h"
#include "utils/file_system.h"

#include <QtWidgets/QApplication>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QDesktopServices>
#include <QUrl>

#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

static bool isCliVerb(const std::wstring& s) {
    return s == L"add" || s == L"a" || s == L"x" || s == L"e" || s == L"t" ||
           s == L"l" || s == L"r" || s == L"d";
}

// Parse a simple -o / -p out of argv (for the extract verb).
static void parseExtractArgs(int n, wchar_t** wargv, std::wstring& out, std::wstring& pass) {
    for (int i = 3; i < n; ++i) {
        std::wstring a = wargv[i];
        if (a == L"-o" && i + 1 < n) { out = wargv[++i]; }
        else if (a == L"-p" && i + 1 < n) { pass = wargv[++i]; }
    }
}

int main(int argc, char** argv) {
    int n = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &n);

    // Context-menu / command-line verb handling with a progress UI.
    if (n > 1 && isCliVerb(wargv[1])) {
        QApplication app(argc, argv);
        QApplication::setApplicationName("WinRAR Clone Engine");
        QApplication::setOrganizationName("WinRARClone");
        QApplication::setApplicationVersion("7.0.0");
        qRegisterMetaType<wrc::Progress>("wrc::Progress");

        std::wstring verb = wargv[1];

        if (verb == L"add" || verb == L"a") {
            if (n < 3) {
                QMessageBox::warning(nullptr, "WinRAR Clone", "Usage: add <path>");
                LocalFree(wargv);
                return 2;
            }
            std::wstring path = wargv[2];
            wrc::ArchiveOptions opt;
            opt.archivePath = wrc::directoryOf(path) + L"\\" + wrc::fileNameOf(path) + L".wrc";
            opt.inputs.push_back(path);

            ProgressDialog dlg(nullptr);
            dlg.setWindowTitle("Creating archive...");
            dlg.setDictLabel(opt.dictSize);
            bool ok = dlg.execJob([&](ProgressDialog& d) -> std::string {
                try {
                    uint64_t ti = 0, to = 0;
                    wrc::createArchive(opt, nullptr,
                                       [&](const wrc::Progress& p) { emit d.progressChanged(p); },
                                       [&] { return d.control(); }, ti, to);
                } catch (const wrc::CancelledError&) {
                    return std::string("__cancelled__");
                } catch (const std::exception& ex) {
                    return std::string(ex.what());
                }
                return std::string();
            });
            if (ok) {
                MainWindow win;
                win.openArchivePath(opt.archivePath);
                win.show();
                return app.exec();
            }
            LocalFree(wargv);
            return ok ? 0 : 1;
        }

        if (verb == L"x" || verb == L"e") {
            if (n < 3) {
                QMessageBox::warning(nullptr, "WinRAR Clone", "Usage: x <archive> [-o outdir] [-p pass]");
                LocalFree(wargv);
                return 2;
            }
            std::wstring archive = wargv[2];
            std::wstring out, pass;
            parseExtractArgs(n, wargv, out, pass);
            if (out.empty()) out = wrc::directoryOf(archive);

            // Prompt for password if the archive is encrypted.
            wrc::ArchiveInfo info;
            std::string lerr;
            if (wrc::listArchive(archive, pass, info) == "password required" ||
                (pass.empty() && info.encryptedNames)) {
                bool okpw = false;
                QString pw = QInputDialog::getText(nullptr, "Password",
                                                  "This archive is encrypted.\nEnter password:",
                                                  QLineEdit::Password, QString(), &okpw);
                if (okpw) pass = pw.toStdWString();
            }

            ProgressDialog dlg(nullptr);
            dlg.setWindowTitle("Extracting...");
            std::vector<std::wstring> extracted;
            bool ok = dlg.execJob([&](ProgressDialog& d) -> std::string {
                try {
                    return wrc::extractArchive(archive, out, pass,
                                               [&](const wrc::Progress& p) { emit d.progressChanged(p); },
                                               [&] { return d.control(); }, &extracted);
                } catch (const wrc::CancelledError&) {
                    return std::string("__cancelled__");
                } catch (const std::exception& ex) {
                    return std::string(ex.what());
                }
            });
            if (ok) {
                QDesktopServices::openUrl(QUrl::fromLocalFile(QString::fromStdWString(out)));
            }
            LocalFree(wargv);
            return ok ? 0 : 1;
        }

        if (verb == L"t") {
            if (n < 3) {
                QMessageBox::warning(nullptr, "WinRAR Clone", "Usage: t <archive> [-p pass]");
                LocalFree(wargv);
                return 2;
            }
            std::wstring archive = wargv[2];
            std::wstring pass;
            for (int i = 3; i < n; ++i) if (std::wstring(wargv[i]) == L"-p" && i + 1 < n) pass = wargv[++i];
            int bad = 0;
            ProgressDialog dlg(nullptr);
            dlg.setWindowTitle("Testing archive...");
            bool ok = dlg.execJob([&](ProgressDialog& d) -> std::string {
                try {
                    std::string err = wrc::testArchive(archive, pass,
                                                       [&](const wrc::Progress& p) { emit d.progressChanged(p); },
                                                       [&] { return d.control(); }, bad);
                    if (!err.empty()) return err;
                } catch (const wrc::CancelledError&) {
                    return std::string("__cancelled__");
                } catch (const std::exception& ex) {
                    return std::string(ex.what());
                }
                return std::string();
            });
            if (ok) {
                if (bad == 0) QMessageBox::information(nullptr, "WinRAR Clone", "All files are OK");
                else QMessageBox::warning(nullptr, "WinRAR Clone", QString("%1 file(s) failed").arg(bad));
            }
            LocalFree(wargv);
            return ok ? 0 : 1;
        }

        // Other verbs: fall back to normal GUI (no verb handling).
    }

    std::wstring openPath;
    if (n > 1) {
        std::wstring cand = wargv[1];
        if (wrc::isArchiveFile(cand)) openPath = cand;
    }
    LocalFree(wargv);

    QApplication app(argc, argv);
    QApplication::setApplicationName("WinRAR Clone Engine");
    QApplication::setOrganizationName("WinRARClone");
    QApplication::setApplicationVersion("7.0.0");
    qRegisterMetaType<wrc::Progress>("wrc::Progress");

    MainWindow win;
    win.show();
    if (!openPath.empty()) win.openArchivePath(openPath);
    return app.exec();
}