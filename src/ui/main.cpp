// main.cpp — WinRAR Clone GUI entry point
#include "ui/main_window.h"

#include <QtWidgets/QApplication>

#include <string>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("WinRAR Clone Engine");
    QApplication::setOrganizationName("WinRARClone");
    QApplication::setApplicationVersion("7.0.0");
    qRegisterMetaType<wrc::Progress>("wrc::Progress");

    MainWindow win;
    win.show();
    return app.exec();
}
