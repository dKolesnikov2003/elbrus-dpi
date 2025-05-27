#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Create and show the main window
    MainWindow mainWin;
    mainWin.show();

    return app.exec();
}