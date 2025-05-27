#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSqlQueryModel>
#include <QSqlDatabase>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void loadSessionData();       // Load data for the selected session (table)
    void applyFilters();          // Apply filter criteria and refresh view
    void onSessionChanged(int index); // Slot for when the session selection changes
    void onHeaderClicked(int section); // Slot for sorting when a header is clicked

private:
    void setupUi();               // Set up all UI widgets and layout
    void refreshTableView();      // Helper to (re)execute the SQL query and update model

    QSqlDatabase db;
    QSqlQueryModel *model;
    QString currentTable;         // Currently selected table name
    QString filterIP;
    QString filterPort;
    QString filterProto;
    int sortColumn;
    Qt::SortOrder sortOrder;
};
#endif