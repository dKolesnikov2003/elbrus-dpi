#include "mainwindow.h"
#include "timedelegate.h"
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QTableView>
#include <QHeaderView>
#include <QSqlError>
#include <QDebug>
#include <QSqlQuery> 

// Constructor: set up UI and database connection
MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow(parent), model(nullptr), sortColumn(-1), sortOrder(Qt::AscendingOrder) {
    // Initialize the UI elements and layout
    setupUi();

    // Open the SQLite database (using default path from DPI config)
    db = QSqlDatabase::addDatabase("QSQLITE");
    // $HOME/.local/share/elbrus-dpi/packets.db
    QString dbPath = QString::fromUtf8("%1").arg(getenv("HOME")) + "/.local/share/elbrus-dpi/packets.db";
    db.setDatabaseName(dbPath);
    if (!db.open()) {
        qWarning() << "Failed to open database:" << db.lastError().text();
        // If database cannot be opened, handle error (for simplicity, we just print and disable UI)
    }

    // Create the query model for displaying data
    model = new QSqlQueryModel(this);

    // Populate session (table) list and select the first session by default
    loadSessionData();
    refreshTableView();                
    
    // Set up auto-refresh 1 second timer
    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(1000); 
    connect(refreshTimer, &QTimer::timeout,
            this, &MainWindow::autoRefresh);
    refreshTimer->start();
}

// Destructor
MainWindow::~MainWindow() {
    db.close();
}

// Set up UI components and layout
void MainWindow::setupUi() {
    this->setWindowTitle(QString::fromUtf8("DPI Analysis Viewer"));

    // Central widget and main layout
    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);

    // --- Top controls panel ---
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    controlsLayout->setSpacing(8);

    // Session selector
    QLabel *sessionLabel = new QLabel(QString::fromUtf8("Сессия:"), central);
    QComboBox *sessionCombo = new QComboBox(central);
    sessionCombo->setMinimumWidth(200);
    controlsLayout->addWidget(sessionLabel);
    controlsLayout->addWidget(sessionCombo);

    // IP filter
    QLabel *ipLabel = new QLabel(QString::fromUtf8("Фильтр по IP:"), central);
    QLineEdit *ipEdit = new QLineEdit(central);
    ipEdit->setPlaceholderText(QString::fromUtf8("напр., 192.168"));
    ipEdit->setMinimumWidth(100);
    controlsLayout->addWidget(ipLabel);
    controlsLayout->addWidget(ipEdit);

    // Port filter
    QLabel *portLabel = new QLabel(QString::fromUtf8("Фильтр по порту:"), central);
    QLineEdit *portEdit = new QLineEdit(central);
    portEdit->setPlaceholderText(QString::fromUtf8("напр., 80"));
    portEdit->setMaximumWidth(80);
    controlsLayout->addWidget(portLabel);
    controlsLayout->addWidget(portEdit);

    // Protocol filter
    QLabel *protoLabel = new QLabel(QString::fromUtf8("Фильтр по протоколу:"), central);
    QLineEdit *protoEdit = new QLineEdit(central);
    protoEdit->setPlaceholderText(QString::fromUtf8("напр., HTTP"));
    protoEdit->setMinimumWidth(100);
    controlsLayout->addWidget(protoLabel);
    controlsLayout->addWidget(protoEdit);

    // Apply filter button
    QPushButton *applyBtn = new QPushButton(QString::fromUtf8("Применить"), central);
    controlsLayout->addWidget(applyBtn);

    // Add the controls panel to the main layout
    mainLayout->addLayout(controlsLayout);

    // --- Table view for results ---
    QTableView *tableView = new QTableView(central);
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);  // read-only
    tableView->setAlternatingRowColors(true);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    tableView->setSortingEnabled(true);  // allow sorting by clicking column headers
    tableView->horizontalHeader()->setStretchLastSection(true);  // last column fills space
    mainLayout->addWidget(tableView);

    // Set central widget and layout
    this->setCentralWidget(central);
    central->setLayout(mainLayout);

    // --- Connect signals to slots ---
    // Session change -> onSessionChanged
    connect(sessionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onSessionChanged);
    // Apply button -> applyFilters
    connect(applyBtn, &QPushButton::clicked, this, &MainWindow::applyFilters);
    // Also allow pressing Enter in filter fields to trigger filter
    connect(ipEdit, &QLineEdit::returnPressed, this, &MainWindow::applyFilters);
    connect(portEdit, &QLineEdit::returnPressed, this, &MainWindow::applyFilters);
    connect(protoEdit, &QLineEdit::returnPressed, this, &MainWindow::applyFilters);
    // Header click -> sorting slot
    connect(tableView->horizontalHeader(), &QHeaderView::sectionClicked,
            this, &MainWindow::onHeaderClicked);

    // Store pointers to UI elements in local variables or as members if needed
    // (For simplicity, we capture these via lambdas or use [=] in slot lambdas if needed)
    // Here we'll capture via member variables for filter fields and session combo:
    // Actually, to keep things simple, we'll retrieve values directly from widgets when needed in applyFilters() etc.
    // Alternatively, make ipEdit, portEdit, protoEdit, sessionCombo as static locals here or class members.

    // For clarity in this example, let's promote these QLineEdit and QComboBox to be accessible in slots:
    ipEdit->setObjectName("ipEdit");
    portEdit->setObjectName("portEdit");
    protoEdit->setObjectName("protoEdit");
    sessionCombo->setObjectName("sessionCombo");
    tableView->setObjectName("tableView");
}

// Populate the session list combo box with available tables
void MainWindow::loadSessionData() {
    QComboBox *sessionCombo = this->findChild<QComboBox*>("sessionCombo");
    if (!sessionCombo) return;
    sessionCombo->clear();
    currentTable.clear();

    if (!db.isOpen()) {
        return;
    }

    // Query SQLite for all user tables in the database
    QSqlQuery q(db);
    // We'll get all table names from sqlite_master excluding SQLite's internal tables
    q.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';");
    QStringList tables;
    while (q.next()) {
        QString tname = q.value(0).toString();
        tables << tname;
    }
    tables.sort(); // sort alphabetically (optional, to make selection easier)
    sessionCombo->addItems(tables);

    if (!tables.isEmpty()) {
        // Select the first table by default
        sessionCombo->setCurrentIndex(0);
        currentTable = tables.first();
        // Load data from the first session by default
        refreshTableView();
    }
}

// Called when session selection changes
void MainWindow::onSessionChanged(int index) {
    QComboBox *sessionCombo = this->findChild<QComboBox*>("sessionCombo");
    if (!sessionCombo) return;
    QString selectedTable = sessionCombo->currentText();
    if (selectedTable.isEmpty()) return;

    // Update current table and reset filters
    currentTable = selectedTable;
    filterIP.clear();
    filterPort.clear();
    filterProto.clear();
    sortColumn = -1;
    sortOrder = Qt::AscendingOrder;
    // Optionally, also clear the filter input fields in the UI:
    QLineEdit *ipEdit = this->findChild<QLineEdit*>("ipEdit");
    QLineEdit *portEdit = this->findChild<QLineEdit*>("portEdit");
    QLineEdit *protoEdit = this->findChild<QLineEdit*>("protoEdit");
    if (ipEdit) ipEdit->clear();
    if (portEdit) portEdit->clear();
    if (protoEdit) protoEdit->clear();

    refreshTableView();
}

// Gather filter inputs and refresh the table view
void MainWindow::applyFilters() {
    // Get filter values from input fields
    QLineEdit *ipEdit = this->findChild<QLineEdit*>("ipEdit");
    QLineEdit *portEdit = this->findChild<QLineEdit*>("portEdit");
    QLineEdit *protoEdit = this->findChild<QLineEdit*>("protoEdit");
    if (ipEdit) filterIP = ipEdit->text().trimmed();
    if (portEdit) filterPort = portEdit->text().trimmed();
    if (protoEdit) filterProto = protoEdit->text().trimmed();

    // After changing filters, we typically reset sort or keep current sort? 
    // We'll keep current sort as is (so user’s chosen sort remains).
    // Just refresh the data with new WHERE clause.
    refreshTableView();
}

// Handle header clicks for sorting
void MainWindow::onHeaderClicked(int section) {
    // If the same column is clicked again, toggle the sort order, otherwise sort ascending on new column.
    if (sortColumn == section) {
        // toggle order
        sortOrder = (sortOrder == Qt::AscendingOrder ? Qt::DescendingOrder : Qt::AscendingOrder);
    } else {
        sortColumn = section;
        sortOrder = Qt::AscendingOrder;
    }
    refreshTableView();
}

void MainWindow::autoRefresh()
{
    refreshTableView();
}

// Compose and execute the SQL query based on current table, filters, and sorting
void MainWindow::refreshTableView() {
    if (currentTable.isEmpty() || !db.isOpen() || !model) return;

    // Start building the query string
    QString queryStr = QString("SELECT timestamp_ms, src_addr, dst_addr, src_port, dst_port, packet_length, protocol_name "
                               "FROM \"%1\"").arg(currentTable);
    // Apply filters (WHERE clause)
    QStringList conditions;
    if (!filterIP.isEmpty()) {
        // Escape single quotes in filter string to prevent SQL injection (basic handling)
        QString ipEsc = filterIP;
        ipEsc.replace("'", "''");
        conditions << QString("(src_addr LIKE '%%1%' OR dst_addr LIKE '%%1%')").arg(ipEsc);
    }
    if (!filterPort.isEmpty()) {
        bool ok;
        int portVal = filterPort.toInt(&ok);
        if (ok) {
            conditions << QString("(src_port = %1 OR dst_port = %1)").arg(portVal);
        } else {
            // If port filter is not a valid number, ignore it (or we could treat as no results).
            // Here we ignore non-numeric port filter.
        }
    }
    if (!filterProto.isEmpty()) {
        QString protoEsc = filterProto;
        protoEsc.replace("'", "''");
        conditions << QString("protocol_name LIKE '%%1%'").arg(protoEsc);
    }
    if (!conditions.isEmpty()) {
        queryStr += " WHERE " + conditions.join(" AND ");
    }

    // Apply sorting (ORDER BY clause)
    if (sortColumn >= 0) {
        // We need to map the sortColumn index to actual column name in query:
        // Our SELECT columns order is:
        // 0: timestamp_ms, 1: src_addr, 2: dst_addr, 3: src_port, 4: dst_port, 5: packet_length, 6: protocol_name
        QString colName;
        switch (sortColumn) {
            case 0: colName = "timestamp_ms"; break;
            case 1: colName = "src_addr"; break;
            case 2: colName = "dst_addr"; break;
            case 3: colName = "src_port"; break;
            case 4: colName = "dst_port"; break;
            case 5: colName = "packet_length"; break;
            case 6: colName = "protocol_name"; break;
            default: colName.clear(); break;
        }
        if (!colName.isEmpty()) {
            queryStr += QString(" ORDER BY %1 %2")
                           .arg(colName)
                           .arg(sortOrder == Qt::AscendingOrder ? "ASC" : "DESC");
        }
    }

    queryStr += ";";
    // Execute the query
    model->setQuery(queryStr, db);
    if (model->lastError().isValid()) {
        qWarning() << "SQL error:" << model->lastError().text();
    }

    // Set model headers to user-friendly names (in Russian, as desired)
    model->setHeaderData(0, Qt::Horizontal, QString::fromUtf8("Время"));
    model->setHeaderData(1, Qt::Horizontal, QString::fromUtf8("Источник (IP)"));
    model->setHeaderData(2, Qt::Horizontal, QString::fromUtf8("Назначение (IP)"));
    model->setHeaderData(3, Qt::Horizontal, QString::fromUtf8("Порт источника"));
    model->setHeaderData(4, Qt::Horizontal, QString::fromUtf8("Порт назначения"));
    model->setHeaderData(5, Qt::Horizontal, QString::fromUtf8("Размер"));
    model->setHeaderData(6, Qt::Horizontal, QString::fromUtf8("Протокол"));

    // Attach model to the view and set up delegate for timestamp formatting
    QTableView *tableView = this->findChild<QTableView*>("tableView");
    if (tableView) {
        tableView->setModel(model);
        // Hide vertical header (row numbers) for cleaner look
        tableView->verticalHeader()->setVisible(false);
        // Set a delegate to display timestamp in human-readable format
        TimeDelegate *timeDel = new TimeDelegate(tableView);
        tableView->setItemDelegateForColumn(0, timeDel);
        // Resize columns to content (optional)
        tableView->resizeColumnsToContents();
    }
}