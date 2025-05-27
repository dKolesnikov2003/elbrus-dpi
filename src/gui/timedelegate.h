#ifndef TIMEDELEGATE_H
#define TIMEDELEGATE_H

#include <QStyledItemDelegate>
#include <QDateTime>

class TimeDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    TimeDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

    // Convert timestamp (ms since epoch) to human-readable string
    QString displayText(const QVariant &value, const QLocale &locale) const override {
        if (value.type() == QVariant::LongLong || value.type() == QVariant::ULongLong) {
            qint64 ms = value.toLongLong();
            QDateTime dt = QDateTime::fromMSecsSinceEpoch(ms);
            return dt.toString("yyyy-MM-dd HH:mm:ss");
        }
        // Fallback for other types (just use default)
        return QStyledItemDelegate::displayText(value, locale);
    }
};

#endif // TIMEDELEGATE_H