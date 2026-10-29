import Foundation

enum ChatTimelineDateComponent: CaseIterable {
    case year
    case month
    case day
}

/// Calendar days, rather than 86,400-second offsets, keep scrubbing correct across DST.
struct ChatTimelineDateSelection {
    let calendar: Calendar
    let minimumDate: Date
    let maximumDate: Date
    private(set) var date: Date

    init(initialDate: Date, minimumDate: Date, maximumDate: Date, timeZone: TimeZone, now: Date = Date()) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        self.calendar = calendar
        let upperBound = min(calendar.startOfDay(for: maximumDate), calendar.startOfDay(for: now))
        let lowerBound = min(calendar.startOfDay(for: minimumDate), upperBound)
        self.minimumDate = lowerBound
        self.maximumDate = upperBound
        self.date = min(upperBound, max(lowerBound, calendar.startOfDay(for: initialDate)))
    }

    func value(for component: ChatTimelineDateComponent) -> Int {
        return self.calendar.component(self.calendarComponent(component), from: self.date)
    }

    func availableValues(for component: ChatTimelineDateComponent) -> ClosedRange<Int> {
        let lower = self.calendar.dateComponents([.year, .month, .day], from: self.minimumDate)
        let upper = self.calendar.dateComponents([.year, .month, .day], from: self.maximumDate)
        let current = self.calendar.dateComponents([.year, .month, .day], from: self.date)
        switch component {
        case .year:
            return (lower.year ?? 2013)...(upper.year ?? 2013)
        case .month:
            let first = current.year == lower.year ? (lower.month ?? 1) : 1
            let last = current.year == upper.year ? (upper.month ?? 12) : 12
            return first...last
        case .day:
            let first = current.year == lower.year && current.month == lower.month ? (lower.day ?? 1) : 1
            let last: Int
            if current.year == upper.year && current.month == upper.month {
                last = upper.day ?? 1
            } else {
                last = self.calendar.range(of: .day, in: .month, for: self.date)?.count ?? 1
            }
            return first...last
        }
    }

    mutating func select(_ value: Int, component: ChatTimelineDateComponent) {
        let range = self.availableValues(for: component)
        let value = min(range.upperBound, max(range.lowerBound, value))
        var parts = self.calendar.dateComponents([.year, .month, .day], from: self.date)
        switch component {
        case .year:
            parts.year = value
        case .month:
            parts.month = value
        case .day:
            parts.day = value
        }
        let requestedDay = parts.day ?? 1
        parts.day = 1
        guard let monthStart = self.calendar.date(from: parts), let days = self.calendar.range(of: .day, in: .month, for: monthStart) else {
            return
        }
        parts.day = min(requestedDay, days.count)
        if let date = self.calendar.date(from: parts) {
            self.setDate(date)
        }
    }

    mutating func setDate(_ date: Date) {
        self.date = min(self.maximumDate, max(self.minimumDate, self.calendar.startOfDay(for: date)))
    }

    mutating func move(days: Int) {
        if let date = self.calendar.date(byAdding: .day, value: days, to: self.date) {
            self.setDate(date)
        }
    }

    func isSameDay(as date: Date) -> Bool {
        return self.calendar.isDate(self.date, inSameDayAs: date)
    }

    private func calendarComponent(_ component: ChatTimelineDateComponent) -> Calendar.Component {
        switch component {
        case .year:
            return .year
        case .month:
            return .month
        case .day:
            return .day
        }
    }
}
