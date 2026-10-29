import Foundation

// Compiles the production Foundation-only date model without the app or a Telegram account.
// These checks do not validate the UIKit presentation or history integration.
@main
enum TimelineDateSelectionChecks {
    static var checks = 0

    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        checks += 1
        guard condition() else { fatalError("Chat Timeline date regression: \(message)") }
    }

    static func calendar(_ timeZone: TimeZone) -> Calendar {
        var result = Calendar(identifier: .gregorian)
        result.timeZone = timeZone
        return result
    }

    static func date(_ year: Int, _ month: Int, _ day: Int, _ zone: TimeZone, hour: Int = 0) -> Date {
        return calendar(zone).date(from: DateComponents(year: year, month: month, day: day, hour: hour))!
    }

    static func matches(_ selection: ChatTimelineDateSelection, _ year: Int, _ month: Int, _ day: Int) -> Bool {
        return selection.value(for: .year) == year && selection.value(for: .month) == month && selection.value(for: .day) == day
    }

    static func main() {
        let utc = TimeZone(secondsFromGMT: 0)!
        let now = date(2026, 10, 30, utc, hour: 12)
        let minimum = date(2013, 8, 14, utc)
        var selection = ChatTimelineDateSelection(initialDate: date(2024, 1, 31, utc), minimumDate: minimum, maximumDate: now, timeZone: utc, now: now)
        selection.select(2, component: .month)
        expect(matches(selection, 2024, 2, 29), "January 31 must clamp to leap February 29, not roll into March")
        selection.select(2025, component: .year)
        expect(matches(selection, 2025, 2, 28), "Changing the leap year must preserve February and clamp its day")
        selection.select(31, component: .day)
        expect(matches(selection, 2025, 2, 28), "Out-of-range day must remain in the displayed month")

        selection.setDate(minimum)
        expect(selection.availableValues(for: .year) == 2013...2026, "Year range must follow the supplied bounds")
        expect(selection.availableValues(for: .month) == 8...12, "First year cannot expose months before the history floor")
        expect(selection.availableValues(for: .day) == 14...31, "First month must begin at the history floor")
        selection.select(1, component: .month)
        expect(matches(selection, 2013, 8, 14), "Selecting before the lower month must not leave the valid range")
        selection.move(days: -1)
        expect(matches(selection, 2013, 8, 14), "Moving before the history floor must clamp")

        selection.setDate(now)
        expect(selection.availableValues(for: .month) == 1...10, "Current year must not expose future months")
        expect(selection.availableValues(for: .day) == 1...30, "Current month must not expose tomorrow")
        selection.select(12, component: .month)
        expect(matches(selection, 2026, 10, 30), "An out-of-range month must not advance into the future")
        selection.move(days: 1)
        expect(matches(selection, 2026, 10, 30), "Day scrubbing must stop at today")

        let future = date(2030, 1, 1, utc)
        let capped = ChatTimelineDateSelection(initialDate: future, minimumDate: minimum, maximumDate: future, timeZone: utc, now: now)
        expect(matches(capped, 2026, 10, 30), "Even a future server bound must not allow future selections")
        let invalidBounds = ChatTimelineDateSelection(initialDate: future, minimumDate: future, maximumDate: minimum, timeZone: utc, now: now)
        expect(invalidBounds.minimumDate == invalidBounds.maximumDate, "Reversed bounds must collapse safely rather than creating an invalid range")

        let losAngeles = TimeZone(identifier: "America/Los_Angeles")!
        let springStart = date(2024, 3, 10, losAngeles)
        var spring = ChatTimelineDateSelection(initialDate: springStart, minimumDate: date(2024, 1, 1, losAngeles), maximumDate: date(2025, 1, 1, losAngeles), timeZone: losAngeles, now: now)
        spring.move(days: 1)
        expect(matches(spring, 2024, 3, 11), "Spring DST must advance one calendar day")
        expect(spring.date.timeIntervalSince(springStart) == 23 * 3600, "Spring DST uses a 23-hour day, not a fixed 86400-second step")
        expect(calendar(losAngeles).component(.hour, from: spring.date) == 0, "Spring DST navigation must stay at local midnight")

        let fallStart = date(2024, 11, 3, losAngeles)
        var fall = ChatTimelineDateSelection(initialDate: fallStart, minimumDate: date(2024, 1, 1, losAngeles), maximumDate: date(2025, 1, 1, losAngeles), timeZone: losAngeles, now: now)
        fall.move(days: 1)
        expect(matches(fall, 2024, 11, 4), "Fall DST must advance one calendar day")
        expect(fall.date.timeIntervalSince(fallStart) == 25 * 3600, "Fall DST uses a 25-hour day")
        fall.move(days: -1)
        expect(fall.date == fallStart, "Calendar-day movement must be reversible across DST")

        let instant = date(2026, 10, 30, utc)
        let local = ChatTimelineDateSelection(initialDate: instant, minimumDate: minimum, maximumDate: future, timeZone: losAngeles, now: instant)
        expect(matches(local, 2026, 10, 29), "The same UTC instant must select the device-local date")
        expect(local.isSameDay(as: date(2026, 10, 29, losAngeles, hour: 23)), "Same-day matching must use the device timezone")
        expect(!local.isSameDay(as: date(2026, 10, 30, losAngeles)), "Adjacent local days must remain distinct")

        var singleDay = ChatTimelineDateSelection(initialDate: now, minimumDate: now, maximumDate: now, timeZone: utc, now: now)
        expect(singleDay.availableValues(for: .year) == 2026...2026, "Single-day history must permit a one-value year range")
        expect(singleDay.availableValues(for: .month) == 10...10, "Single-day history must permit a one-value month range")
        expect(singleDay.availableValues(for: .day) == 30...30, "Single-day history must permit a one-value day range")
        singleDay.move(days: -3000)
        expect(matches(singleDay, 2026, 10, 30), "Scrubbing a single-day history must not move its selection")

        print("Chat Timeline date selection: \(checks) production-model checks passed")
    }
}
