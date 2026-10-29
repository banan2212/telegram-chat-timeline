import Foundation
import UIKit
import AccountContext
import AsyncDisplayKit
import Display
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

struct ChatTimelinePreview {
    let messageId: EngineMessage.Id
    let timestamp: Int32
    let author: String
    let text: String
}

enum ChatTimelinePreviewResult {
    case message(ChatTimelinePreview)
    case unavailable
    case failed
}

/// Choosing a day only requests a preview. The owner moves history after explicit confirmation.
final class ChatTimelineController: ViewController {
    private let context: AccountContext
    private let loadPreview: (Date) -> Signal<ChatTimelinePreviewResult, NoError>
    private let openCalendar: () -> Void
    private let confirm: (ChatTimelinePreview) -> Void
    private let returnToReadingPosition: (() -> Void)?
    private var presentationData: PresentationData
    private var selection: ChatTimelineDateSelection
    private var component: ChatTimelineDateComponent = .month
    private var result: ChatTimelinePreviewResult?
    private var isLoading = true
    private var isClosing = false
    private var didAnimateIn = false
    private var generation = 0
    private var requestTimer: SwiftSignalKit.Timer?
    private let requestDisposable = MetaDisposable()
    private var presentationDisposable: Disposable?
    private var sheetView: ChatTimelineSheetView?

    init(
        context: AccountContext,
        initialDate: Date,
        minimumDate: Date,
        maximumDate: Date,
        timeZone: TimeZone,
        loadPreview: @escaping (Date) -> Signal<ChatTimelinePreviewResult, NoError>,
        openCalendar: @escaping () -> Void,
        confirm: @escaping (ChatTimelinePreview) -> Void,
        returnToReadingPosition: (() -> Void)? = nil
    ) {
        self.context = context
        self.loadPreview = loadPreview
        self.openCalendar = openCalendar
        self.confirm = confirm
        self.returnToReadingPosition = returnToReadingPosition
        self.presentationData = context.sharedContext.currentPresentationData.with { $0 }
        self.selection = ChatTimelineDateSelection(initialDate: initialDate, minimumDate: minimumDate, maximumDate: maximumDate, timeZone: timeZone)

        super.init(navigationBarPresentationData: nil)
        self.statusBar.statusBarStyle = .Ignore

        self.presentationDisposable = (context.sharedContext.presentationData
        |> deliverOnMainQueue).startStrict(next: { [weak self] data in
            guard let self else {
                return
            }
            self.presentationData = data
            self.updateView()
        })
    }

    required init(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        self.requestTimer?.invalidate()
        self.requestDisposable.dispose()
        self.presentationDisposable?.dispose()
    }

    override func loadDisplayNode() {
        self.displayNode = ASDisplayNode()
        let sheetView = ChatTimelineSheetView(presentationData: self.presentationData, selection: self.selection, hasReturn: self.returnToReadingPosition != nil)
        self.sheetView = sheetView
        self.displayNode.view.addSubview(sheetView)
        sheetView.cancel = { [weak self] in
            self?.dismiss()
        }
        sheetView.componentChanged = { [weak self] component in
            guard let self, !self.isClosing else {
                return
            }
            self.component = component
            self.updateView()
        }
        sheetView.valueChanged = { [weak self] value in
            guard let self, !self.isClosing else {
                return
            }
            let previous = self.selection.date
            self.selection.select(value, component: self.component)
            if previous != self.selection.date {
                self.schedulePreview()
            }
        }
        sheetView.moveDay = { [weak self] days in
            guard let self, !self.isClosing else {
                return
            }
            let previous = self.selection.date
            self.selection.move(days: days)
            if previous != self.selection.date {
                self.schedulePreview()
            }
        }
        sheetView.retry = { [weak self] in
            self?.schedulePreview(immediately: true)
        }
        sheetView.jump = { [weak self] in
            guard let self, !self.isClosing, !self.isLoading, case let .message(preview)? = self.result else {
                return
            }
            let confirm = self.confirm
            self.dismiss(completion: {
                confirm(preview)
            })
        }
        sheetView.calendar = { [weak self] in
            guard let self, !self.isClosing else {
                return
            }
            let openCalendar = self.openCalendar
            self.dismiss(completion: openCalendar)
        }
        sheetView.returnToPosition = { [weak self] in
            guard let self, !self.isClosing, let returnToReadingPosition = self.returnToReadingPosition else {
                return
            }
            self.dismiss(completion: returnToReadingPosition)
        }
        self.displayNodeDidLoad()
        self.updateView()
        self.schedulePreview(immediately: true)
    }

    override func containerLayoutUpdated(_ layout: ContainerViewLayout, transition: ContainedViewLayoutTransition) {
        super.containerLayoutUpdated(layout, transition: transition)
        self.sheetView?.frame = CGRect(origin: .zero, size: layout.size)
        self.sheetView?.updateInsets(safeInsets: layout.safeInsets, topInset: max(layout.statusBarHeight ?? 0.0, layout.safeInsets.top))
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if !self.didAnimateIn {
            self.didAnimateIn = true
            self.sheetView?.animateIn()
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        self.cancelRequest()
    }

    override func dismiss(completion: (() -> Void)? = nil) {
        guard !self.isClosing else {
            return
        }
        self.isClosing = true
        self.cancelRequest()
        let finish: () -> Void = { [weak self] in
            guard let self else {
                return
            }
            self.presentingViewController?.dismiss(animated: false, completion: completion)
        }
        if let sheetView = self.sheetView {
            sheetView.animateOut(completion: finish)
        } else {
            finish()
        }
    }

    private func cancelRequest() {
        self.generation += 1
        self.requestTimer?.invalidate()
        self.requestTimer = nil
        self.requestDisposable.set(nil)
    }

    private func schedulePreview(immediately: Bool = false) {
        guard !self.isClosing else {
            return
        }
        self.cancelRequest()
        // Invalidate the previous preview before the debounce starts: it must never be confirmable
        // while the ruler already shows a different day.
        self.result = nil
        self.isLoading = true
        self.updateView()
        let generation = self.generation
        let date = self.selection.date
        if immediately {
            self.requestPreview(date: date, generation: generation)
        } else {
            let timer = SwiftSignalKit.Timer(timeout: 0.28, repeat: false, completion: { [weak self] in
                self?.requestPreview(date: date, generation: generation)
            }, queue: .mainQueue())
            self.requestTimer = timer
            timer.start()
        }
    }

    private func requestPreview(date: Date, generation: Int) {
        guard !self.isClosing, self.generation == generation, self.selection.date == date else {
            return
        }
        self.requestTimer = nil
        self.requestDisposable.set((self.loadPreview(date)
        |> take(1)
        |> deliverOnMainQueue).startStrict(next: { [weak self] result in
            guard let self, !self.isClosing, self.generation == generation, self.selection.date == date else {
                return
            }
            self.result = result
            self.isLoading = false
            self.updateView()
        }))
    }

    private func updateView() {
        self.sheetView?.update(presentationData: self.presentationData, selection: self.selection, component: self.component, result: self.result, isLoading: self.isLoading)
    }
}

private final class ChatTimelineSheetView: UIView {
    var cancel: (() -> Void)?
    var componentChanged: ((ChatTimelineDateComponent) -> Void)?
    var valueChanged: ((Int) -> Void)?
    var moveDay: ((Int) -> Void)?
    var retry: (() -> Void)?
    var jump: (() -> Void)?
    var calendar: (() -> Void)?
    var returnToPosition: (() -> Void)?

    private let dimButton = UIButton(type: .custom)
    private let sheet = UIView()
    private let handle = UIView()
    private let titleLabel = UILabel()
    private let closeButton = UIButton(type: .custom)
    private let scrollView = UIScrollView()
    private let selectedCaption = UILabel()
    private let dateLabel = UILabel()
    private let zoneLabel = UILabel()
    private let previousButton = UIButton(type: .custom)
    private let nextButton = UIButton(type: .custom)
    private let pills = ChatTimelineDateComponent.allCases.map { ChatTimelineComponentButton(component: $0) }
    private let ruler = ChatTimelineRuler()
    private let hintLabel = UILabel()
    private let previewCard = UIView()
    private let previewAccent = UIView()
    private let previewCaption = UILabel()
    private let previewDate = UILabel()
    private let previewAuthor = UILabel()
    private let previewText = UILabel()
    private let activity = UIActivityIndicatorView(style: .medium)
    private let retryButton = UIButton(type: .custom)
    private let footer = UIView()
    private let footerSeparator = UIView()
    private let jumpButton = UIButton(type: .custom)
    private let calendarButton = UIButton(type: .custom)
    private let returnButton = UIButton(type: .custom)
    private let dateFormatter = DateFormatter()
    private let messageDateFormatter = DateFormatter()
    private let monthFormatter = DateFormatter()
    private let haptic = HapticFeedback()
    private var presentationData: PresentationData
    private var selection: ChatTimelineDateSelection
    private var component: ChatTimelineDateComponent = .month
    private var result: ChatTimelinePreviewResult?
    private var isLoading = true
    private let hasReturn: Bool
    private var contentScale: CGFloat = 1.0
    private var safeInsets = UIEdgeInsets.zero
    private var topInset: CGFloat = 0.0
    private var previewHeight: CGFloat = 180.0

    init(presentationData: PresentationData, selection: ChatTimelineDateSelection, hasReturn: Bool) {
        self.presentationData = presentationData
        self.selection = selection
        self.hasReturn = hasReturn
        super.init(frame: .zero)
        self.accessibilityViewIsModal = true
        self.addSubview(self.dimButton)
        self.addSubview(self.sheet)
        self.sheet.layer.cornerRadius = 28.0
        self.sheet.layer.cornerCurve = .continuous
        self.sheet.clipsToBounds = true
        self.sheet.addSubview(self.handle)
        self.handle.layer.cornerRadius = 2.0
        self.sheet.addSubview(self.titleLabel)
        self.sheet.addSubview(self.closeButton)
        self.sheet.addSubview(self.scrollView)
        self.sheet.addSubview(self.footer)
        self.scrollView.alwaysBounceVertical = false
        self.scrollView.delaysContentTouches = false
        self.scrollView.contentInsetAdjustmentBehavior = .never
        for view in [self.selectedCaption, self.dateLabel, self.zoneLabel, self.previousButton, self.nextButton, self.ruler, self.hintLabel, self.previewCard] {
            self.scrollView.addSubview(view)
        }
        for pill in self.pills {
            self.scrollView.addSubview(pill)
            pill.addTarget(self, action: #selector(self.componentPressed(_:)), for: .touchUpInside)
        }
        self.previewCard.layer.cornerRadius = 18.0
        self.previewCard.layer.cornerCurve = .continuous
        self.previewCard.clipsToBounds = true
        for view in [self.previewAccent, self.previewCaption, self.previewDate, self.previewAuthor, self.previewText, self.activity, self.retryButton] {
            self.previewCard.addSubview(view)
        }
        self.previewAccent.layer.cornerRadius = 1.5
        for view in [self.footerSeparator, self.jumpButton, self.calendarButton, self.returnButton] {
            self.footer.addSubview(view)
        }
        self.jumpButton.layer.cornerRadius = 14.0
        self.jumpButton.layer.cornerCurve = .continuous
        self.closeButton.layer.cornerRadius = 22.0
        self.titleLabel.text = "Chat Timeline"
        self.titleLabel.numberOfLines = 0
        self.titleLabel.accessibilityTraits = .header
        self.selectedCaption.text = "EXPLORE A DATE"
        self.hintLabel.text = "Slide to explore. Your chat stays in place."
        self.hintLabel.numberOfLines = 0
        self.dateLabel.numberOfLines = 0
        self.dateLabel.accessibilityTraits = .header
        self.zoneLabel.numberOfLines = 0
        self.previewCaption.numberOfLines = 0
        self.previewDate.numberOfLines = 0
        self.previewAuthor.numberOfLines = 2
        self.previewText.numberOfLines = 3
        self.previewText.lineBreakMode = .byTruncatingTail
        self.activity.hidesWhenStopped = true
        self.jumpButton.setTitle("Jump to message", for: .normal)
        self.calendarButton.setTitle("Open calendar", for: .normal)
        self.returnButton.setTitle("Return to reading position", for: .normal)
        self.returnButton.isHidden = !hasReturn
        self.retryButton.setTitle("Try again", for: .normal)
        self.previousButton.setImage(UIImage(systemName: "chevron.left", withConfiguration: UIImage.SymbolConfiguration(pointSize: 15.0, weight: .semibold)), for: .normal)
        self.nextButton.setImage(UIImage(systemName: "chevron.right", withConfiguration: UIImage.SymbolConfiguration(pointSize: 15.0, weight: .semibold)), for: .normal)
        self.closeButton.setImage(UIImage(systemName: "xmark", withConfiguration: UIImage.SymbolConfiguration(pointSize: 13.0, weight: .semibold)), for: .normal)
        self.previousButton.accessibilityLabel = "Previous day"
        self.nextButton.accessibilityLabel = "Next day"
        self.dimButton.isAccessibilityElement = false
        self.closeButton.addTarget(self, action: #selector(self.cancelPressed), for: .touchUpInside)
        self.dimButton.addTarget(self, action: #selector(self.cancelPressed), for: .touchUpInside)
        self.previousButton.addTarget(self, action: #selector(self.previousPressed), for: .touchUpInside)
        self.nextButton.addTarget(self, action: #selector(self.nextPressed), for: .touchUpInside)
        self.retryButton.addTarget(self, action: #selector(self.retryPressed), for: .touchUpInside)
        self.jumpButton.addTarget(self, action: #selector(self.jumpPressed), for: .touchUpInside)
        self.calendarButton.addTarget(self, action: #selector(self.calendarPressed), for: .touchUpInside)
        self.returnButton.addTarget(self, action: #selector(self.returnPressed), for: .touchUpInside)
        self.ruler.addTarget(self, action: #selector(self.rulerChanged), for: .valueChanged)
        NotificationCenter.default.addObserver(self, selector: #selector(self.contentSizeChanged), name: UIContentSizeCategory.didChangeNotification, object: nil)
        self.update(presentationData: presentationData, selection: selection, component: .month, result: nil, isLoading: true)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    func updateInsets(safeInsets: UIEdgeInsets, topInset: CGFloat) {
        self.safeInsets = safeInsets
        self.topInset = topInset
        self.setNeedsLayout()
    }

    func update(presentationData: PresentationData, selection: ChatTimelineDateSelection, component: ChatTimelineDateComponent, result: ChatTimelinePreviewResult?, isLoading: Bool) {
        self.presentationData = presentationData
        self.selection = selection
        self.component = component
        self.result = result
        self.isLoading = isLoading
        let theme = presentationData.theme.actionSheet
        self.overrideUserInterfaceStyle = presentationData.theme.overallDarkAppearance ? .dark : .light
        self.contentScale = max(presentationData.listsFontSize.baseDisplaySize / 17.0, UIFont.preferredFont(forTextStyle: .body).pointSize / 17.0)
        self.dimButton.backgroundColor = theme.dimColor
        self.sheet.backgroundColor = theme.opaqueItemBackgroundColor
        self.footer.backgroundColor = theme.opaqueItemBackgroundColor
        self.handle.backgroundColor = theme.secondaryTextColor.withAlphaComponent(0.35)
        self.footerSeparator.backgroundColor = theme.opaqueItemSeparatorColor
        self.previewCard.backgroundColor = theme.inputBackgroundColor
        self.previewAccent.backgroundColor = theme.controlAccentColor
        self.closeButton.backgroundColor = theme.inputBackgroundColor
        self.closeButton.tintColor = theme.secondaryTextColor
        self.closeButton.accessibilityLabel = presentationData.strings.Common_Cancel
        self.previousButton.tintColor = theme.controlAccentColor
        self.nextButton.tintColor = theme.controlAccentColor
        self.previousButton.isEnabled = selection.date > selection.minimumDate
        self.nextButton.isEnabled = selection.date < selection.maximumDate
        self.previousButton.alpha = self.previousButton.isEnabled ? 1.0 : 0.3
        self.nextButton.alpha = self.nextButton.isEnabled ? 1.0 : 0.3
        self.titleLabel.font = self.font(21.0, weight: .semibold)
        self.titleLabel.textColor = theme.primaryTextColor
        self.selectedCaption.font = self.font(11.0, weight: .semibold)
        self.selectedCaption.textColor = theme.secondaryTextColor
        self.dateLabel.font = self.font(28.0, weight: .bold)
        self.dateLabel.textColor = theme.primaryTextColor
        self.zoneLabel.font = self.font(12.0)
        self.zoneLabel.textColor = theme.secondaryTextColor
        self.hintLabel.font = self.font(13.0)
        self.hintLabel.textColor = theme.secondaryTextColor
        self.previewCaption.font = self.font(11.0, weight: .semibold)
        self.previewCaption.textColor = theme.controlAccentColor
        self.previewDate.font = self.font(15.0, weight: .semibold)
        self.previewDate.textColor = theme.primaryTextColor
        self.previewAuthor.font = self.font(14.0, weight: .semibold)
        self.previewAuthor.textColor = theme.primaryTextColor
        self.previewText.font = self.font(15.0)
        self.previewText.textColor = theme.secondaryTextColor
        self.activity.color = theme.controlAccentColor
        for button in [self.calendarButton, self.returnButton, self.retryButton] {
            button.setTitleColor(theme.controlAccentColor, for: .normal)
            button.titleLabel?.font = self.font(14.0, weight: .medium)
            button.titleLabel?.numberOfLines = 0
            button.titleLabel?.textAlignment = .center
        }
        self.jumpButton.titleLabel?.font = self.font(17.0, weight: .semibold)
        self.jumpButton.titleLabel?.numberOfLines = 0
        self.jumpButton.titleLabel?.textAlignment = .center
        self.jumpButton.setTitleColor(theme.checkContentColor, for: .normal)
        self.jumpButton.backgroundColor = theme.controlAccentColor
        self.jumpButton.isEnabled = false
        if !isLoading, case .message? = result {
            self.jumpButton.isEnabled = true
        }
        self.jumpButton.alpha = self.jumpButton.isEnabled ? 1.0 : 0.4
        self.jumpButton.accessibilityHint = "Opens this previewed message in the chat."
        for formatter in [self.dateFormatter, self.messageDateFormatter, self.monthFormatter] {
            formatter.calendar = selection.calendar
            formatter.timeZone = selection.calendar.timeZone
            formatter.locale = Locale.current
        }
        self.dateFormatter.setLocalizedDateFormatFromTemplate("d MMMM yyyy")
        self.messageDateFormatter.setLocalizedDateFormatFromTemplate("d MMM yyyy jmm")
        self.monthFormatter.setLocalizedDateFormatFromTemplate("MMM")
        self.dateLabel.text = self.dateFormatter.string(from: selection.date)
        let zone = selection.calendar.timeZone
        self.zoneLabel.text = zone.abbreviation(for: selection.date) ?? zone.identifier
        for pill in self.pills {
            let caption: String
            let value: String
            switch pill.component {
            case .year:
                caption = "Year"
                value = String(selection.value(for: .year))
            case .month:
                caption = "Month"
                value = self.monthFormatter.string(from: selection.date)
            case .day:
                caption = "Day"
                value = String(selection.value(for: .day))
            }
            pill.update(caption: caption, value: value, selected: pill.component == component, theme: theme, scale: self.contentScale)
        }
        let values = selection.availableValues(for: component)
        let labels: [Int: String]
        if component == .month {
            var monthLabels: [Int: String] = [:]
            for value in values {
                if let date = selection.calendar.date(from: DateComponents(year: selection.value(for: .year), month: value, day: 1)) {
                    monthLabels[value] = self.monthFormatter.string(from: date)
                }
            }
            labels = monthLabels
        } else {
            labels = Dictionary(uniqueKeysWithValues: values.map { ($0, String($0)) })
        }
        self.ruler.update(range: values, value: selection.value(for: component), labels: labels, theme: theme, scale: self.contentScale)
        self.ruler.accessibilityLabel = component == .year ? "Year" : (component == .month ? "Month" : "Day")
        self.updatePreview()
        self.setNeedsLayout()
    }

    private func updatePreview() {
        self.retryButton.isHidden = true
        self.previewAuthor.isHidden = true
        self.activity.stopAnimating()
        if self.isLoading {
            self.previewCaption.text = "MESSAGE PREVIEW"
            self.previewDate.text = "Finding a message…"
            self.previewText.text = "Your place in the chat is kept while the preview loads."
            self.activity.startAnimating()
        } else if let result = self.result {
            switch result {
            case let .message(preview):
                let date = Date(timeIntervalSince1970: TimeInterval(preview.timestamp))
                self.previewCaption.text = self.selection.isSameDay(as: date) ? "MESSAGE ON THIS DATE" : "NEAREST AVAILABLE MESSAGE"
                self.previewDate.text = self.messageDateFormatter.string(from: date)
                self.previewAuthor.text = preview.author
                self.previewAuthor.isHidden = preview.author.isEmpty
                self.previewText.text = preview.text
            case .unavailable:
                self.previewCaption.text = "PREVIEW UNAVAILABLE"
                self.previewDate.text = "No accessible message found"
                self.previewText.text = "This does not mean the period is empty. Try another date or open the calendar."
                self.retryButton.isHidden = false
            case .failed:
                self.previewCaption.text = "COULDN’T LOAD THIS DATE"
                self.previewDate.text = "The preview could not be loaded"
                self.previewText.text = "Check your connection and try again. Your place in the chat hasn’t changed."
                self.retryButton.isHidden = false
            }
        }
    }

    private func font(_ size: CGFloat, weight: UIFont.Weight = .regular) -> UIFont {
        return UIFont.systemFont(ofSize: size * self.contentScale, weight: weight)
    }

    private func buttonHeight(_ button: UIButton, width: CGFloat, minimum: CGFloat, verticalPadding: CGFloat) -> CGFloat {
        let title = NSAttributedString(string: button.currentTitle ?? "", attributes: [.font: button.titleLabel?.font ?? self.font(14.0)])
        let textHeight = ceil(title.boundingRect(with: CGSize(width: max(1.0, width - 24.0), height: .greatestFiniteMagnitude), options: [.usesLineFragmentOrigin, .usesFontLeading], context: nil).height)
        return max(minimum, textHeight + verticalPadding)
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        guard self.bounds.width > 0.0, self.bounds.height > 0.0 else {
            return
        }
        self.dimButton.frame = self.bounds
        let availableWidth = max(1.0, self.bounds.width - self.safeInsets.left - self.safeInsets.right)
        let sheetWidth = min(520.0, availableWidth)
        let inset: CGFloat = 20.0
        let width = max(1.0, sheetWidth - inset * 2.0)
        let titleHeight = ceil(self.titleLabel.sizeThatFits(CGSize(width: max(1.0, width - 56.0), height: .greatestFiniteMagnitude)).height)
        let headerHeight = max(68.0, titleHeight + 30.0)
        let actionHeight = self.buttonHeight(self.jumpButton, width: width, minimum: 50.0, verticalPadding: 22.0)
        let calendarHeight = self.buttonHeight(self.calendarButton, width: width, minimum: 44.0, verticalPadding: 16.0)
        let returnHeight = self.hasReturn ? self.buttonHeight(self.returnButton, width: width, minimum: 44.0, verticalPadding: 16.0) : 0.0
        let bottomInset = max(10.0, self.safeInsets.bottom)
        let footerHeight = 12.0 + actionHeight + calendarHeight + returnHeight + bottomInset
        let contentHeight = self.layoutContent(width: width, inset: inset)
        let height = min(max(1.0, self.bounds.height - self.topInset - 12.0), headerHeight + contentHeight + footerHeight)
        self.sheet.frame = CGRect(x: self.safeInsets.left + floor((availableWidth - sheetWidth) * 0.5), y: self.bounds.height - height, width: sheetWidth, height: height)
        self.handle.frame = CGRect(x: floor((sheetWidth - 36.0) * 0.5), y: 9.0, width: 36.0, height: 4.0)
        self.closeButton.frame = CGRect(x: sheetWidth - inset - 44.0, y: 18.0, width: 44.0, height: 44.0)
        self.titleLabel.frame = CGRect(x: inset, y: 24.0, width: max(1.0, width - 56.0), height: headerHeight - 30.0)
        // Keep the action dock visible normally. On short screens or at accessibility text sizes,
        // put it in the scroll content instead of letting it cover the date and preview.
        if height - headerHeight - footerHeight < 180.0 {
            if self.footer.superview !== self.scrollView {
                self.scrollView.addSubview(self.footer)
            }
            self.scrollView.frame = CGRect(x: 0.0, y: headerHeight, width: sheetWidth, height: max(1.0, height - headerHeight))
            self.scrollView.contentSize = CGSize(width: sheetWidth, height: contentHeight + footerHeight)
            self.footer.frame = CGRect(x: 0.0, y: contentHeight, width: sheetWidth, height: footerHeight)
        } else {
            if self.footer.superview !== self.sheet {
                self.sheet.addSubview(self.footer)
            }
            self.scrollView.frame = CGRect(x: 0.0, y: headerHeight, width: sheetWidth, height: height - headerHeight - footerHeight)
            self.scrollView.contentSize = CGSize(width: sheetWidth, height: contentHeight)
            self.footer.frame = CGRect(x: 0.0, y: height - footerHeight, width: sheetWidth, height: footerHeight)
        }
        self.footerSeparator.frame = CGRect(x: inset, y: 0.0, width: width, height: 1.0 / self.contentScaleFactor)
        self.jumpButton.frame = CGRect(x: inset, y: 12.0, width: width, height: actionHeight)
        self.calendarButton.frame = CGRect(x: inset, y: 12.0 + actionHeight, width: width, height: calendarHeight)
        self.returnButton.frame = CGRect(x: inset, y: 12.0 + actionHeight + calendarHeight, width: width, height: returnHeight)
    }

    private func layoutContent(width: CGFloat, inset: CGFloat) -> CGFloat {
        var y: CGFloat = 8.0
        func place(_ label: UILabel, x: CGFloat, width: CGFloat, spacing: CGFloat) {
            let height = ceil(label.sizeThatFits(CGSize(width: width, height: CGFloat.greatestFiniteMagnitude)).height)
            label.frame = CGRect(x: x, y: y, width: width, height: height)
            y += height + spacing
        }
        place(self.selectedCaption, x: inset, width: width, spacing: 8.0)
        // Day-step buttons have their own row at accessibility sizes, leaving the date untruncated.
        place(self.dateLabel, x: inset, width: width, spacing: 5.0)
        let zoneHeight = max(44.0, ceil(self.zoneLabel.sizeThatFits(CGSize(width: max(1.0, width - 104.0), height: .greatestFiniteMagnitude)).height))
        self.zoneLabel.frame = CGRect(x: inset, y: y, width: max(1.0, width - 104.0), height: zoneHeight)
        self.previousButton.frame = CGRect(x: inset + width - 92.0, y: y, width: 44.0, height: zoneHeight)
        self.nextButton.frame = CGRect(x: inset + width - 44.0, y: y, width: 44.0, height: zoneHeight)
        y += zoneHeight + 12.0
        let pillWidth = (width - 16.0) / 3.0
        let pillHeight = max(64.0, 42.0 * self.contentScale + 18.0)
        for (index, pill) in self.pills.enumerated() {
            pill.frame = CGRect(x: inset + CGFloat(index) * (pillWidth + 8.0), y: y, width: pillWidth, height: pillHeight)
        }
        y += pillHeight + 12.0
        let rulerHeight = 54.0 + 20.0 * self.contentScale
        self.ruler.frame = CGRect(x: inset, y: y, width: width, height: rulerHeight)
        y += rulerHeight + 2.0
        place(self.hintLabel, x: inset, width: width, spacing: 18.0)
        let cardWidth = width - 36.0
        var cardY: CGFloat = 16.0
        let captionWidth = self.isLoading ? cardWidth - 30.0 : cardWidth
        let captionHeight = ceil(self.previewCaption.sizeThatFits(CGSize(width: captionWidth, height: .greatestFiniteMagnitude)).height)
        self.previewCaption.frame = CGRect(x: 18.0, y: cardY, width: captionWidth, height: captionHeight)
        self.activity.frame = CGRect(x: width - 40.0, y: cardY - 2.0, width: 22.0, height: 22.0)
        cardY += captionHeight + 8.0
        let dateHeight = ceil(self.previewDate.sizeThatFits(CGSize(width: cardWidth, height: .greatestFiniteMagnitude)).height)
        self.previewDate.frame = CGRect(x: 18.0, y: cardY, width: cardWidth, height: dateHeight)
        cardY += dateHeight + 14.0
        if !self.previewAuthor.isHidden {
            let height = ceil(self.previewAuthor.sizeThatFits(CGSize(width: cardWidth, height: .greatestFiniteMagnitude)).height)
            self.previewAuthor.frame = CGRect(x: 18.0, y: cardY, width: cardWidth, height: height)
            cardY += height + 5.0
        }
        let textHeight = min(ceil(self.previewText.sizeThatFits(CGSize(width: cardWidth, height: .greatestFiniteMagnitude)).height), ceil(self.previewText.font.lineHeight * 3.0))
        self.previewText.frame = CGRect(x: 18.0, y: cardY, width: cardWidth, height: textHeight)
        cardY += textHeight + 16.0
        if !self.retryButton.isHidden {
            let height = self.buttonHeight(self.retryButton, width: width - 20.0, minimum: 44.0, verticalPadding: 16.0)
            self.retryButton.frame = CGRect(x: 10.0, y: cardY - 8.0, width: width - 20.0, height: height)
            cardY += height - 8.0
        }
        self.previewHeight = max(160.0, cardY)
        self.previewCard.frame = CGRect(x: inset, y: y, width: width, height: self.previewHeight)
        self.previewAccent.frame = CGRect(x: 0.0, y: 18.0, width: 3.0, height: self.previewHeight - 36.0)
        return y + self.previewHeight + 20.0
    }

    private var reduceMotion: Bool {
        return self.presentationData.reduceMotion || UIAccessibility.isReduceMotionEnabled
    }

    func animateIn() {
        self.layoutIfNeeded()
        self.dimButton.alpha = 0.0
        if self.reduceMotion {
            self.sheet.alpha = 0.0
        } else {
            self.sheet.transform = CGAffineTransform(translationX: 0.0, y: self.sheet.bounds.height)
        }
        UIView.animate(withDuration: self.reduceMotion ? 0.18 : 0.3, delay: 0.0, options: [.curveEaseOut, .beginFromCurrentState], animations: {
            self.dimButton.alpha = 1.0
            self.sheet.alpha = 1.0
            self.sheet.transform = .identity
        }, completion: { [weak self] _ in
            if let self {
                UIAccessibility.post(notification: .screenChanged, argument: self.titleLabel)
            }
        })
    }

    func animateOut(completion: @escaping () -> Void) {
        self.isUserInteractionEnabled = false
        UIView.animate(withDuration: self.reduceMotion ? 0.15 : 0.22, delay: 0.0, options: [.curveEaseIn, .beginFromCurrentState], animations: {
            self.dimButton.alpha = 0.0
            if self.reduceMotion {
                self.sheet.alpha = 0.0
            } else {
                self.sheet.transform = CGAffineTransform(translationX: 0.0, y: self.sheet.bounds.height)
            }
        }, completion: { _ in
            completion()
        })
    }

    override func accessibilityPerformEscape() -> Bool {
        self.cancel?()
        return true
    }

    @objc private func contentSizeChanged() {
        self.update(presentationData: self.presentationData, selection: self.selection, component: self.component, result: self.result, isLoading: self.isLoading)
    }

    @objc private func componentPressed(_ sender: ChatTimelineComponentButton) {
        self.haptic.tap()
        self.componentChanged?(sender.component)
    }

    @objc private func rulerChanged() {
        self.haptic.tap()
        self.valueChanged?(self.ruler.value)
    }

    @objc private func cancelPressed() { self.cancel?() }
    @objc private func previousPressed() { self.moveDay?(-1) }
    @objc private func nextPressed() { self.moveDay?(1) }
    @objc private func retryPressed() { self.retry?() }
    @objc private func jumpPressed() { self.jump?() }
    @objc private func calendarPressed() { self.calendar?() }
    @objc private func returnPressed() { self.returnToPosition?() }
}

private final class ChatTimelineComponentButton: UIControl {
    let component: ChatTimelineDateComponent
    private let captionLabel = UILabel()
    private let valueLabel = UILabel()

    init(component: ChatTimelineDateComponent) {
        self.component = component
        super.init(frame: .zero)
        self.layer.cornerRadius = 14.0
        self.layer.cornerCurve = .continuous
        self.addSubview(self.captionLabel)
        self.addSubview(self.valueLabel)
        self.captionLabel.textAlignment = .center
        self.captionLabel.adjustsFontSizeToFitWidth = true
        self.captionLabel.minimumScaleFactor = 0.6
        self.valueLabel.textAlignment = .center
        self.valueLabel.adjustsFontSizeToFitWidth = true
        self.valueLabel.minimumScaleFactor = 0.6
        self.isAccessibilityElement = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(caption: String, value: String, selected: Bool, theme: PresentationThemeActionSheet, scale: CGFloat) {
        self.captionLabel.text = caption
        self.valueLabel.text = value
        self.captionLabel.font = UIFont.systemFont(ofSize: 11.0 * scale, weight: .medium)
        self.valueLabel.font = UIFont.systemFont(ofSize: 20.0 * scale, weight: .semibold)
        self.captionLabel.textColor = selected ? theme.controlAccentColor : theme.secondaryTextColor
        self.valueLabel.textColor = selected ? theme.controlAccentColor : theme.primaryTextColor
        self.backgroundColor = selected ? theme.controlAccentColor.withAlphaComponent(0.12) : theme.inputBackgroundColor
        self.layer.borderWidth = selected ? 1.0 : 0.0
        self.layer.borderColor = theme.controlAccentColor.withAlphaComponent(0.3).cgColor
        self.accessibilityLabel = caption
        self.accessibilityValue = value
        self.accessibilityHint = "Choose this scale, then adjust the timeline below."
        self.accessibilityTraits = selected ? [.button, .selected] : [.button]
        self.setNeedsLayout()
    }

    override var isHighlighted: Bool {
        didSet {
            self.alpha = self.isHighlighted ? 0.6 : 1.0
        }
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        let captionHeight = ceil(self.captionLabel.font.lineHeight)
        let valueHeight = ceil(self.valueLabel.font.lineHeight)
        let y = floor((self.bounds.height - captionHeight - valueHeight - 4.0) * 0.5)
        self.captionLabel.frame = CGRect(x: 6.0, y: y, width: self.bounds.width - 12.0, height: captionHeight)
        self.valueLabel.frame = CGRect(x: 6.0, y: y + captionHeight + 4.0, width: self.bounds.width - 12.0, height: valueHeight)
    }
}

/// A bounded, discrete calendar ruler. All gestures stay inside the sheet.
private final class ChatTimelineRuler: UIControl {
    private(set) var value = 1
    private var range = 1...12
    private var labels: [Int: String] = [:]
    private var accent = UIColor.systemBlue
    private var secondary = UIColor.secondaryLabel
    private var scale: CGFloat = 1.0

    override init(frame: CGRect) {
        super.init(frame: frame)
        self.backgroundColor = .clear
        self.isOpaque = false
        self.isAccessibilityElement = true
        self.accessibilityTraits = .adjustable
        self.accessibilityHint = "Swipe up or down to change the selected date."
        self.contentMode = .redraw
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(range: ClosedRange<Int>, value: Int, labels: [Int: String], theme: PresentationThemeActionSheet, scale: CGFloat) {
        self.range = range
        self.value = value
        self.labels = labels
        self.accent = theme.controlAccentColor
        self.secondary = theme.secondaryTextColor
        self.scale = scale
        self.accessibilityValue = labels[value] ?? String(value)
        self.setNeedsDisplay()
    }

    override func draw(_ rect: CGRect) {
        guard let context = UIGraphicsGetCurrentContext() else {
            return
        }
        let inset: CGFloat = 14.0
        let width = max(1.0, self.bounds.width - inset * 2.0)
        let steps = max(1, self.range.upperBound - self.range.lowerBound)
        let labelFont = UIFont.systemFont(ofSize: 11.0 * self.scale, weight: .medium)
        let widestLabel = self.labels.values.map { ($0 as NSString).size(withAttributes: [.font: labelFont]).width }.max() ?? 24.0
        let maxLabels = max(2, Int(width / (widestLabel + 14.0)))
        let labelStep = max(1, Int(ceil(Double(steps) / Double(maxLabels - 1))))
        var lastLabelMaxX: CGFloat = -.greatestFiniteMagnitude
        for index in self.range {
            let x = inset + CGFloat(index - self.range.lowerBound) / CGFloat(steps) * width
            let major = (index - self.range.lowerBound) % labelStep == 0 || index == self.range.upperBound
            context.setStrokeColor(self.secondary.withAlphaComponent(major ? 0.5 : 0.23).cgColor)
            context.setLineWidth(1.0)
            context.move(to: CGPoint(x: x, y: major ? 18.0 : 25.0))
            context.addLine(to: CGPoint(x: x, y: 40.0))
            context.strokePath()
            if major, let label = self.labels[index] {
                let size = (label as NSString).size(withAttributes: [.font: labelFont])
                let labelX = max(0.0, min(self.bounds.width - size.width, x - size.width * 0.5))
                if labelX > lastLabelMaxX + 8.0 {
                    (label as NSString).draw(at: CGPoint(x: labelX, y: 48.0), withAttributes: [.font: labelFont, .foregroundColor: self.secondary])
                    lastLabelMaxX = labelX + size.width
                }
            }
        }
        let selectedX = inset + CGFloat(self.value - self.range.lowerBound) / CGFloat(steps) * width
        context.setFillColor(self.accent.withAlphaComponent(0.1).cgColor)
        context.fillEllipse(in: CGRect(x: selectedX - 15.0, y: 8.0, width: 30.0, height: 38.0))
        context.setFillColor(self.accent.cgColor)
        UIBezierPath(roundedRect: CGRect(x: selectedX - 2.0, y: 10.0, width: 4.0, height: 34.0), cornerRadius: 2.0).fill()
        context.fillEllipse(in: CGRect(x: selectedX - 4.0, y: 7.0, width: 8.0, height: 8.0))
    }

    private func updateValue(at point: CGPoint) {
        let width = max(1.0, self.bounds.width - 28.0)
        let fraction = min(1.0, max(0.0, (point.x - 14.0) / width))
        let value = self.range.lowerBound + Int((fraction * CGFloat(self.range.upperBound - self.range.lowerBound)).rounded())
        self.setValue(value)
    }

    private func setValue(_ value: Int) {
        let value = min(self.range.upperBound, max(self.range.lowerBound, value))
        guard value != self.value else {
            return
        }
        self.value = value
        self.accessibilityValue = self.labels[value] ?? String(value)
        self.setNeedsDisplay()
        self.sendActions(for: .valueChanged)
    }

    override func beginTracking(_ touch: UITouch, with event: UIEvent?) -> Bool {
        self.updateValue(at: touch.location(in: self))
        return true
    }

    override func continueTracking(_ touch: UITouch, with event: UIEvent?) -> Bool {
        self.updateValue(at: touch.location(in: self))
        return true
    }

    override func endTracking(_ touch: UITouch?, with event: UIEvent?) {
        if let touch {
            self.updateValue(at: touch.location(in: self))
        }
    }

    override func accessibilityIncrement() { self.setValue(self.value + 1) }
    override func accessibilityDecrement() { self.setValue(self.value - 1) }
}
