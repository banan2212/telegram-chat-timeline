import Foundation
import UIKit
import AsyncDisplayKit
import Display
import TelegramPresentationData

final class AuthorizationQRLoginController: ViewController {
    private let presentationData: PresentationData
    private let scrollView = UIScrollView()
    private let stackView = UIStackView()
    private let imageView = UIImageView()
    private let statusLabel = UILabel()
    private let activityView = UIActivityIndicatorView(style: .medium)
    private let retryButton = UIButton(type: .system)
    private let cancelButton = UIButton(type: .system)
    private var currentState: AuthorizationQRLoginCoordinator.DisplayState = .loading
    var retry: (() -> Void)?
    var cancelled: (() -> Void)?

    init(presentationData: PresentationData) {
        self.presentationData = presentationData
        super.init(navigationBarPresentationData: nil)
        self.statusBar.statusBarStyle = presentationData.theme.intro.statusBarStyle.style
        self.supportedOrientations = ViewControllerSupportedOrientations(regularSize: .all, compactSize: .all)
    }

    required init(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadDisplayNode() {
        self.displayNode = ASDisplayNode()
        self.displayNode.backgroundColor = self.presentationData.theme.list.plainBackgroundColor
        self.displayNodeDidLoad()

        let textColor = self.presentationData.theme.list.itemPrimaryTextColor
        let accentColor = self.presentationData.theme.list.itemAccentColor
        self.scrollView.alwaysBounceVertical = true
        self.scrollView.contentInsetAdjustmentBehavior = .never
        self.displayNode.view.addSubview(self.scrollView)
        self.stackView.axis = .vertical
        self.stackView.alignment = .fill
        self.stackView.spacing = 20.0
        self.stackView.translatesAutoresizingMaskIntoConstraints = false
        self.scrollView.addSubview(self.stackView)

        let titleLabel = UILabel()
        titleLabel.text = "Log in with QR code"
        titleLabel.font = UIFont.preferredFont(forTextStyle: .title1)
        titleLabel.adjustsFontForContentSizeCategory = true
        titleLabel.textColor = textColor
        titleLabel.numberOfLines = 0
        titleLabel.textAlignment = .center
        titleLabel.accessibilityTraits = .header
        self.stackView.addArrangedSubview(titleLabel)

        let instructionsLabel = UILabel()
        instructionsLabel.text = "Approve this QR code in your main Telegram: Settings → Devices → Link Desktop Device. Use a second screen to scan it. Enter your two-step verification password here if Telegram requests it."
        instructionsLabel.font = UIFont.preferredFont(forTextStyle: .body)
        instructionsLabel.adjustsFontForContentSizeCategory = true
        instructionsLabel.textColor = textColor
        instructionsLabel.numberOfLines = 0
        instructionsLabel.textAlignment = .center
        self.stackView.addArrangedSubview(instructionsLabel)

        let imageContainer = UIView()
        imageContainer.backgroundColor = .white
        imageContainer.layer.cornerRadius = 16.0
        imageContainer.clipsToBounds = true
        self.imageView.translatesAutoresizingMaskIntoConstraints = false
        self.imageView.contentMode = .scaleAspectFit
        self.imageView.layer.magnificationFilter = .nearest
        self.imageView.isAccessibilityElement = true
        self.imageView.accessibilityLabel = "Telegram login QR code"
        self.imageView.accessibilityIdentifier = "Auth.QRLogin.Code"
        imageContainer.addSubview(self.imageView)
        self.stackView.addArrangedSubview(imageContainer)

        self.activityView.color = accentColor
        self.activityView.hidesWhenStopped = true
        self.stackView.addArrangedSubview(self.activityView)
        self.statusLabel.font = UIFont.preferredFont(forTextStyle: .body)
        self.statusLabel.adjustsFontForContentSizeCategory = true
        self.statusLabel.textColor = textColor
        self.statusLabel.numberOfLines = 0
        self.statusLabel.textAlignment = .center
        self.statusLabel.accessibilityIdentifier = "Auth.QRLogin.Status"
        self.stackView.addArrangedSubview(self.statusLabel)

        self.retryButton.setTitle("Retry", for: .normal)
        self.retryButton.accessibilityIdentifier = "Auth.QRLogin.Retry"
        self.retryButton.addTarget(self, action: #selector(self.retryPressed), for: .touchUpInside)
        self.cancelButton.setTitle(self.presentationData.strings.Common_Cancel, for: .normal)
        self.cancelButton.accessibilityIdentifier = "Auth.QRLogin.Cancel"
        self.cancelButton.addTarget(self, action: #selector(self.cancelPressed), for: .touchUpInside)
        for button in [self.retryButton, self.cancelButton] {
            button.setTitleColor(accentColor, for: .normal)
            button.titleLabel?.font = UIFont.preferredFont(forTextStyle: .headline)
            button.titleLabel?.adjustsFontForContentSizeCategory = true
            button.titleLabel?.numberOfLines = 0
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 44.0).isActive = true
            self.stackView.addArrangedSubview(button)
        }

        let cancellationLabel = UILabel()
        cancellationLabel.text = "Hiding or cancelling does not revoke a code already shown. It can be approved until it expires. Cancel stops checks and does not undo a login already approved."
        cancellationLabel.font = UIFont.preferredFont(forTextStyle: .footnote)
        cancellationLabel.adjustsFontForContentSizeCategory = true
        cancellationLabel.textColor = self.presentationData.theme.list.itemSecondaryTextColor
        cancellationLabel.numberOfLines = 0
        cancellationLabel.textAlignment = .center
        self.stackView.addArrangedSubview(cancellationLabel)

        let imageAspect = imageContainer.heightAnchor.constraint(equalTo: imageContainer.widthAnchor)
        imageAspect.priority = .defaultHigh
        NSLayoutConstraint.activate([
            self.stackView.topAnchor.constraint(equalTo: self.scrollView.contentLayoutGuide.topAnchor, constant: 24.0),
            self.stackView.bottomAnchor.constraint(equalTo: self.scrollView.contentLayoutGuide.bottomAnchor, constant: -24.0),
            self.scrollView.contentLayoutGuide.widthAnchor.constraint(equalTo: self.scrollView.frameLayoutGuide.widthAnchor),
            self.stackView.leadingAnchor.constraint(equalTo: self.scrollView.contentLayoutGuide.leadingAnchor, constant: 24.0),
            self.stackView.trailingAnchor.constraint(equalTo: self.scrollView.contentLayoutGuide.trailingAnchor, constant: -24.0),
            imageAspect,
            self.imageView.leadingAnchor.constraint(equalTo: imageContainer.leadingAnchor, constant: 20.0),
            self.imageView.trailingAnchor.constraint(equalTo: imageContainer.trailingAnchor, constant: -20.0),
            self.imageView.topAnchor.constraint(equalTo: imageContainer.topAnchor, constant: 20.0),
            self.imageView.bottomAnchor.constraint(equalTo: imageContainer.bottomAnchor, constant: -20.0)
        ])
        self.update(self.currentState)
    }

    override func containerLayoutUpdated(_ layout: ContainerViewLayout, transition: ContainedViewLayoutTransition) {
        super.containerLayoutUpdated(layout, transition: transition)
        let insets = layout.insets(options: [.statusBar])
        let width = min(480.0, layout.size.width - layout.safeInsets.left - layout.safeInsets.right)
        self.scrollView.frame = CGRect(x: layout.safeInsets.left + (layout.size.width - layout.safeInsets.left - layout.safeInsets.right - width) / 2.0, y: insets.top, width: width, height: max(0.0, layout.size.height - insets.top - insets.bottom))
    }

    func update(_ state: AuthorizationQRLoginCoordinator.DisplayState) {
        self.currentState = state
        guard self.isNodeLoaded else { return }
        // Always remove the previous credential before changing state.
        self.imageView.image = nil
        self.imageView.isHidden = true
        self.imageView.superview?.isHidden = true
        self.activityView.stopAnimating()
        self.retryButton.isHidden = true
        self.retryButton.setTitle("Retry", for: .normal)
        switch state {
        case .loading:
            self.statusLabel.text = "Getting a new QR code…"
            self.activityView.startAnimating()
        case .finishing:
            self.statusLabel.text = "Finishing sign-in…"
            self.activityView.startAnimating()
        case let .code(image):
            self.imageView.image = image
            self.imageView.isHidden = false
            self.imageView.superview?.isHidden = false
            self.statusLabel.text = "Waiting for your approval in Telegram. This code refreshes when it expires."
        case let .retry(reason):
            self.retryButton.isHidden = false
            switch reason {
            case .failed:
                self.statusLabel.text = "Could not complete QR login. Try again or cancel."
            case .limitExceeded:
                self.statusLabel.text = self.presentationData.strings.Login_CodeFloodError
            case .expired:
                self.statusLabel.text = "The QR code expired. Tap Retry for a new code."
            case .suspended:
                self.retryButton.setTitle("Continue", for: .normal)
                self.statusLabel.text = "QR login is paused. After approving on your main Telegram, tap Continue to check approval or get a new code."
            case .completionFailed:
                self.statusLabel.text = "Could not finish this sign-in. Retry to complete it. Cancel closes this screen; you can tap QR to try again later."
            }
        }
    }

    func finish() {
        self.cancelled = nil
        self.retry = nil
        self.update(.loading)
        self.dismiss()
    }

    @objc private func retryPressed() {
        self.retry?()
    }

    @objc private func cancelPressed() {
        self.update(.retry(.suspended))
        self.cancelled?()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        self.update(.retry(.suspended))
        self.cancelled?()
    }
}

// Display's navigation bar supports one trailing item. Keep Next available on
// narrow phones, with separate 44-point targets and explicit VoiceOver labels.
final class AuthorizationQRLoginNavigationNode: ASDisplayNode {
    private let qrButton = ASButtonNode()
    private let nextButton: ASButtonNode?
    private let qrPressed: () -> Void
    private let nextPressed: () -> Void

    init(color: UIColor, nextTitle: String?, qrPressed: @escaping () -> Void, nextPressed: @escaping () -> Void) {
        self.qrPressed = qrPressed
        self.nextPressed = nextPressed
        self.nextButton = nextTitle == nil ? nil : ASButtonNode()
        super.init()
        self.qrButton.setTitle("QR", with: Font.regular(17.0), with: color, for: .normal)
        self.qrButton.accessibilityLabel = "Log in with QR code"
        self.qrButton.accessibilityIdentifier = "Auth.PhoneEntry.QRLogin"
        self.qrButton.addTarget(self, action: #selector(self.qrAction), forControlEvents: .touchUpInside)
        self.addSubnode(self.qrButton)
        if let nextButton = self.nextButton, let nextTitle {
            nextButton.setTitle(nextTitle, with: Font.semibold(17.0), with: color, for: .normal)
            nextButton.addTarget(self, action: #selector(self.nextAction), forControlEvents: .touchUpInside)
            self.addSubnode(nextButton)
        }
    }

    override func calculateSizeThatFits(_ constrainedSize: CGSize) -> CGSize {
        let nextWidth = self.nextButton.map { max(44.0, $0.measure(CGSize(width: constrainedSize.width, height: 44.0)).width) + 8.0 } ?? 0.0
        return CGSize(width: 44.0 + nextWidth, height: 44.0)
    }

    override func layout() {
        super.layout()
        self.qrButton.frame = CGRect(x: 0.0, y: 0.0, width: 44.0, height: 44.0)
        self.nextButton?.frame = CGRect(x: 52.0, y: 0.0, width: max(0.0, self.bounds.width - 52.0), height: 44.0)
    }

    @objc private func qrAction() { self.qrPressed() }
    @objc private func nextAction() { self.nextPressed() }
}
