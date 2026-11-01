import Foundation
import Postbox
internal import TelegramApi
import SwiftSignalKit

public struct AuthTransferExportedToken {
    public let value: Data
    public let validUntil: Int32
}

public enum ExportAuthTransferTokenError {
    case generic
    case limitExceeded
}

public enum ExportAuthTransferTokenResult {
    case displayToken(AuthTransferExportedToken)
    case changeAccountAndRetry(UnauthorizedAccount)
    case loggedIn
    case passwordRequested(UnauthorizedAccount)
}

private func authTransferTestingEnvironment(_ attributes: [TelegramAccountManagerTypes.Attribute]) -> Bool {
    return attributes.contains(where: { attribute in
        if case let .environment(environment) = attribute, case .test = environment.environment {
            return true
        }
        return false
    })
}

// Shared by normal QR completion and recovery after a cancelled subscription.
// AccountManager serializes this transaction: a delayed original completion
// must not switch accounts twice or remove a newer authentication record.
private func completeAuthTransferAccount(transaction: AccountManagerModifier<TelegramAccountManagerTypes>, account: UnauthorizedAccount) -> Bool {
    if let record = transaction.getRecords().first(where: { $0.id == account.id }) {
        guard transaction.getCurrentAuth()?.id != account.id,
            record.temporarySessionId == nil,
            authTransferTestingEnvironment(record.attributes) == account.testingEnvironment,
            !record.attributes.contains(where: { if case .loggedOut = $0 { return true }; return false }) else {
            return false
        }
        return true
    }
    // createAuth stores its placeholder separately from getRecords(). Only the
    // exact still-current auth record can become a newly authorized record.
    guard let authRecord = transaction.getCurrentAuth(), authRecord.id == account.id,
        authTransferTestingEnvironment(authRecord.attributes) == account.testingEnvironment else {
        return false
    }
    switchToAuthorizedAccount(transaction: transaction, account: account, isSupportUser: false)
    return true
}

func _internal_completeQRLoginIfAlreadyAuthorized(accountManager: AccountManager<TelegramAccountManagerTypes>, account: UnauthorizedAccount) -> Signal<Bool, NoError> {
    return account.postbox.transaction { transaction -> Bool in
        guard let state = transaction.getState() as? AuthorizedAccountState,
            state.isTestingEnvironment == account.testingEnvironment else {
            return false
        }
        return true
    }
    |> mapToSignal { authorized -> Signal<Bool, NoError> in
        guard authorized else { return .single(false) }
        return accountManager.transaction { transaction -> Bool in
            return completeAuthTransferAccount(transaction: transaction, account: account)
        }
    }
}

func _internal_exportAuthTransferToken(accountManager: AccountManager<TelegramAccountManagerTypes>, account: UnauthorizedAccount, otherAccountUserIds: [PeerId.Id], syncContacts: Bool) -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> {
    return account.network.request(Api.functions.auth.exportLoginToken(apiId: account.networkArguments.apiId, apiHash: account.networkArguments.apiHash, exceptIds: otherAccountUserIds.map({ $0._internalGetInt64Value() })))
    |> map(Optional.init)
    |> `catch` { error -> Signal<Api.auth.LoginToken?, ExportAuthTransferTokenError> in
        if error.errorDescription == "SESSION_PASSWORD_NEEDED" {
            return account.network.request(Api.functions.account.getPassword(), automaticFloodWait: false)
            |> mapError { error -> ExportAuthTransferTokenError in
                if error.errorDescription.hasPrefix("FLOOD_WAIT") {
                    return .limitExceeded
                } else {
                    return .generic
                }
            }
            |> mapToSignal { result -> Signal<Api.auth.LoginToken?, ExportAuthTransferTokenError> in
                switch result {
                case let .password(passwordData):
                    let hint = passwordData.hint
                    return account.postbox.transaction { transaction -> Api.auth.LoginToken? in
                        transaction.setState(UnauthorizedAccountState(isTestingEnvironment: account.testingEnvironment, masterDatacenterId: account.masterDatacenterId, contents: .passwordEntry(hint: hint ?? "", number: nil, code: nil, suggestReset: false, syncContacts: syncContacts)))
                        return nil
                    }
                    |> castError(ExportAuthTransferTokenError.self)
                }
            }
        } else {
            return .fail(.generic)
        }
    }
    |> mapToSignal { result -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
        guard let result = result else {
            return .single(.passwordRequested(account))
        }
        switch result {
        case let .loginToken(loginTokenData):
            let (expires, token) = (loginTokenData.expires, loginTokenData.token)
            return .single(.displayToken(AuthTransferExportedToken(value: token.makeData(), validUntil: expires)))
        case let .loginTokenMigrateTo(loginTokenMigrateToData):
            let (dcId, token) = (loginTokenMigrateToData.dcId, loginTokenMigrateToData.token)
            let updatedAccount = account.changedMasterDatacenterId(accountManager: accountManager, masterDatacenterId: dcId)
            return updatedAccount
            |> castError(ExportAuthTransferTokenError.self)
            |> mapToSignal { updatedAccount -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                return updatedAccount.network.request(Api.functions.auth.importLoginToken(token: token))
                |> map(Optional.init)
                |> `catch` { error -> Signal<Api.auth.LoginToken?, ExportAuthTransferTokenError> in
                    if error.errorDescription == "SESSION_PASSWORD_NEEDED" {
                        return updatedAccount.network.request(Api.functions.account.getPassword(), automaticFloodWait: false)
                        |> mapError { error -> ExportAuthTransferTokenError in
                            if error.errorDescription.hasPrefix("FLOOD_WAIT") {
                                return .limitExceeded
                            } else {
                                return .generic
                            }
                        }
                        |> mapToSignal { result -> Signal<Api.auth.LoginToken?, ExportAuthTransferTokenError> in
                            switch result {
                            case let .password(passwordData):
                                let hint = passwordData.hint
                                return updatedAccount.postbox.transaction { transaction -> Api.auth.LoginToken? in
                                    transaction.setState(UnauthorizedAccountState(isTestingEnvironment: updatedAccount.testingEnvironment, masterDatacenterId: updatedAccount.masterDatacenterId, contents: .passwordEntry(hint: hint ?? "", number: nil, code: nil, suggestReset: false, syncContacts: syncContacts)))
                                    return nil
                                }
                                |> castError(ExportAuthTransferTokenError.self)
                            }
                        }
                    } else {
                        return .fail(.generic)
                    }
                }
                |> mapToSignal { result -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                    guard let result = result else {
                        return .single(.passwordRequested(updatedAccount))
                    }
                    switch result {
                    case let .loginTokenSuccess(loginTokenSuccessData):
                        let authorization = loginTokenSuccessData.authorization
                        switch authorization {
                        case let .authorization(authorizationData):
                            let (futureAuthToken, apiUser) = (authorizationData.futureAuthToken, authorizationData.user)
                            if let futureAuthToken = futureAuthToken {
                                storeFutureLoginToken(accountManager: accountManager, token: futureAuthToken.makeData())
                            }

                            return updatedAccount.postbox.transaction { transaction -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                                let user = TelegramUser(user: apiUser)
                                let state = AuthorizedAccountState(isTestingEnvironment: updatedAccount.testingEnvironment, masterDatacenterId: updatedAccount.masterDatacenterId, peerId: user.id, state: nil, invalidatedChannels: [])
                                initializedAppSettingsAfterLogin(transaction: transaction, appVersion: updatedAccount.networkArguments.appVersion, syncContacts: syncContacts)
                                transaction.setState(state)
                                return accountManager.transaction { transaction -> Bool in
                                    return completeAuthTransferAccount(transaction: transaction, account: updatedAccount)
                                }
                                |> castError(ExportAuthTransferTokenError.self)
                                |> mapToSignal { completed -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                                    return completed ? .single(.loggedIn) : .fail(.generic)
                                }
                            }
                            |> castError(ExportAuthTransferTokenError.self)
                            |> switchToLatest
                        default:
                            return .fail(.generic)
                        }
                    default:
                        return .single(.changeAccountAndRetry(updatedAccount))
                    }
                }
            }
        case let .loginTokenSuccess(loginTokenSuccessData):
            let authorization = loginTokenSuccessData.authorization
            switch authorization {
            case let .authorization(authorizationData):
                let (futureAuthToken, apiUser) = (authorizationData.futureAuthToken, authorizationData.user)
                if let futureAuthToken = futureAuthToken {
                    storeFutureLoginToken(accountManager: accountManager, token: futureAuthToken.makeData())
                }

                return account.postbox.transaction { transaction -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                    let user = TelegramUser(user: apiUser)
                    let state = AuthorizedAccountState(isTestingEnvironment: account.testingEnvironment, masterDatacenterId: account.masterDatacenterId, peerId: user.id, state: nil, invalidatedChannels: [])
                    initializedAppSettingsAfterLogin(transaction: transaction, appVersion: account.networkArguments.appVersion, syncContacts: syncContacts)
                    transaction.setState(state)
                    return accountManager.transaction { transaction -> Bool in
                        return completeAuthTransferAccount(transaction: transaction, account: account)
                    }
                    |> castError(ExportAuthTransferTokenError.self)
                    |> mapToSignal { completed -> Signal<ExportAuthTransferTokenResult, ExportAuthTransferTokenError> in
                        return completed ? .single(.loggedIn) : .fail(.generic)
                    }
                }
                |> castError(ExportAuthTransferTokenError.self)
                |> switchToLatest
            case .authorizationSignUpRequired:
                return .fail(.generic)
            }
        }
    }
}

public enum ApproveAuthTransferTokenError {
    case generic
    case invalid
    case expired
    case alreadyAccepted
}

public func approveAuthTransferToken(account: Account, token: Data, activeSessionsContext: ActiveSessionsContext) -> Signal<RecentAccountSession, ApproveAuthTransferTokenError> {
    return account.network.request(Api.functions.auth.acceptLoginToken(token: Buffer(data: token)))
    |> mapError { error -> ApproveAuthTransferTokenError in
        switch error.errorDescription {
        case "AUTH_TOKEN_INVALID":
            return .invalid
        case "AUTH_TOKEN_EXPIRED":
            return .expired
        case "AUTH_TOKEN_ALREADY_ACCEPTED":
            return .alreadyAccepted
        default:
            return .generic
        }
    }
    |> mapToSignal { authorization -> Signal<RecentAccountSession, ApproveAuthTransferTokenError> in
        let session = RecentAccountSession(apiAuthorization: authorization)
        activeSessionsContext.addSession(session)
        return .single(session)
    }
}
