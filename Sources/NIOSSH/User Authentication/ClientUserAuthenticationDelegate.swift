//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A single prompt field in a keyboard-interactive (RFC 4256) challenge.
///
/// `prompt` is the human-readable question to display; `echo` indicates whether
/// the user's input should be echoed on screen (e.g. `false` for passwords).
public struct NIOSSHKeyboardInteractivePromptField: Sendable, Equatable {
    public let prompt: String
    public let echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentictation methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>)
}

public extension NIOSSHClientUserAuthenticationDelegate {
    /// Called when the server issues a keyboard-interactive (RFC 4256) challenge.
    /// Fulfil `responsePromise` with one response per prompt, or `nil` to abort.
    func nextKeyboardInteractiveResponse(
        name: String,
        instruction: String,
        prompts: [NIOSSHKeyboardInteractivePromptField],
        responsePromise: EventLoopPromise<[String]?>
    ) {
        responsePromise.succeed(nil) // default: cannot answer → abort this method
    }
}
