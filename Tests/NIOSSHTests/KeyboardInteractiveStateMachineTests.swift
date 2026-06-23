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
import NIOEmbedded
@testable import NIOSSH
import XCTest

// MARK: - Stub delegates

/// A client delegate that offers keyboard-interactive once, then gives up.
private final class KeyboardInteractiveDelegate: NIOSSHClientUserAuthenticationDelegate {
    let username: String

    // Captures what the state machine handed to nextKeyboardInteractiveResponse.
    var capturedName: String?
    var capturedInstruction: String?
    var capturedPrompts: [NIOSSHKeyboardInteractivePromptField]?
    // The test fulfils this promise to inject the response.
    var capturedResponsePromise: EventLoopPromise<[String]?>?

    init(username: String = "foo") {
        self.username = username
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.keyboardInteractive) else {
            nextChallengePromise.succeed(nil)
            return
        }
        let offer = NIOSSHUserAuthenticationOffer(
            username: self.username,
            serviceName: "",
            offer: .keyboardInteractive(.init())
        )
        nextChallengePromise.succeed(offer)
    }

    func nextKeyboardInteractiveResponse(
        name: String,
        instruction: String,
        prompts: [NIOSSHKeyboardInteractivePromptField],
        responsePromise: EventLoopPromise<[String]?>
    ) {
        self.capturedName = name
        self.capturedInstruction = instruction
        self.capturedPrompts = prompts
        self.capturedResponsePromise = responsePromise
        // The test drives the response manually — do not fulfil the promise here.
    }
}

// MARK: - Tests

final class KeyboardInteractiveStateMachineTests: XCTestCase {
    var loop: EmbeddedEventLoop!
    var sessionID: ByteBuffer!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeBytes(0 ..< 32)
        self.sessionID = buffer
    }

    override func tearDown() {
        try! self.loop.syncShutdownGracefully()
        self.loop = nil
        self.sessionID = nil
    }

    // MARK: - Helper

    /// Drives the state machine through service request / accept, returning
    /// the `UserAuthRequestMessage` the delegate produced (the KI offer).
    private func driveToKIRequest(
        stateMachine: inout UserAuthenticationStateMachine
    ) throws -> SSHMessage.UserAuthRequestMessage {
        // beginAuthentication
        let serviceReqMsg = stateMachine.beginAuthentication()
        XCTAssertNotNil(serviceReqMsg)

        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        // receive service accept -> state machine asks delegate for next method
        var producedAuthRequest: SSHMessage.UserAuthRequestMessage?
        let future = try XCTUnwrap(stateMachine.receiveServiceAccept(.init(service: "ssh-userauth")))
        future.whenComplete { result in
            switch result {
            case .success(let msg):
                producedAuthRequest = msg
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        let authRequest = try XCTUnwrap(producedAuthRequest)
        // Verify method is keyboard-interactive
        guard case .keyboardInteractive = authRequest.method else {
            XCTFail("Expected keyboard-interactive method, got \(authRequest.method)")
            throw NIOSSHError.protocolViolation(protocolName: "userauth", violation: "wrong method")
        }
        return authRequest
    }

    // MARK: - Test 1: Full happy-path flow (A5 core)

    /// Drives the state machine client through a complete keyboard-interactive exchange:
    /// offer → INFO_REQUEST → INFO_RESPONSE → userAuthSuccess.
    func testKeyboardInteractiveHappyPathFlow() throws {
        let delegate = KeyboardInteractiveDelegate(username: "alice")
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )

        // Step 1: drive to keyboard-interactive request
        let kiRequest = try self.driveToKIRequest(stateMachine: &stateMachine)
        stateMachine.sendUserAuthRequest(kiRequest)

        // After sendUserAuthRequest with KI method, flag must be set.
        XCTAssertTrue(stateMachine.expectingKeyboardInteractive,
                      "expectingKeyboardInteractive must be true after sending KI request")

        // Step 2: server sends INFO_REQUEST with one echo=false prompt
        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "Google Authenticator",
            instruction: "Open the app and enter the code.",
            languageTag: "",
            prompts: [.init(prompt: "Verification code: ", echo: false)]
        )
        let responseFuture = try XCTUnwrap(
            try stateMachine.receiveUserAuthInfoRequest(infoRequest),
            "receiveUserAuthInfoRequest must return a non-nil future"
        )

        // Step 3: assert delegate was invoked with correct parameters
        XCTAssertEqual(delegate.capturedName, "Google Authenticator")
        XCTAssertEqual(delegate.capturedInstruction, "Open the app and enter the code.")
        XCTAssertEqual(delegate.capturedPrompts?.count, 1)
        XCTAssertEqual(delegate.capturedPrompts?.first?.prompt, "Verification code: ")
        XCTAssertEqual(delegate.capturedPrompts?.first?.echo, false)

        // Step 4: fulfil the response promise with ["123456"]
        let responsePromise = try XCTUnwrap(delegate.capturedResponsePromise)
        responsePromise.succeed(["123456"])

        // Resolve futures on the loop
        var producedResponse: SSHMessage.UserAuthInfoResponseMessage?
        responseFuture.whenComplete { result in
            switch result {
            case .success(let msg):
                producedResponse = msg
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
        }
        self.loop.run()

        // Step 5: assert INFO_RESPONSE contains the right answer
        let infoResponse = try XCTUnwrap(producedResponse,
                                         "INFO_RESPONSE must be produced after fulfilling the promise")
        XCTAssertEqual(infoResponse, SSHMessage.UserAuthInfoResponseMessage(responses: ["123456"]))

        // expectingKeyboardInteractive must still be set (server may send another challenge)
        XCTAssertTrue(stateMachine.expectingKeyboardInteractive,
                      "expectingKeyboardInteractive must remain true after INFO_RESPONSE (server may retry)")

        // Step 6: server sends userAuthSuccess → state should become succeeded
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())

        // Flag is cleared on success
        XCTAssertFalse(stateMachine.expectingKeyboardInteractive,
                       "expectingKeyboardInteractive must be cleared on auth success")
    }

    // MARK: - Test 2: Flag lifecycle (A4 review carry-over, Minor #2)

    /// Verifies the `expectingKeyboardInteractive` flag lifecycle:
    ///   - Set after sending a KI request.
    ///   - Remains set across an INFO_REQUEST / INFO_RESPONSE round-trip (so a server retry
    ///     of INFO_REQUEST after a wrong code is still routed correctly).
    ///   - Cleared on `userAuthSuccess`.
    ///   - Cleared on `userAuthFailure`.
    func testExpectingKeyboardInteractiveFlagLifecycle() throws {
        // --- Sub-test A: flag cleared on failure ---
        do {
            let delegateA = KeyboardInteractiveDelegate()
            var sm = UserAuthenticationStateMachine(
                role: .client(.init(userAuthDelegate: delegateA, serverAuthDelegate: AcceptAllHostKeysDelegate())),
                loop: self.loop,
                sessionID: self.sessionID
            )

            let kiRequest = try self.driveToKIRequest(stateMachine: &sm)
            sm.sendUserAuthRequest(kiRequest)

            // Flag is set after sending KI request
            XCTAssertTrue(sm.expectingKeyboardInteractive, "flag must be set after sending KI request")

            // Server rejects — flag must be cleared
            let failureMsg = SSHMessage.UserAuthFailureMessage(
                authentications: ["keyboard-interactive"],
                partialSuccess: false
            )
            let nextMethodFuture = try XCTUnwrap(sm.receiveUserAuthFailure(failureMsg))
            self.loop.run()
            _ = try nextMethodFuture.wait()
            XCTAssertFalse(sm.expectingKeyboardInteractive, "flag must be cleared on userAuthFailure")
        }

        // --- Sub-test B: flag survives INFO_RESPONSE (retry scenario) ---
        do {
            let delegateB = KeyboardInteractiveDelegate()
            var sm = UserAuthenticationStateMachine(
                role: .client(.init(userAuthDelegate: delegateB, serverAuthDelegate: AcceptAllHostKeysDelegate())),
                loop: self.loop,
                sessionID: self.sessionID
            )

            let kiRequest = try self.driveToKIRequest(stateMachine: &sm)
            sm.sendUserAuthRequest(kiRequest)
            XCTAssertTrue(sm.expectingKeyboardInteractive, "flag set after KI request")

            // Server sends first INFO_REQUEST — delegate captures the promise
            let infoRequest1 = SSHMessage.UserAuthInfoRequestMessage(
                name: "PAM", instruction: "", languageTag: "",
                prompts: [.init(prompt: "Code: ", echo: false)]
            )
            let future1 = try XCTUnwrap(try sm.receiveUserAuthInfoRequest(infoRequest1))
            delegateB.capturedResponsePromise?.succeed(["wrong"])
            self.loop.run()
            _ = try future1.wait() // consume future

            // Flag must still be set after the first INFO_RESPONSE
            XCTAssertTrue(sm.expectingKeyboardInteractive,
                          "flag must survive INFO_RESPONSE (server may issue a retry INFO_REQUEST)")

            // Server sends a SECOND INFO_REQUEST (retry after wrong code) — must still be accepted.
            // Reuse delegateB: the second call to nextKeyboardInteractiveResponse overwrites its captured fields.
            let future2 = try XCTUnwrap(try sm.receiveUserAuthInfoRequest(
                SSHMessage.UserAuthInfoRequestMessage(
                    name: "PAM", instruction: "", languageTag: "",
                    prompts: [.init(prompt: "Code: ", echo: false)]
                )
            ), "second INFO_REQUEST must be accepted while flag is still set")
            // Fulfil and verify the second response resolves cleanly
            delegateB.capturedResponsePromise?.succeed(["123456"])
            self.loop.run()
            _ = try future2.wait()

            // Still set (waiting for success/failure from server)
            XCTAssertTrue(sm.expectingKeyboardInteractive)

            // Server grants success
            XCTAssertNoThrow(try sm.receiveUserAuthSuccess())
            XCTAssertFalse(sm.expectingKeyboardInteractive, "flag cleared on success")
        }
    }

    // MARK: - Test 3: Negative byte-60 cross-case (A4 review carry-over, Minor #1)
    // (This test lives here alongside the other negative routing tests.
    //  The same case is also separately exercised in SSHMessagesKeyboardInteractiveTests.swift
    //  if the task brief requires it there; see inline note in that file.)

    /// Feeds an INFO_REQUEST-shaped byte-60 payload to the parser with
    /// `expectingKeyboardInteractive: false`.  The INFO_REQUEST name field
    /// ("Google Authenticator") is not a valid SSH public-key algorithm name,
    /// so `readUserAuthPKOKMessage` must throw `invalidSSHMessage` rather
    /// than silently producing a corrupt `UserAuthPKOKMessage`.
    func testByte60InfoRequestPayloadRejectedAsPKOKWhenFlagNotSet() throws {
        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "Google Authenticator",
            instruction: "Enter your TOTP code",
            languageTag: "",
            prompts: [.init(prompt: "Code: ", echo: false)]
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(.userAuthInfoRequest(infoRequest))

        // First byte must be 60 (the shared message number).
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 60,
                       "INFO_REQUEST must carry message byte 60")

        // Without the flag, the parser tries to read this as PK_OK.
        // The INFO_REQUEST name is not a known key algorithm, so it must throw.
        XCTAssertThrowsError(try buffer.readSSHMessage(expectingKeyboardInteractive: false)) { error in
            guard let nioError = error as? NIOSSHError else {
                XCTFail("Expected NIOSSHError, got \(error)")
                return
            }
            XCTAssertEqual(nioError.type, .invalidSSHMessage,
                           "Parser must throw invalidSSHMessage, not silently misparse INFO_REQUEST as PK_OK")
        }
    }
}
