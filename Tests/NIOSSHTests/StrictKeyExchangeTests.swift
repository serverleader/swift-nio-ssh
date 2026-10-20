//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
@testable import NIOSSH
import XCTest

/// A transport protection whose MAC covers the packet sequence number, like hmac-sha2-* in RFC 4253 section 6.4
/// (`mac = MAC(key, sequence_number || unencrypted_packet)`), so any sequence number desync between the peers fails
/// the connection. The payload is left in the clear: these tests are about sequence numbers, not confidentiality.
///
/// Each instance (one per key exchange per peer) records the sequence numbers it used, so tests can check where
/// the numbering restarted after NEWKEYS.
final class SequenceNumberMACTransportProtection: NIOSSHTransportProtection {
    struct SequenceNumberMismatch: Error {}

    static let instances = NIOLockedValueBox<[SequenceNumberMACTransportProtection]>([])

    static var cipherBlockSize: Int { 16 }
    static var cipherName: String { "insecure-sequence-number-mac-cipher" }
    static var macNames: [String] { [] }
    static func keySizes(forMac mac: String?) throws -> ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }

    var macBytes: Int { 32 }

    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey
    private(set) var outboundSequenceNumbers: [UInt32] = []
    private(set) var inboundSequenceNumbers: [UInt32] = []

    required init(initialKeys: NIOSSHSessionKeys, mac: String?) throws {
        self.outboundMACKey = initialKeys.outboundMACKey
        self.inboundMACKey = initialKeys.inboundMACKey
        Self.instances.withLockedValue { $0.append(self) }
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        self.outboundMACKey = newKeys.outboundMACKey
        self.inboundMACKey = newKeys.inboundMACKey
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // Identity cipher: the length is already in the clear.
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        guard source.readableBytes > self.macBytes,
              var plaintext = source.readSlice(length: source.readableBytes - self.macBytes),
              let tag = source.readSlice(length: self.macBytes)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        self.inboundSequenceNumbers.append(sequenceNumber)

        var hmac = HMAC<SHA256>(key: self.inboundMACKey)
        hmac.update(data: withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) })
        hmac.update(data: plaintext.readableBytesView)
        guard Data(hmac.finalize()) == Data(tag.readableBytesView) else {
            throw SequenceNumberMismatch()
        }

        plaintext.moveReaderIndex(forwardBy: 4)
        let paddingLength = plaintext.readInteger(as: UInt8.self)!
        return plaintext.readSlice(length: plaintext.readableBytes - Int(paddingLength))!
    }

    func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer, sequenceNumber: UInt32) throws {
        self.outboundSequenceNumbers.append(sequenceNumber)
        let packetLengthIndex = outboundBuffer.writerIndex
        outboundBuffer.moveWriterIndex(forwardBy: 5)
        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        var packetSize = payloadBytes + 5
        var paddingBytes = Self.cipherBlockSize - (packetSize % Self.cipherBlockSize)
        if paddingBytes < 4 {
            paddingBytes += Self.cipherBlockSize
        }
        packetSize += outboundBuffer.writeSSHPaddingBytes(count: paddingBytes)
        outboundBuffer.setInteger(UInt32(packetSize - 4), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(paddingBytes), at: packetLengthIndex + 4)

        var hmac = HMAC<SHA256>(key: self.outboundMACKey)
        hmac.update(data: withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) })
        hmac.update(data: outboundBuffer.viewBytes(at: packetLengthIndex, length: packetSize)!)
        outboundBuffer.writeBytes(hmac.finalize())
    }
}

final class StrictKeyExchangeTests: XCTestCase {
    private let allocator = ByteBufferAllocator()
    private var loop: EmbeddedEventLoop!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        SequenceNumberMACTransportProtection.instances.withLockedValue { $0.removeAll() }
    }

    override func tearDown() {
        XCTAssertNoThrow(try self.loop.syncShutdownGracefully())
        self.loop = nil
        SequenceNumberMACTransportProtection.instances.withLockedValue { $0.removeAll() }
    }

    // MARK: Helpers

    private enum Side { case client, server }

    private static let clientMarker: Substring = "kex-strict-c-v00@openssh.com"
    private static let serverMarker: Substring = "kex-strict-s-v00@openssh.com"

    /// Rewrites outbound messages before they hit the wire, e.g. to model a peer that does not advertise strict KEX.
    private typealias Rewrite = (Side, SSHMessage) -> SSHMessage

    private static func stripStrictMarker(from side: Side) -> Rewrite {
        { sender, message in
            guard sender == side, case .keyExchange(var kexInit) = message else { return message }
            kexInit.keyExchangeAlgorithms.removeAll { $0 == clientMarker || $0 == serverMarker }
            return .keyExchange(kexInit)
        }
    }

    private func makePair(schemes: [NIOSSHTransportProtection.Type] = [SequenceNumberMACTransportProtection.self]) -> (SSHConnectionStateMachine, SSHConnectionStateMachine) {
        var clientConfig = SSHClientConfiguration(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
        clientConfig.transportProtectionSchemes = schemes
        var serverConfig = SSHServerConfiguration(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0))
        serverConfig.transportProtectionSchemes = schemes
        return (SSHConnectionStateMachine(role: .client(clientConfig)), SSHConnectionStateMachine(role: .server(serverConfig)))
    }

    /// Spins both state machines until neither has anything left to send. Throws the first inbound error.
    private func run(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine,
                     clientMessages: [SSHMessage] = [], serverMessages: [SSHMessage] = [],
                     rewrite: Rewrite = { $1 }) throws {
        let pendingClient = NIOLockedValueBox<[SSHMessage]>(clientMessages)
        let pendingServer = NIOLockedValueBox<[SSHMessage]>(serverMessages)
        var clientBuffer = self.allocator.buffer(capacity: 1024)
        var serverBuffer = self.allocator.buffer(capacity: 1024)

        func handle(_ result: SSHConnectionStateMachine.StateMachineInboundProcessResult, into pending: NIOLockedValueBox<[SSHMessage]>) {
            switch result {
            case .emitMessage(let multi):
                pending.withLockedValue { $0.append(contentsOf: multi) }
            case .possibleFutureMessage(let future):
                future.whenSuccess { multi in
                    if let multi = multi { pending.withLockedValue { $0.append(contentsOf: multi) } }
                }
            case .noMessage, .forwardToMultiplexer, .globalRequest, .globalRequestResponse, .disconnect, .event:
                ()
            }
        }

        for _ in 0..<100 {
            let toClient = pendingClient.withLockedValue { p -> [SSHMessage] in defer { p.removeAll() }; return p }
            let toServer = pendingServer.withLockedValue { p -> [SSHMessage] in defer { p.removeAll() }; return p }
            if toClient.isEmpty, toServer.isEmpty, clientBuffer.readableBytes == 0, serverBuffer.readableBytes == 0 {
                self.loop.run()
                if pendingClient.withLockedValue({ $0.isEmpty }), pendingServer.withLockedValue({ $0.isEmpty }) {
                    return
                }
                continue
            }
            for message in toClient {
                try client.processOutboundMessage(rewrite(.client, message), buffer: &clientBuffer, allocator: self.allocator, loop: self.loop)
            }
            for message in toServer {
                try server.processOutboundMessage(rewrite(.server, message), buffer: &serverBuffer, allocator: self.allocator, loop: self.loop)
            }
            server.bufferInboundData(&clientBuffer)
            clientBuffer.clear()
            client.bufferInboundData(&serverBuffer)
            serverBuffer.clear()

            while let result = try client.processInboundMessage(allocator: self.allocator, loop: self.loop) {
                handle(result, into: pendingClient)
            }
            while let result = try server.processInboundMessage(allocator: self.allocator, loop: self.loop) {
                handle(result, into: pendingServer)
            }
            self.loop.run()
        }
        XCTFail("connection did not settle")
    }

    private func connect(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, rewrite: Rewrite = { $1 }) throws {
        try self.run(client: &client, server: &server,
                     clientMessages: Array(client.start()!), serverMessages: Array(server.start()!), rewrite: rewrite)
        XCTAssertTrue(client.isActive)
        XCTAssertTrue(server.isActive)
    }

    private func rekey(initiator: Side, client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, rewrite: Rewrite = { $1 }) throws {
        var buffer = self.allocator.buffer(capacity: 1024)
        switch initiator {
        case .client:
            try client.beginRekeying(buffer: &buffer, allocator: self.allocator, loop: self.loop)
            server.bufferInboundData(&buffer)
            var serverMessages: [SSHMessage] = []
            while let result = try server.processInboundMessage(allocator: self.allocator, loop: self.loop) {
                if case .emitMessage(let multi) = result { serverMessages.append(contentsOf: multi) }
            }
            try self.run(client: &client, server: &server, serverMessages: serverMessages, rewrite: rewrite)
        case .server:
            try server.beginRekeying(buffer: &buffer, allocator: self.allocator, loop: self.loop)
            client.bufferInboundData(&buffer)
            var clientMessages: [SSHMessage] = []
            while let result = try client.processInboundMessage(allocator: self.allocator, loop: self.loop) {
                if case .emitMessage(let multi) = result { clientMessages.append(contentsOf: multi) }
            }
            try self.run(client: &client, server: &server, clientMessages: clientMessages, rewrite: rewrite)
        }
        XCTAssertTrue(client.isActive)
        XCTAssertTrue(server.isActive)
    }

    /// Sends a channel data message each way and checks it arrives intact (the MAC binds the sequence number).
    private func assertDataFlows(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine, count: Int = 3) throws {
        for (sender, receiver) in [(Side.client, Side.server), (Side.server, Side.client)] {
            for i in 0..<count {
                let message = SSHMessage.channelData(.init(recipientChannel: UInt32(i), data: ByteBuffer(repeating: UInt8(i), count: 100)))
                var buffer = self.allocator.buffer(capacity: 1024)
                if sender == .client {
                    try client.processOutboundMessage(message, buffer: &buffer, allocator: self.allocator, loop: self.loop)
                } else {
                    try server.processOutboundMessage(message, buffer: &buffer, allocator: self.allocator, loop: self.loop)
                }
                let result: SSHConnectionStateMachine.StateMachineInboundProcessResult?
                if receiver == .server {
                    server.bufferInboundData(&buffer)
                    result = try server.processInboundMessage(allocator: self.allocator, loop: self.loop)
                } else {
                    client.bufferInboundData(&buffer)
                    result = try client.processInboundMessage(allocator: self.allocator, loop: self.loop)
                }
                guard case .some(.forwardToMultiplexer(let received)) = result else {
                    XCTFail("Unexpected result \(String(describing: result))")
                    return
                }
                XCTAssertEqual(received, message)
            }
        }
    }

    private var protections: [SequenceNumberMACTransportProtection] {
        SequenceNumberMACTransportProtection.instances.withLockedValue { $0 }
    }

    /// Drives version exchange and returns the server's KEXINIT plus the client's KEXINIT, without processing them.
    private func exchangeVersions(client: inout SSHConnectionStateMachine, server: inout SSHConnectionStateMachine) throws -> (clientKexInit: SSHMessage, serverKexInit: SSHMessage) {
        var clientBuffer = self.allocator.buffer(capacity: 1024)
        var serverBuffer = self.allocator.buffer(capacity: 1024)
        try client.processOutboundMessage(client.start()!.first!, buffer: &clientBuffer, allocator: self.allocator, loop: self.loop)
        try server.processOutboundMessage(server.start()!.first!, buffer: &serverBuffer, allocator: self.allocator, loop: self.loop)
        server.bufferInboundData(&clientBuffer)
        client.bufferInboundData(&serverBuffer)
        guard case .some(.emitMessage(let clientKexInit)) = try client.processInboundMessage(allocator: self.allocator, loop: self.loop),
              case .some(.emitMessage(let serverKexInit)) = try server.processInboundMessage(allocator: self.allocator, loop: self.loop)
        else {
            XCTFail("expected KEXINIT")
            throw SequenceNumberMACTransportProtection.SequenceNumberMismatch()
        }
        return (clientKexInit.first!, serverKexInit.first!)
    }

    private func assertStrictViolation(_ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation, "\(error)", file: file, line: line)
        }
    }

    // MARK: Negotiation

    func testInitialKexInitAdvertisesMarkerAndRekeyDoesNot() throws {
        var (client, server) = self.makePair()
        let (clientKexInit, serverKexInit) = try self.exchangeVersions(client: &client, server: &server)
        guard case .keyExchange(let c) = clientKexInit, case .keyExchange(let s) = serverKexInit else { return XCTFail() }
        XCTAssertTrue(c.keyExchangeAlgorithms.contains(Self.clientMarker))
        XCTAssertFalse(c.keyExchangeAlgorithms.contains(Self.serverMarker))
        XCTAssertTrue(s.keyExchangeAlgorithms.contains(Self.serverMarker))
        XCTAssertFalse(s.keyExchangeAlgorithms.contains(Self.clientMarker))

        // Rekey KEXINITs omit the marker: it is only valid in the initial KEXINIT.
        (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        var sawRekeyKexInit = false
        try self.rekey(initiator: .server, client: &client, server: &server) { _, message in
            if case .keyExchange(let kexInit) = message {
                sawRekeyKexInit = true
                XCTAssertFalse(kexInit.keyExchangeAlgorithms.contains(Self.clientMarker))
                XCTAssertFalse(kexInit.keyExchangeAlgorithms.contains(Self.serverMarker))
            }
            return message
        }
        XCTAssertTrue(sawRekeyKexInit)
    }

    func testStrictNegotiatedWhenBothAdvertise() throws {
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        XCTAssertTrue(client.strictKeyExchange)
        XCTAssertTrue(server.strictKeyExchange)
    }

    func testClientDoesNotEnableStrictWhenServerDoesNotAdvertise() throws {
        // AES-GCM ignores the sequence number, so the handshake completes despite the forged one-sided view.
        var (client, server) = self.makePair(schemes: [AES128GCMOpenSSHTransportProtection.self])
        try self.connect(client: &client, server: &server, rewrite: Self.stripStrictMarker(from: .server))
        XCTAssertFalse(client.strictKeyExchange)
    }

    func testServerDoesNotEnableStrictWhenClientDoesNotAdvertise() throws {
        var (client, server) = self.makePair(schemes: [AES128GCMOpenSSHTransportProtection.self])
        try self.connect(client: &client, server: &server, rewrite: Self.stripStrictMarker(from: .client))
        XCTAssertFalse(server.strictKeyExchange)
    }

    func testMarkersAreNotNegotiatedAsKeyExchangeAlgorithms() throws {
        // A peer that offers only the markers has no real KEX algorithm in common with us.
        var (client, server) = self.makePair()
        let rewrite: Rewrite = { sender, message in
            guard sender == .server, case .keyExchange(var kexInit) = message else { return message }
            kexInit.keyExchangeAlgorithms = [Self.serverMarker, Self.clientMarker]
            return .keyExchange(kexInit)
        }
        XCTAssertThrowsError(try self.connect(client: &client, server: &server, rewrite: rewrite)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyExchangeNegotiationFailure)
        }
    }

    // MARK: Sequence number reset (draft-miller-sshm-strict-kex 3.3)

    func testSequenceNumbersResetAfterInitialNewKeys() throws {
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)

        let protections = self.protections
        XCTAssertEqual(protections.count, 2)
        for protection in protections {
            // The first encrypted packet in each direction carries sequence number 0.
            XCTAssertEqual(protection.outboundSequenceNumbers.first, 0)
            XCTAssertEqual(protection.inboundSequenceNumbers.first, 0)
        }
    }

    func testSequenceNumbersResetAfterEveryRekey() throws {
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        try self.rekey(initiator: .client, client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        try self.rekey(initiator: .server, client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        XCTAssertTrue(client.strictKeyExchange)
        XCTAssertTrue(server.strictKeyExchange)

        let protections = self.protections
        XCTAssertEqual(protections.count, 6)  // 3 key exchanges x 2 peers
        for protection in protections {
            XCTAssertEqual(protection.outboundSequenceNumbers.first, 0, "outbound \(protection.outboundSequenceNumbers)")
            XCTAssertEqual(protection.inboundSequenceNumbers.first, 0, "inbound \(protection.inboundSequenceNumbers)")
        }
    }

    func testStrictStaysOnAcrossRekeysWithoutMarker() throws {
        // Rekey KEXINITs carry no marker (see above); strict KEX must stay on for the connection regardless.
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        try self.rekey(initiator: .client, client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        XCTAssertTrue(client.strictKeyExchange)
        XCTAssertEqual(self.protections.last?.outboundSequenceNumbers.first, 0)
    }

    func testNonStrictPeersConnectRekeyAndKeepCounting() throws {
        let stripBoth: Rewrite = { sender, message in
            Self.stripStrictMarker(from: .client)(sender, Self.stripStrictMarker(from: .server)(sender, message))
        }
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server, rewrite: stripBoth)
        XCTAssertFalse(client.strictKeyExchange)
        XCTAssertFalse(server.strictKeyExchange)
        try self.assertDataFlows(client: &client, server: &server)

        // Rekeys in both directions keep working and strict stays off for the connection.
        try self.rekey(initiator: .client, client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        try self.rekey(initiator: .server, client: &client, server: &server)
        try self.assertDataFlows(client: &client, server: &server)
        XCTAssertFalse(client.strictKeyExchange)
        XCTAssertFalse(server.strictKeyExchange)

        // Without strict KEX nothing resets: the first encrypted packet follows KEXINIT, KEX_ECDH_*, NEWKEYS.
        for protection in self.protections {
            XCTAssertNotEqual(protection.outboundSequenceNumbers.first, 0)
        }
    }

    // MARK: Non-KEX messages during the initial KEX (draft-miller-sshm-strict-kex 3.2)

    /// Delivers `version, injected..., KEXINIT` from the server to the client.
    private func deliverServerKexInit(after injected: [SSHMessage], strictServer: Bool) throws {
        var (client, server) = self.makePair()
        let (_, serverKexInit) = try self.exchangeVersions(client: &client, server: &server)
        var buffer = self.allocator.buffer(capacity: 1024)
        for message in injected {
            try server.processOutboundMessage(message, buffer: &buffer, allocator: self.allocator, loop: self.loop)
        }
        let kexInit = strictServer ? serverKexInit : Self.stripStrictMarker(from: .server)(.server, serverKexInit)
        try server.processOutboundMessage(kexInit, buffer: &buffer, allocator: self.allocator, loop: self.loop)
        client.bufferInboundData(&buffer)
        while try client.processInboundMessage(allocator: self.allocator, loop: self.loop) != nil {}
    }

    func testIgnoreBeforeKexInitIsFatalUnderStrict() {
        self.assertStrictViolation { try self.deliverServerKexInit(after: [.ignore(.init(data: ByteBuffer()))], strictServer: true) }
        self.assertStrictViolation { try self.deliverServerKexInit(after: [.debug(.init(alwaysDisplay: false, message: "hi", language: ""))], strictServer: true) }
    }

    func testIgnoreBeforeKexInitIsToleratedWithoutStrict() {
        XCTAssertNoThrow(try self.deliverServerKexInit(after: [.ignore(.init(data: ByteBuffer()))], strictServer: false))
    }

    func testKexInitAsFirstPacketIsAccepted() {
        XCTAssertNoThrow(try self.deliverServerKexInit(after: [], strictServer: true))
    }

    /// Runs the initial KEX but injects `message` from the server right after its KEXINIT.
    private func injectAfterServerKexInit(_ message: SSHMessage, strict: Bool) throws {
        var (client, server) = self.makePair()
        let rewrite: Rewrite = { sender, outbound in
            strict ? outbound : Self.stripStrictMarker(from: sender)(sender, outbound)
        }
        let (clientKexInit, serverKexInit) = try self.exchangeVersions(client: &client, server: &server)

        // Both peers send KEXINIT before seeing the other's (so the rewritten message is the one each side hashes),
        // and the server follows its KEXINIT with the injected message.
        var toServer = self.allocator.buffer(capacity: 1024)
        var toClient = self.allocator.buffer(capacity: 1024)
        try client.processOutboundMessage(rewrite(.client, clientKexInit), buffer: &toServer, allocator: self.allocator, loop: self.loop)
        try server.processOutboundMessage(rewrite(.server, serverKexInit), buffer: &toClient, allocator: self.allocator, loop: self.loop)
        try server.processOutboundMessage(message, buffer: &toClient, allocator: self.allocator, loop: self.loop)
        server.bufferInboundData(&toServer)
        var serverMessages: [SSHMessage] = []
        while let result = try server.processInboundMessage(allocator: self.allocator, loop: self.loop) {
            if case .emitMessage(let multi) = result { serverMessages.append(contentsOf: multi) }
        }
        client.bufferInboundData(&toClient)
        var clientMessages: [SSHMessage] = []
        while let result = try client.processInboundMessage(allocator: self.allocator, loop: self.loop) {
            if case .emitMessage(let multi) = result { clientMessages.append(contentsOf: multi) }
        }
        try self.run(client: &client, server: &server, clientMessages: clientMessages, serverMessages: serverMessages, rewrite: rewrite)
        XCTAssertTrue(client.isActive)
        XCTAssertEqual(client.strictKeyExchange, strict)
    }

    func testIgnoreDuringInitialKexIsFatalUnderStrict() {
        self.assertStrictViolation { try self.injectAfterServerKexInit(.ignore(.init(data: ByteBuffer())), strict: true) }
        self.assertStrictViolation { try self.injectAfterServerKexInit(.debug(.init(alwaysDisplay: true, message: "x", language: "")), strict: true) }
    }

    func testIgnoreDuringInitialKexIsToleratedWithoutStrict() {
        XCTAssertNoThrow(try self.injectAfterServerKexInit(.ignore(.init(data: ByteBuffer())), strict: false))
    }

    func testUnimplementedDuringInitialKexIsFatal() {
        XCTAssertThrowsError(try self.injectAfterServerKexInit(.unimplemented(.init(sequenceNumber: 0)), strict: true))
    }

    func testIgnoreAfterInitialKexIsTolerated() throws {
        var (client, server) = self.makePair()
        try self.connect(client: &client, server: &server)
        var buffer = self.allocator.buffer(capacity: 1024)
        try server.processOutboundMessage(.ignore(.init(data: ByteBuffer())), buffer: &buffer, allocator: self.allocator, loop: self.loop)
        client.bufferInboundData(&buffer)
        XCTAssertNoThrow(try client.processInboundMessage(allocator: self.allocator, loop: self.loop))
        try self.assertDataFlows(client: &client, server: &server)
    }

    func testKexMethodMessageAcceptedOnlyOnce() throws {
        // A replayed KEX_ECDH_INIT must be rejected by the server.
        var (client, server) = self.makePair()
        let (clientKexInit, serverKexInit) = try self.exchangeVersions(client: &client, server: &server)
        var toServer = self.allocator.buffer(capacity: 1024)
        var toClient = self.allocator.buffer(capacity: 1024)
        try client.processOutboundMessage(clientKexInit, buffer: &toServer, allocator: self.allocator, loop: self.loop)
        try server.processOutboundMessage(serverKexInit, buffer: &toClient, allocator: self.allocator, loop: self.loop)
        server.bufferInboundData(&toServer)
        while try server.processInboundMessage(allocator: self.allocator, loop: self.loop) != nil {}
        client.bufferInboundData(&toClient)
        var ecdhInit: SSHMessage?
        while let result = try client.processInboundMessage(allocator: self.allocator, loop: self.loop) {
            if case .emitMessage(let multi) = result { ecdhInit = multi.first }
        }
        guard let ecdhInit = ecdhInit, case .keyExchangeInit = ecdhInit else { return XCTFail("no ECDH init") }

        var initBytes = self.allocator.buffer(capacity: 1024)
        try client.processOutboundMessage(ecdhInit, buffer: &initBytes, allocator: self.allocator, loop: self.loop)
        var replay = initBytes  // cleartext before NEWKEYS, so the bytes can be replayed as-is
        server.bufferInboundData(&initBytes)
        _ = try server.processInboundMessage(allocator: self.allocator, loop: self.loop)
        server.bufferInboundData(&replay)
        XCTAssertThrowsError(try server.processInboundMessage(allocator: self.allocator, loop: self.loop))
    }

    // MARK: Sequence number wrap before the initial KEX completes (draft-miller-sshm-strict-kex 3.2)

    func testOutboundSequenceNumberMayNotWrapBeforeInitialNewKeys() throws {
        var serializer = SSHPacketSerializer()
        var buffer = self.allocator.buffer(capacity: 1024)
        try serializer.serialize(message: .version("SSH-2.0-SwiftNIOSSH_1.0"), to: &buffer)
        serializer._setSequenceNumber(.max)
        XCTAssertThrowsError(try serializer.serialize(message: .ignore(.init(data: ByteBuffer())), to: &buffer)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        // After the initial NEWKEYS, wrapping is allowed (RFC 4253 section 6.4).
        var completed = SSHPacketSerializer()
        try completed.serialize(message: .version("SSH-2.0-SwiftNIOSSH_1.0"), to: &buffer)
        completed.sentNewKeys()
        completed._setSequenceNumber(.max)
        XCTAssertNoThrow(try completed.serialize(message: .ignore(.init(data: ByteBuffer())), to: &buffer))
        XCTAssertEqual(completed.sequenceNumber, 0)
    }

    func testInboundSequenceNumberMayNotWrapBeforeInitialNewKeys() throws {
        var serializer = SSHPacketSerializer()
        var wire = self.allocator.buffer(capacity: 1024)
        try serializer.serialize(message: .version("SSH-2.0-SwiftNIOSSH_1.0"), to: &wire)
        try serializer.serialize(message: .ignore(.init(data: ByteBuffer())), to: &wire)

        var parser = SSHPacketParser(allocator: self.allocator)
        var copy = wire
        parser.append(bytes: &copy)
        XCTAssertNotNil(try parser.nextPacket())  // version
        parser._setSequenceNumber(.max)
        XCTAssertThrowsError(try parser.nextPacket()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }

        var completed = SSHPacketParser(allocator: self.allocator)
        completed.append(bytes: &wire)
        XCTAssertNotNil(try completed.nextPacket())  // version
        completed.receivedNewKeys()
        completed._setSequenceNumber(.max)
        XCTAssertNotNil(try completed.nextPacket())
        XCTAssertEqual(completed.sequenceNumber, 0)
    }

    func testNewKeysResetsSequenceNumbersOnlyUnderStrict() {
        var parser = SSHPacketParser(allocator: self.allocator)
        parser._setSequenceNumber(7)
        parser.receivedNewKeys()
        XCTAssertEqual(parser.sequenceNumber, 7)
        parser.enableStrictKeyExchange()
        parser.receivedNewKeys()
        XCTAssertEqual(parser.sequenceNumber, 0)

        var serializer = SSHPacketSerializer()
        serializer._setSequenceNumber(7)
        serializer.sentNewKeys()
        XCTAssertEqual(serializer.sequenceNumber, 7)
        serializer.enableStrictKeyExchange()
        serializer.sentNewKeys()
        XCTAssertEqual(serializer.sequenceNumber, 0)
    }
}
