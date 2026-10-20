//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

struct SSHPacketSerializer {
    enum State {
        case initialized
        case cleartext
        case encrypted(NIOSSHTransportProtection)
    }

    private var state: State = .initialized
    /// The sequence number of the next outbound packet.
    private(set) var sequenceNumber: UInt32 = 0

    /// Whether strict key exchange (draft-miller-sshm-strict-kex, CVE-2023-48795 / Terrapin) is in effect.
    /// Decided once, from the initial KEXINIT messages.
    private(set) var strictKeyExchange = false

    /// Whether we have sent the SSH_MSG_NEWKEYS that concludes the initial key exchange.
    private var initialKeyExchangeComplete = false

    /// Enables strict key exchange mode for the rest of the connection.
    mutating func enableStrictKeyExchange() {
        self.strictKeyExchange = true
    }

    /// Must be called immediately after an SSH_MSG_NEWKEYS has been sent (initial KEX and every rekey).
    ///
    /// Under strict KEX the outbound sequence number is reset to zero (draft-miller-sshm-strict-kex 3.3).
    mutating func sentNewKeys() {
        self.initialKeyExchangeComplete = true
        if self.strictKeyExchange {
            self.sequenceNumber = 0
        }
    }

    /// Testing only: force the outbound sequence number.
    mutating func _setSequenceNumber(_ sequenceNumber: UInt32) {
        self.sequenceNumber = sequenceNumber
    }

    private mutating func incrementSequenceNumber() throws {
        self.sequenceNumber = self.sequenceNumber &+ 1
        // draft-miller-sshm-strict-kex 3.2 (and OpenSSH): the sequence number must not wrap before the
        // initial key exchange has completed.
        if self.sequenceNumber == 0, !self.initialKeyExchangeComplete {
            throw NIOSSHError.protocolViolation(protocolName: "transport", violation: "Outbound sequence number wrapped during initial key exchange")
        }
    }

    /// Encryption schemes can be added to a packet serializer whenever encryption is negotiated.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartext:
            self.state = .encrypted(protection)
        case .encrypted:
            self.state = .encrypted(protection)
        case .initialized:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func serialize(
        message: SSHMessage,
        to buffer: inout ByteBuffer
    ) throws {
        switch self.state {
        case .initialized:
            switch message {
            case .version:
                buffer.writeSSHMessage(message)
                self.state = .cleartext
            default:
                preconditionFailure("only .version message is allowed at this point")
            }
        case .cleartext:
            let index = buffer.writerIndex

            /// Each packet is in the following format:
            ///
            ///   uint32        packet_length
            ///   byte           padding_length
            ///   byte[n1]  payload; n1 = packet_length - padding_length - 1
            ///   byte[n2]  random padding; n2 = padding_length
            ///   byte[m]   mac (Message Authentication Code - MAC); m = mac_length

            /// payload
            buffer.moveWriterIndex(forwardBy: 5)
            let messageLength = buffer.writeSSHMessage(message)

            /// RFC 4253 § 6:
            /// random padding
            ///   Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding)
            ///   is a multiple of the cipher block size or 8, whichever is larger.  There MUST be at least four bytes of padding.  The
            ///   padding SHOULD consist of random bytes.  The maximum amount of padding is 255 bytes.
            let blockSize = 8
            let paddingLength = 3 + blockSize - ((messageLength + blockSize) % blockSize)

            /// packet_length
            ///   The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
            buffer.setInteger(UInt32(1 + messageLength + paddingLength), at: index)
            /// padding_length
            buffer.setInteger(UInt8(paddingLength), at: index + 4)
            /// random padding
            buffer.writeSSHPaddingBytes(count: paddingLength)
            try self.incrementSequenceNumber()
        case .encrypted(let protection):
            let payload = NIOSSHEncryptablePayload(message: message)
            try protection.encryptPacket(payload, to: &buffer, sequenceNumber: self.sequenceNumber)
            try self.incrementSequenceNumber()
        }
    }
}
