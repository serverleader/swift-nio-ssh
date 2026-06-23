import Crypto
import NIOCore
@testable import NIOSSH
import XCTest

final class SSHMessagesKeyboardInteractiveTests: XCTestCase {
    func test_infoRequest_roundTrips() {
        let original = SSHMessage.UserAuthInfoRequestMessage(
            name: "Google Authenticator",
            instruction: "",
            languageTag: "",
            prompts: [.init(prompt: "Verification code: ", echo: false),
                      .init(prompt: "Password: ", echo: false)]
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        let written = buffer.writeUserAuthInfoRequestMessage(original)
        XCTAssertGreaterThan(written, 0)
        let decoded = buffer.readUserAuthInfoRequestMessage()
        XCTAssertEqual(decoded, original)
    }

    func test_infoResponse_roundTrips() {
        let original = SSHMessage.UserAuthInfoResponseMessage(responses: ["123456", "hunter2"])
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        _ = buffer.writeUserAuthInfoResponseMessage(original)
        XCTAssertEqual(buffer.readUserAuthInfoResponseMessage(), original)
    }

    func test_availableMethods_parses_keyboardInteractive() {
        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["publickey", "keyboard-interactive"], partialSuccess: false)
        let methods = NIOSSHAvailableUserAuthenticationMethods(failure)
        XCTAssertTrue(methods.contains(.keyboardInteractive))
        XCTAssertTrue(methods.contains(.publicKey))
        XCTAssertEqual(Set(methods.strings.map(String.init)), ["publickey", "keyboard-interactive"])
    }

    // MARK: - Byte 60 disambiguation (PK_OK vs INFO_REQUEST)

    /// Without a keyboard-interactive request outstanding (the default), a byte-60 packet
    /// must still decode as SSH_MSG_USERAUTH_PK_OK. This guards the pre-existing behaviour.
    func test_byte60_defaultsToPKOK() throws {
        let key = NIOSSHPrivateKey(ed25519Key: .init())
        let pkOK = SSHMessage.userAuthPKOK(.init(key: key.publicKey))
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(pkOK)

        // expectingKeyboardInteractive defaults to false.
        let decoded = try buffer.readSSHMessage()
        XCTAssertEqual(decoded, pkOK)
    }

    /// When a keyboard-interactive request is outstanding, a byte-60 packet must decode as
    /// SSH_MSG_USERAUTH_INFO_REQUEST instead of PK_OK.
    func test_byte60_routesToInfoRequest_whenExpectingKeyboardInteractive() throws {
        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "PAM",
            instruction: "Please authenticate",
            languageTag: "",
            prompts: [.init(prompt: "Verification code: ", echo: false)]
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(.userAuthInfoRequest(infoRequest))

        let decoded = try buffer.readSSHMessage(expectingKeyboardInteractive: true)
        guard case .userAuthInfoRequest(let decodedRequest) = decoded else {
            return XCTFail("Expected .userAuthInfoRequest, got \(String(describing: decoded))")
        }
        XCTAssertEqual(decodedRequest, infoRequest)
    }

    /// The same wire byte (60) routes to *different* messages purely based on the flag.
    /// This is the crux of the disambiguation: an INFO_REQUEST payload parsed without the
    /// flag would be (mis)read as PK_OK, so the flag is what makes parsing correct.
    func test_byte60_flagDrivesRouting() throws {
        // An INFO_REQUEST with an empty prompt list also happens to be a structurally valid
        // PK_OK-shaped prefix is not guaranteed, so we only assert the positive routings:
        // with the flag set we get INFO_REQUEST; a PK_OK without the flag stays PK_OK.
        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "", instruction: "", languageTag: "", prompts: []
        )
        var infoBuffer = ByteBufferAllocator().buffer(capacity: 64)
        infoBuffer.writeSSHMessage(.userAuthInfoRequest(infoRequest))
        // First byte must be 60.
        XCTAssertEqual(infoBuffer.getInteger(at: infoBuffer.readerIndex, as: UInt8.self), 60)
        let decodedInfo = try infoBuffer.readSSHMessage(expectingKeyboardInteractive: true)
        guard case .userAuthInfoRequest = decodedInfo else {
            return XCTFail("Expected .userAuthInfoRequest with flag set, got \(String(describing: decodedInfo))")
        }

        let key = NIOSSHPrivateKey(ed25519Key: .init())
        let pkOK = SSHMessage.userAuthPKOK(.init(key: key.publicKey))
        var pkBuffer = ByteBufferAllocator().buffer(capacity: 256)
        pkBuffer.writeSSHMessage(pkOK)
        XCTAssertEqual(pkBuffer.getInteger(at: pkBuffer.readerIndex, as: UInt8.self), 60)
        let decodedPK = try pkBuffer.readSSHMessage(expectingKeyboardInteractive: false)
        XCTAssertEqual(decodedPK, pkOK)
    }
}
