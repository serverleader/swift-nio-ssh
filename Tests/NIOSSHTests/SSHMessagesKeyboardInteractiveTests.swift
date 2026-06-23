import NIOCore
import XCTest
@testable import NIOSSH

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
}
