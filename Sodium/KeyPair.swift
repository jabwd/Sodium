//
//  Common.swift
//  Sodium
//
//  Created by Antwan van Houdt on 29/09/2017.
//

import Foundation

public struct KeyPair {
	public static let publicKeySize: Int = Int(crypto_box_PUBLICKEYBYTES)
	public static let secretKeySize: Int = Int(crypto_box_SECRETKEYBYTES)

	public let publicKey: [UInt8]
	public let secretKey: [UInt8]

	init?(_ publicKey: [UInt8], secretKey: [UInt8]) {
		guard publicKey.count == KeyPair.publicKeySize,
			secretKey.count == KeyPair.secretKeySize else {
			return nil
		}
		self.publicKey = publicKey
		self.secretKey = secretKey
	}

	init() {
		var pub = [UInt8](repeating: 0, count: KeyPair.publicKeySize)
		var sec = [UInt8](repeating: 0, count: KeyPair.secretKeySize)

		crypto_box_keypair(&pub, &sec)

		publicKey = pub
		secretKey = sec
	}
}

public struct SigningKeyPair {
	public static let publicKeySize: Int = Int(crypto_sign_PUBLICKEYBYTES)
	public static let secretKeySize: Int = Int(crypto_sign_SECRETKEYBYTES)
	public static let signatureSize: Int = Int(crypto_sign_BYTES)

	public let secretKey: [UInt8]
	public let publicKey: [UInt8]

	/// Initializes using an existing keypair
	public init(_ publicKey: [UInt8], secretKey: [UInt8]) throws {
		guard secretKey.count == SigningKeyPair.secretKeySize else {
			throw SodiumError.invalidSecretKey
		}
		guard publicKey.count == SigningKeyPair.publicKeySize else {
			throw SodiumError.invalidPublicKey
		}
		self.publicKey = publicKey
		self.secretKey = secretKey
	}

	/// Initializes an instance with a newly generated keypair
	public init() {
		var sec = [UInt8](repeating: 0, count: SigningKeyPair.secretKeySize)
		var pub = [UInt8](repeating: 0, count: SigningKeyPair.publicKeySize)

		crypto_sign_keypair(&pub, &sec)

		self.publicKey = pub
		self.secretKey = sec
	}

	/// Attaches a signature to the given bytebuffer that can later be verified
	/// - Parameter message: The message to sign
	/// - Returns: Payload containing the message and a signature
	public func sign(message: [UInt8]) -> [UInt8] {
		var signedMessage: [UInt8] = [UInt8](repeating: 0, count: SigningKeyPair.signatureSize+message.count)
		var signedMessageLength: UInt64 = 0
		crypto_sign(
			&signedMessage,
			&signedMessageLength,
			message,
			UInt64(message.count),
			secretKey
		)
		return signedMessage
	}

	/// Verifies a payload and returns the message without the signature
	/// - Parameter signedMessage: the signed payload to verify
	/// - Throws: SodiumError.invalidSignature when the signature or message is incorrect
	/// - Returns: The message with the signature removed from the payload
	public func verifySignature(_ signedMessage: [UInt8]) throws -> [UInt8] {
		var unsigned: [UInt8] = [UInt8](repeating: 0, count: signedMessage.count-SigningKeyPair.signatureSize)
		var unsignedLength: UInt64 = 0
		let result = crypto_sign_open(
			&unsigned,
			&unsignedLength,
			signedMessage,
			UInt64(signedMessage.count),
			publicKey
		)
		guard result == 0 else {
			throw SodiumError.invalidSignature
		}
		return unsigned
	}
}
