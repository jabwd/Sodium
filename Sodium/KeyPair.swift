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
	
	init?(_ publicKey: Data, secretKey: Data) {
		guard publicKey.count == KeyPair.publicKeySize, secretKey.count == KeyPair.secretKeySize else {
			return nil
		}
		self.publicKey = publicKey.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: publicKey.count))
		}
		self.secretKey = secretKey.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: secretKey.count))
		}
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
	
	public init?(_ publicKey: Data, secretKey: Data) {
		guard secretKey.count == SigningKeyPair.secretKeySize, publicKey.count == SigningKeyPair.secretKeySize else {
			return nil
		}
		
		self.publicKey = publicKey.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: publicKey.count))
		}
		self.secretKey = secretKey.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: secretKey.count))
		}
	}
	
	public init() {
		var sec = [UInt8](repeating: 0, count: SigningKeyPair.secretKeySize)
		var pub = [UInt8](repeating: 0, count: SigningKeyPair.publicKeySize)
		
		crypto_sign_keypair(&pub, &sec)
		
		self.publicKey = pub
		self.secretKey = sec
	}
	
	public func sign(message: Data) -> Data {
		let messageBytes: [UInt8] = message.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: message.count))
		}
		var signedMessage: [UInt8] = [UInt8](repeating: 0, count: SigningKeyPair.signatureSize+messageBytes.count)
		var signedMessageLength: UInt64 = 0
		crypto_sign(&signedMessage, &signedMessageLength, messageBytes, UInt64(messageBytes.count), secretKey)
		return Data(bytes: signedMessage)
	}
	
	public func verifySignature(_ signedMessage: Data) -> Data? {
		let signedMessageBytes: [UInt8] = signedMessage.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: signedMessage.count))
		}
		var unsigned: [UInt8] = [UInt8](repeating: 0, count: signedMessage.count-SigningKeyPair.signatureSize)
		var unsignedLength: UInt64 = 0
		let result = crypto_sign_open(&unsigned, &unsignedLength, signedMessageBytes, UInt64(signedMessageBytes.count), publicKey)
		guard result == 0 else {
			return nil
		}
		return Data(bytes: unsigned)
	}
}
