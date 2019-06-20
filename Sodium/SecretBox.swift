//
//  SecretBox.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import Foundation

public class SecretBox {
	public static let keySize:   Int = Int(crypto_secretbox_KEYBYTES)
	public static let nonceSize: Int = Int(crypto_secretbox_NONCEBYTES)
	public static let macSize:   Int = Int(crypto_secretbox_MACBYTES)

	public let key: [UInt8]

	/// Initializes a secretbox with the given key. If the key is not of the correct size
	/// nil will be returned.
	public init?(key: [UInt8]) {
		guard key.count == SecretBox.keySize else {
			return nil
		}
		self.key = key
	}

	/// Initializes a new secretbox and automatically generates
	/// a new key for you.
	public init() {
		self.key = Data.randomBytes(SecretBox.keySize)
	}

	/// Encrypts a given byte buffer with the key of this instance
	/// - Parameter bytes: The bytebuffer to encrypt
	/// - Returns: A byte buffer with the nonce prepended to the ciphertext
	public func encrypt(bytes: [UInt8]) -> [UInt8] {
		let nonce:      [UInt8] = Data.randomBytes(SecretBox.nonceSize)
		var cipherText: [UInt8] = [UInt8](repeating: 0, count: (SecretBox.macSize+bytes.count))
		crypto_secretbox_easy(&cipherText, bytes, UInt64(bytes.count), nonce, key)
		
		// The payload is simply [nonce][cipherText], implementations have to mirror this
		// in order to successfully decrypt the payload
		return nonce + cipherText
	}

	/// Decrypts a given bytebuffer with the key of the current instance
	/// Requires the payload to have a nonce prepended for succesful decryption
	/// - Parameter bytes: The encrypted cipher text + nonce to decrypt
	/// - Throws: When decryption fails throws a SodiumError
	/// - Returns: A decrypted byte buffer
	public func decrypt(bytes: [UInt8]) throws -> [UInt8] {
		// Decode the nonce + ciphertext payload
		assert(bytes.count >= SecretBox.nonceSize+SecretBox.macSize)
		let nonce = Array(bytes[0..<SecretBox.nonceSize])
		assert(nonce.count == SecretBox.nonceSize)
		let cipher = Array(bytes[SecretBox.nonceSize..<bytes.count])

		var output: [UInt8] = [UInt8](repeating: 0, count: cipher.count-SecretBox.macSize)
		guard crypto_secretbox_open_easy(&output, cipher, UInt64(cipher.count), nonce, key) == 0 else {
			throw SodiumError.boxDecryptionFailed
		}
		return output
	}
	
	public func encrypt(_ message: String) -> [UInt8] {
		let nonce:      [UInt8] = Data.randomBytes(SecretBox.nonceSize)
		var cipherText: [UInt8] = [UInt8](repeating: 0, count: (SecretBox.macSize+message.count))
		crypto_secretbox_easy(&cipherText, message, UInt64(message.count), nonce, key)
		return nonce + cipherText
	}

	/// Wrapper around bytebuffer decrypting, eats a Data object
	/// and returns a decrypted string if succesful
	/// - Parameter cipherText: Data object to decrypt
	/// - Throws: SodiumError on decryption failure
	/// - Returns: Decrypted string
	public func decrypt(_ cipherText: Data) throws -> String? {
		let cipherTextBytes = cipherText.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> [UInt8] in
			[UInt8](ptr)
		}
		let bytes = try decrypt(bytes: cipherTextBytes)
		return String(bytes: bytes, encoding: .utf8)
	}
}
