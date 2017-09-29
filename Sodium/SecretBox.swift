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
	
	public let key: Data
	
	///
	/// Initializes a secretbox with the given key. If the key is not of the correct size
	/// nil will be returned.
	///
	public init?(key: Data) {
		guard key.count == SecretBox.keySize else {
			return nil
		}
		self.key = key
	}
	
	///
	/// Initializes a new secretbox and automatically generates
	/// a new key for you.
	///
	public init() {
		self.key = Data.random(SecretBox.keySize)
	}
	
	public func encrypt(_ message: String) -> Data {
		let nonce:      [UInt8] = Data.randomBytes(SecretBox.nonceSize)
		var cipherText: [UInt8] = [UInt8](repeating: 0, count: (SecretBox.macSize+message.count))
		let keyBytes:   [UInt8] = key.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: key.count))
		}
		crypto_secretbox_easy(&cipherText, message, UInt64(message.count), nonce, keyBytes)
		
		// Generate the nonce + cipherText payload
		let final: [UInt8] = nonce + cipherText
		return Data(bytes: final)
	}
	
	public func decrypt(_ cipherText: Data) -> String? {
		let cipherTextBytes = cipherText.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: cipherText.count))
		}
		let keyBytes = key.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: key.count))
		}
		
		// Take apart the nonce from the cipherText
		assert(cipherText.count>=SecretBox.nonceSize+SecretBox.macSize)
		let nonce = Array(cipherTextBytes[0..<SecretBox.nonceSize])
		assert(nonce.count == SecretBox.nonceSize)
		let cipher = Array(cipherTextBytes[SecretBox.nonceSize..<cipherTextBytes.count])
		
		var output: [UInt8] = [UInt8](repeating: 0, count: cipher.count-SecretBox.macSize)
		guard crypto_secretbox_open_easy(&output, cipher, UInt64(cipher.count), nonce, keyBytes) == 0 else {
			print("[\(type(of: self))] Decrypt failed")
			return nil
		}
		
		return String(cString: &output)
	}
}
