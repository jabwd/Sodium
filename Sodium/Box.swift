//
//  Box.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

public class Box {
	static public let nonceSize: Int = Int(crypto_box_NONCEBYTES)
	static public let boxSize:   Int = Int(crypto_box_MACBYTES)
	
	public let publicKey: [UInt8]
	public let secretKey: [UInt8]
	
	public init() {
		var newPublicKey = [UInt8](repeating: 0, count: KeyPair.publicKeySize)
		var newSecretKey = [UInt8](repeating: 0, count: KeyPair.secretKeySize)
		
		crypto_box_keypair(&newPublicKey, &newSecretKey)
		
		publicKey = newPublicKey
		secretKey = newSecretKey
	}
	
	public init(publicKey pKey: [UInt8], secretKey sKey: [UInt8]? = nil) throws {
		guard pKey.count == KeyPair.publicKeySize else {
			throw SodiumError.invalidPublicKey
		}
		publicKey = pKey
		if let sKeyUnwrapped = sKey {
			secretKey = sKeyUnwrapped
		} else {
			secretKey = []
		}
	}
	
	// MARK: -
	
	public func decrypt(message: [UInt8], remoteBox: Box) throws -> [UInt8] {
		guard message.count > Box.boxSize else {
			throw SodiumError.invalidBoxCipherText
		}
		
		let nonce: [UInt8], cipher: [UInt8]
		(nonce, cipher) = decode(cipher: message)
		let messageLength = cipher.count - Box.boxSize
		guard messageLength > 0 else {
			throw SodiumError.invalidBoxCipherText
		}
		
		var decryptedMessage = [UInt8](repeating: 0, count: messageLength)
		
		let result = crypto_box_open_easy(
			&decryptedMessage,
			&cipher,
			UInt64(cipher.count),
			&nonce,
			remoteBox.publicKey,
			secretKey
		)
		guard result == 0 else {
			throw SodiumError.boxDecryptionFailed
		}
		return decryptedMessage
	}
	
	public func encrypt(message: [UInt8], localBox: Box) throws -> [UInt8] {
		var nonce = [UInt8](repeating: 0, count: Box.nonceSize)
		randombytes_buf(&nonce, Box.nonceSize)
		
		var cipher = [UInt8](repeating: 0, count: message.count + Box.boxSize)
		guard crypto_box_easy(&cipher, message, UInt64(message.count), nonce, publicKey, localBox.secretKey) == 0 else {
			throw SodiumError.boxEncryptionFailed
		}
		
		return encode(nonce: nonce, cipher: cipher)
	}
}

// MARK - Encoding decoding cipher texts

extension Box {
	internal func decode(cipher cipherAndNonce: [UInt8]) -> (nonce: [UInt8], cipher: [UInt8]) {
		let nonce  = Array(cipherAndNonce[0..<Box.nonceSize])
		let cipher = Array(cipherAndNonce[Box.nonceSize..<cipherAndNonce.count])
		return (nonce, cipher)
	}
	
	internal func encode(nonce: [UInt8], cipher: [UInt8]) -> [UInt8] {
		return nonce + cipher
	}
}
