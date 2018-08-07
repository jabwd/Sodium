//
//  Hash.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import Foundation

public class Hash {
	// Technically it supports other sizes, but these are the recommended size
	// and therefore I haven't made it a user option.
	public static let outputSize       = Int(crypto_generichash_BYTES)
	public static let keySize          = Int(crypto_generichash_KEYBYTES)
	public static let passwordHashSize = Int(crypto_pwhash_STRBYTES)
	public static let passwordMemLimit = 1024*1024*20 // 20MB should be okay for a mobile device.
	public static let passwordOpsLimit: UInt64 = 6
	
	public static let friendlierLimit = Int(crypto_pwhash_MEMLIMIT_SENSITIVE)
	
	///
	/// Generates a blake2b hash from the given input data with the given key.
	/// The user is responsible for providing a proper cryptographically secure key.
	/// Input data can be of any size.
	///
	/// - Parameters:
	///		- input: The data to hash
	///     - key:   The random key of keySize to use
	///
	/// - Returns: Hashed input data using key, data is of Hash.outputSize in length
	///
	public static func blake(_ input: Data, key: Data) -> Data {
		var output: [UInt8] = [UInt8](repeating: 0, count: outputSize)
		
		let keyBytes = key.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: key.count))
		}
		let inputBytes = input.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: input.count))
		}
		crypto_generichash(&output, outputSize, inputBytes, UInt64(input.count), keyBytes, keyBytes.count)
		return Data(bytes: output)
	}
	
	public static func createPasswordHash(_ password: String) -> String? {
		var hashedPassword = [Int8](repeating: 0, count: Hash.passwordHashSize)
		let result = crypto_pwhash_str(&hashedPassword, password, UInt64(password.count), Hash.passwordOpsLimit, Hash.passwordMemLimit)
		guard result == 0 else {
			print("[\(type(of: self))] Not enough memory available to hash password")
			return nil
		}
		
		return String(cString: &hashedPassword)
	}
	
	public static func verifyPassword(_ password: String, hash: String) -> Bool {
		return crypto_pwhash_str_verify(hash, password, UInt64(password.count)) == 0
	}
	
	public static func sha256(bytes: [UInt8]) -> [UInt8] {
		var localBytes = bytes
		var hash: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_hash_sha256_BYTES))
		crypto_hash_sha256(&hash, &localBytes, UInt64(localBytes.count))
		return hash
	}
	
	public static func sha512(bytes: [UInt8]) -> [UInt8] {
		var localBytes = bytes
		var hash: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_hash_sha512_BYTES))
		crypto_hash_sha512(&hash, &localBytes, UInt64(localBytes.count))
		return hash
	}
	
	public static func hmacSHA256Key() -> [UInt8] {
		var key: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_auth_hmacsha256_KEYBYTES))
		crypto_auth_hmacsha256_keygen(&key)
		return key
	}
	
	public static func hmacSHA512Key() -> [UInt8] {
		var key: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_auth_hmacsha512_KEYBYTES))
		crypto_auth_hmacsha512_keygen(&key)
		return key
	}
	
	public static func hmacSHA256(_ bytes: [UInt8], key: [UInt8]) -> [UInt8] {
		assert(key.count > 0)
		
		// Allocate all the memory we need to create the HMAC
		var hash: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_auth_hmacsha256_BYTES))
		var localKey: [UInt8] = key
		var localBytes: [UInt8] = bytes
		var state = crypto_auth_hmacsha256_state()
		
		print("Key size: \(localKey.count)")
		// We perform a multi-part SHA2 operation because the one-shot API
		// does not allow for variable-size key sizes
		crypto_auth_hmacsha256_init(&state, &localKey, localKey.count)
		crypto_auth_hmacsha256_update(&state, &localBytes, UInt64(localBytes.count))
		crypto_auth_hmacsha256_final(&state, &hash)
		let data = Data(bytes: bytes)
		print("Hashing: \(String(data: data, encoding: .utf8) ?? "")")
		print("Intermediate: \(hash.toHexString())")
		return hash
	}
	
	public static func hmacSHA512(_ bytes: [UInt8], key: [UInt8]) -> [UInt8] {
		assert(key.count > 0)
		
		// Allocate all the memory we need to create the HMAC
		var hash: [UInt8] = [UInt8](repeating: 0, count: Int(crypto_auth_hmacsha512_BYTES))
		var localKey: [UInt8] = key
		var localBytes: [UInt8] = bytes
		var state = crypto_auth_hmacsha512_state()
		
		// We perform a multi-part SHA2 operation because the one-shot API
		// does not allow for variable-size key sizes
		crypto_auth_hmacsha512_init(&state, &localKey, localKey.count)
		crypto_auth_hmacsha512_update(&state, &localBytes, UInt64(localBytes.count))
		crypto_auth_hmacsha512_final(&state, &hash)
		
		return hash
	}
}
