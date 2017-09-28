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
		let result = crypto_pwhash_str_verify(hash, password, UInt64(password.count))
		guard result == 0 else {
			return false
		}
		return true
	}
}
