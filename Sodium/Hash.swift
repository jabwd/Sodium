//
//  Hash.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import Foundation

public class Hash {
	public static let outputSize = Int(crypto_generichash_BYTES)
	public static let keySize    = Int(crypto_generichash_KEYBYTES)
	
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
}
