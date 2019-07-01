//
//  DataExtensions.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import Foundation

public extension Data {
	func bytes() -> [UInt8] {
		return withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> [UInt8] in
			[UInt8](ptr)
		}
	}

	static func random(_ size: Int) -> Data {
		return Data(randomBytes(size))
	}

	static func randomBytes(_ size: Int) -> [UInt8] {
		// This can technically be replaced with SecRandom, but I wanted to reduce
		// the amount of frameworks this code relies on. 
		var bytes: [UInt8] = [UInt8](repeating: 0, count: size)
		randombytes_buf(&bytes, size)
		return bytes
	}
}
