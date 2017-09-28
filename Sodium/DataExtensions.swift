//
//  DataExtensions.swift
//  Sodium
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import Foundation

public extension Data {
	public func bytes() -> [UInt8] {
		return self.withUnsafeBytes {
			[UInt8](UnsafeBufferPointer(start: $0, count: self.count))
		}
	}
	
	public static func random(_ size: Int) -> Data {
		return Data(bytes: randomBytes(size))
	}
	
	public static func randomBytes(_ size: Int) -> [UInt8] {
		var bytes: [UInt8] = [UInt8](repeating: 0, count: size)
		randombytes_buf(&bytes, size)
		return bytes
	}
}
