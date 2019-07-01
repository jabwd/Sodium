//
//  Array+Extensions.swift
//  Sodium
//
//  Created by Antwan van Houdt on 07/08/2018.
//

import Foundation

extension Array where Element == UInt8 {
	public func toHexString() -> String {
		return `lazy`.reduce("") {
			var byte = String($1, radix: 16)
			if byte.count == 1 {
				byte = "0" + byte
			}
			return $0 + byte
		}
	}

	public var sha256: [UInt8] {
		return Hash.sha256(bytes: self)
	}
}
