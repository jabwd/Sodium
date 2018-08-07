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
			var s = String($1, radix: 16)
			if s.count == 1 {
				s = "0" + s
			}
			return $0 + s
		}
	}
	
	public var sha256: [UInt8] {
		return Hash.sha256(bytes: self)
	}
}
