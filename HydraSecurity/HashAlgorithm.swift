//
//  HashHmac.swift
//  UubeeSecurity
//
//  Created by Hydra on 15/9/16.
//  Copyright © 2015年 Uubee. All rights reserved.
//

import Foundation
import CommonCrypto

public enum HashMode {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    var HMACAlgorithm: CCHmacAlgorithm {
        var algorithm: Int = 0
        switch self {
        case .MD5:      algorithm = kCCHmacAlgMD5
        case .SHA1:     algorithm = kCCHmacAlgSHA1
        case .SHA224:   algorithm = kCCHmacAlgSHA224
        case .SHA256:   algorithm = kCCHmacAlgSHA256
        case .SHA384:   algorithm = kCCHmacAlgSHA384
        case .SHA512:   algorithm = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(algorithm)
    }
    
    var digestLength: Int {
        var length: Int32 = 0
        switch self {
        case .MD5:      length = CC_MD5_DIGEST_LENGTH
        case .SHA1:     length = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   length = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   length = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   length = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   length = CC_SHA512_DIGEST_LENGTH
        }
        return Int(length)
    }
}

public struct HashModeFuction {
    let MD2 = (CC_MD2,    CC_MD2_DIGEST_LENGTH)
    let MD4 = (CC_MD4,    CC_MD4_DIGEST_LENGTH)
    let MD5 = (CC_MD5,    CC_MD5_DIGEST_LENGTH)
    let SHA1 = (CC_SHA1,    CC_SHA1_DIGEST_LENGTH)
    let SHA224 = (CC_SHA224,    CC_SHA224_DIGEST_LENGTH)
    let SHA256 = (CC_SHA256,    CC_SHA256_DIGEST_LENGTH)
    let SHA384 = (CC_SHA384,    CC_SHA384_DIGEST_LENGTH)
    let SHA512 = (CC_SHA512,    CC_SHA512_DIGEST_LENGTH)
}

public struct HmacAlgorithm{
    let SHA1 =  CCHmacAlgorithm(kCCHmacAlgSHA1)
    let MD5 = CCHmacAlgorithm(kCCHmacAlgMD5)
    let SHA256 = CCHmacAlgorithm(kCCHmacAlgSHA256)
    let SHA384 = CCHmacAlgorithm(kCCHmacAlgSHA384)
    let SHA512 = CCHmacAlgorithm(kCCHmacAlgSHA512)
    let SHA224 = CCHmacAlgorithm(kCCHmacAlgSHA224)
}

//public enum HashMode {
//    case MD2
//    case MD4
//    case MD5
//    case SHA1
//    case SHA224
//    case SHA256
//    case SHA384
//    case SHA512
//}

extension Data{
    
    public static func hashDataByHmac(mode:HashMode, data: Data, key: String) -> Data? {
        let hmacAlgorithm = HmacAlgorithm()
        let algos : [HashMode : CCHmacAlgorithm] = [.MD5:   hmacAlgorithm.MD5,
                                                    .SHA1:  hmacAlgorithm.SHA1,
                                                    .SHA224: hmacAlgorithm.SHA224,
                                                    .SHA256: hmacAlgorithm.SHA256,
                                                    .SHA384: hmacAlgorithm.SHA384,
                                                    .SHA512: hmacAlgorithm.SHA512]
        guard let hashAlgorithm = algos[mode]  else {
            print("Non-existent mode")
            return nil
        }
        
        let keyData = key.data(using: String.Encoding.utf8)!
        
        var hashData = Data(count: mode.digestLength)
        
        let keyBytes = keyData.withUnsafeBytes { (bytes: UnsafePointer<Any>) -> UnsafePointer<Any> in
            return bytes
        }
        let dataBytes = data.withUnsafeBytes { (bytes: UnsafePointer<Any>) -> UnsafePointer<Any> in
            return bytes
        }
        let digestBytes = hashData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        
        CCHmac(hashAlgorithm, keyBytes, keyData.count, dataBytes, data.count, digestBytes)
        
        return hashData as Data
    }
    
    public static func hashData(mode:HashMode, data:Data) -> String? {
        let hashFunction = HashModeFuction()
        let algos = [HashMode.MD5:   hashFunction.MD5,
                     HashMode.SHA1:  hashFunction.SHA1,
                     HashMode.SHA224: hashFunction.SHA224,
                     HashMode.SHA256: hashFunction.SHA256,
                     HashMode.SHA384: hashFunction.SHA384,
                     HashMode.SHA512: hashFunction.SHA512]
        
        guard let (hashAlgorithm, length) = algos[mode]  else { return nil }
        var hashData = Data(count: Int(length))
        
        let digestBytes = hashData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        
        let dataBytes = data.withUnsafeBytes { (bytes: UnsafePointer<Any>) -> UnsafePointer<Any> in
            return bytes
        }
        _ = hashAlgorithm(dataBytes, CC_LONG(data.count), digestBytes)
        
        let hashString = NSMutableString()
        for i in 0..<Int(length) {
            hashString.appendFormat("%02x", digestBytes[i])
        }
        
        return String(hashString)
    }
}

