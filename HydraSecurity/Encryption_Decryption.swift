//
//  Encryption&Decryption.swift
//  UubeeSecurity
//
//  Created by Hydra on 15/9/16.
//  Copyright © 2015年 Uubee. All rights reserved.
//

import Foundation
import CommonCrypto
//RSA extension
extension Data{
    static func getPrivateKey(_ certificateName:String, passwd:String) -> SecKey{
        
        let certificatePath = Bundle.main.path(forResource: certificateName, ofType:".p12")
        
        let certificateData = try? Data(contentsOf: URL(fileURLWithPath: certificatePath!))

        let options = NSMutableDictionary()
        
        var privateKeyRef : SecKey?
        
        options.setObject(passwd, forKey: kSecImportExportPassphrase as String as String as NSCopying)

        var rawPointer: UnsafeRawPointer? = UnsafeRawPointer.init(bitPattern: 0)
        var items = withUnsafeMutablePointer(to: &rawPointer) { ppArray in
            CFArrayCreate(kCFAllocatorDefault, ppArray, 0, nil)
        }
 
        let cfCertificateData : CFData = certificateData! as CFData
        
        var status = SecPKCS12Import(cfCertificateData, options, &items)
        
        
        
        let itemsArray = items as AnyObject
        
        if status == noErr && itemsArray.count > 0 {
            
            let idenitfyDict = itemsArray.object(at: 0)
            
            let identifyApp = (idenitfyDict as AnyObject).object(forKey: kSecImportItemIdentity as String) as! SecIdentity
            
            status = SecIdentityCopyPrivateKey(identifyApp, &privateKeyRef)
        }
        
        return privateKeyRef!
    
    }
    
    static func getPublicKey(_ certificateName:String) -> SecKey{
        
        let certificatePath = Bundle.main.path(forResource: certificateName, ofType:".der")
        
        let certificateData = try? Data(contentsOf: URL(fileURLWithPath: certificatePath!))
        
        let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData! as CFData)
        
        let myPolicy = SecPolicyCreateBasicX509()
        
        var myTrust: SecTrust?
        
        var trustResult = SecTrustResultType(rawValue: 0)
        
        var status = SecTrustCreateWithCertificates(certificate!, myPolicy, &myTrust)
        
        if status == noErr {
            status = SecTrustEvaluate(myTrust!, &trustResult!)
        }
        
        return SecTrustCopyPublicKey(myTrust!)!
        
    }
    
    public static func rsaEncryptTheData(_ original:AnyObject, certificateName: String) -> Data?{
        
        var needEncryptData = Data()
        
        if original is String{
            needEncryptData = (original as! String).data(using: String.Encoding.utf8)!
        }
        else{
            do{
                needEncryptData = try JSONSerialization.data(withJSONObject: original, options: JSONSerialization.WritingOptions.prettyPrinted)
            }
            catch let parseError{
                print(parseError)
            }
        }
        
        
        let pubulicKey : SecKey = self.getPublicKey(certificateName)
        
        var cipherBufferSize = SecKeyGetBlockSize(pubulicKey)
        
        var cipherBuffer : UnsafeMutablePointer<UInt8>?
        
        cipherBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity:cipherBufferSize * MemoryLayout<Int>.size)
        
        memset(cipherBuffer, 0*0, cipherBufferSize)
        
        let blockSize = cipherBufferSize
        
        let numBlock = Int(ceil(Double(needEncryptData.count / blockSize)))
        
        let encryptedData = NSMutableData()
        
        for i in 0...numBlock {
           
            let bufferSzie = blockSize > (needEncryptData.count - i * blockSize) ? (needEncryptData.count - i * blockSize) : blockSize
            let buffer = needEncryptData.subdata(in: Range(i * blockSize..<bufferSzie))
            
            let status = SecKeyEncrypt(pubulicKey, SecPadding.OAEP, (buffer as NSData).bytes.bindMemory(to: UInt8.self, capacity: buffer.count), buffer.count, cipherBuffer!, &cipherBufferSize)
            
            if status == noErr {
                let encryptedBytes = Data.init(bytes: UnsafeRawPointer(cipherBuffer!), count: cipherBufferSize)
                encryptedData.append(encryptedBytes)
            }
            else{
                return nil
            }
        }
        
        if cipherBuffer != nil {
            free(cipherBuffer)
        }
        
        return encryptedData as Data
    }
    
    public static func rsaDecryptTheData(_ cipherString: String, certificateName: String, passwd: String) -> Data?{
        
        let cipherData :Data = Data(base64Encoded: cipherString, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters)!
        
        let privateKey : SecKey = self.getPrivateKey(certificateName, passwd: passwd)
        
        let decryptedData = NSMutableData()
        
        let blockSize = Int(SecKeyGetBlockSize(privateKey))
        
        let blockCount = Int(ceil(Double(cipherData.count) / Double(blockSize)))
        
        for i in 0..<blockCount {
            
            var contentLen = Int(blockSize)
            
            var content = [UInt8](repeating: 0, count: Int(contentLen))
        
            let bufferSize =  blockSize > (cipherData.count - i * blockSize) ? (cipherData.count - i * blockSize) : blockSize
    
            let buffer = cipherData.subdata(in: Range(i*blockSize..<bufferSize))
            
            let status = SecKeyDecrypt(privateKey, SecPadding.OAEP, (buffer as NSData).bytes.bindMemory(to: UInt8.self, capacity: buffer.count), buffer.count, &content, &contentLen)
            
            if (status == noErr){
                
                decryptedData.append(content, length: Int(contentLen))
                
            }else{
                print("SecKeyDecrypt fail. Error Code: \(status)")
                return nil
            }
        }
        return decryptedData as Data
    }
}


//AES
extension Data{
    
    public static func aesEncryptData(_ originalData:Data, key: String, iv:String) -> Data? {
        
        var cryptor : CCCryptorRef? = nil
          
        let ivData = NSData(data: iv.data(using: String.Encoding.utf8)!)
        let keyData = NSData(data: key.data(using: String.Encoding.utf8)!) as Data
        
        let create = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccPKCS7Padding), UnsafeRawPointer(ivData.bytes), (keyData as NSData).bytes.bindMemory(to: UInt8.self, capacity: keyData.count), kCCKeySizeAES256, nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
        
        let cipherData = NSMutableData(length: CCCryptorGetOutputLength(cryptor, originalData.count, true) + kCCBlockSizeAES128)
        
        if create == Int32(kCCSuccess) {
            
            var outLength = Int()
        
            let update = CCCryptorUpdate(cryptor,
                                        (originalData as NSData).bytes,
                                        originalData.count,
                                        cipherData!.mutableBytes,
                                        cipherData!.length,
                                        &outLength)
            
            if update == Int32(kCCSuccess) {
                
                cipherData!.length =  outLength
                
                let final = CCCryptorFinal(cryptor, cipherData!.mutableBytes,cipherData!.length, &outLength)
                
                if final == Int32(kCCSuccess) {
                    CCCryptorRelease(cryptor)
                }
                
                
                
                return cipherData as Data?
            }
            else{
                return nil
            }
        }
        
        return nil
    }
    
    
    public static func aesDecryptData(_ cipherData:Data, key: String, iv:String) -> Data? {
        
        var cryptor : CCCryptorRef? = nil
        
        let originalData = NSMutableData(length: cipherData.count + kCCBlockSizeAES128)
        
        let ivData = iv.data(using: String.Encoding.utf8)
        
        let keyData = key.data(using: String.Encoding.utf8)

        let create = CCCryptorCreateWithMode(UInt32(kCCDecrypt), UInt32(kCCModeCTR), UInt32(kCCAlgorithmAES128), UInt32(ccPKCS7Padding), ((ivData as NSData?)?.bytes)!, ((keyData as NSData?)?.bytes)!, kCCKeySizeAES256, nil, 0, 0, UInt32(kCCModeOptionCTR_BE), &cryptor)
        
        if create == Int32(kCCSuccess) {
            
            var outLength = Int()
            
            let update = CCCryptorUpdate(cryptor, (cipherData as NSData).bytes, cipherData.count, (originalData?.mutableBytes)!, (originalData?.length)!, &outLength)
            
            
            if update == Int32(kCCSuccess) {
                
                originalData?.length = outLength
                
                let final = CCCryptorFinal(cryptor, (originalData?.mutableBytes)!, (originalData?.length)!, &outLength)
                
                if final == Int32(kCCSuccess) {
                    CCCryptorRelease(cryptor)
                }
                
                return originalData as Data?
            }
            else{
                return nil
            }
        }
        
        return nil
    }
    
}
