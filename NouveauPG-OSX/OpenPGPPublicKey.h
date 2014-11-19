//
//  OpenPGPPublicKey.h
//  PrivacyForAll
//
//  Created by John Hill on 9/23/13.
//  Copyright (c) 2013 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>

#include "openssl/conf.h"
#include <openssl/evp.h>

#import "OpenPGPPacket.h"

#define kPublicKeyType_RSAEncryptAndSign 1

@interface OpenPGPPublicKey: NSObject {
    NSInteger m_publicKeyType;
    NSUInteger m_generatedTimestamp;
    unsigned char m_fingerprint[20];
    bool m_subkey;
    
    RSA *m_rsaKey;
    NSData *m_encryptedKey;
    unsigned char *m_iv;
    unsigned char *m_salt;
}


-(id)initWithEncryptedPacket:(OpenPGPPacket *)keyPacket;
-(id)initWithPacket:(OpenPGPPacket *)keyPacket;
-(id)initWithKeyLength:(int)bits isSubkey: (BOOL) subkey;
-(bool)isSubkey;
-(OpenPGPPacket *)encryptBytes: (const unsigned char *)sessionKey length:(int)keyLen;
// limited to 128 bit keys
-(unsigned char *)decryptBytes: (const unsigned char *)encryptedBytes length:(int)len;
-(unsigned char *)fingerprintBytes;
-(bool)hasPrivateKey;
-(NSData *)signHashWithPrivateKey: (unsigned char *)hash length:(int)len;
-(OpenPGPPacket *)exportPublicKey;
-(OpenPGPPacket *)exportPrivateKey: (NSString *)passphrase;
-(NSData *)decryptSignature: (NSData *)encryptedSig;
-(bool)decryptKey: (NSString *)passphrase;
-(bool)isEncrypted;
-(OpenPGPPacket *)exportPrivateKeyUnencrypted;

@property (copy) NSString *keyId;
@property NSInteger publicKeyType;
@property NSInteger publicKeySize;

@end
