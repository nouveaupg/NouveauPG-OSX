//
//  EncryptedEnvelope.m
//  UITest
//
//  Created by John Hill on 11/11/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import "EncryptedEnvelope.h"
#import "NSString+Base64.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

@implementation EncryptedEnvelope

- (id) initWithTextMessage: (NSString *)message forKey: (OpenPGPPublicKey *)publicKey {
    if (self = [super init]) {
        LiteralPacket *newPacket = [[LiteralPacket alloc]initWithUTF8String:message];
        int packetLength = (int)[[newPacket packetData] length] + 41;
        // currently only supporting AES-128 encryption (16 byte session keys)
        unsigned char session_key[16];
        unsigned char iv[16];
        // we set the IV to zero since we're using the idiosyncratic OpenPGP/CFB mode encryption
        memset(iv, 0, 16);
        // generate session key here, we need to keep track of this memory so we can reset it once we're done with it
        RAND_bytes(session_key, 16);
        OpenPGPPacket *sessionKeyPacket = [publicKey encryptBytes:session_key length:16];
        
        if (sessionKeyPacket) {
            unsigned char *packetData = malloc(packetLength);
        }
    }
    return self;
}

- (id) initWithLiteralPacket: (LiteralPacket *)packet publicKey: (OpenPGPPublicKey *)key {
    if (self = [super init]) {
        int packetLength = (int)[[packet packetData] length] + 40;
        unsigned char digest[20];
        unsigned char session_key[16];
        unsigned char iv[16];
        unsigned char *encryptedData = malloc(packetLength);
        int outputLength = -1;
        memset(iv, 0, 16);
        EVP_CIPHER *cipher = EVP_aes_128_cfb128();
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        unsigned char *ptr = malloc(packetLength);
        if (ptr) {
            RAND_bytes(ptr, 16);
            RAND_bytes(session_key, 16);
            ptr[16] = ptr[14];
            ptr[17] = ptr[15];
            memcpy((ptr + 18), [[packet packetData] bytes], [[packet packetData] length]);
            *(ptr + [[packet packetData] length] + 18) = 0xD3;
            *(ptr + [[packet packetData] length] + 19) = 0x14;
            SHA1(ptr, [[packet packetData] length] + 20, digest);
            memcpy((ptr + [[packet packetData] length] + 20), digest, 20);
            EVP_EncryptInit(&ctx, cipher, session_key, iv);
            EVP_EncryptUpdate(&ctx, encryptedData, &outputLength, ptr, packetLength);
            EVP_cleanup();
            memset(ptr, 0, packetLength);
            free(ptr);
            
            OpenPGPPacket *sessionKey = [key encryptBytes:session_key length:16];
            memset(session_key, 0, 16);
            
            unsigned char *payloadData = malloc(packetLength+1);
            payloadData[0] = 0x1;
            memcpy((payloadData+1), encryptedData, packetLength);
            free(encryptedData);
            OpenPGPPacket *payload = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:payloadData length:packetLength+1] tag:18 oldFormat:false];
            free(payloadData);
            
            NSMutableData *concat = [[NSMutableData alloc]initWithLength:[sessionKey length] + [payload length]];
            ptr = (unsigned char *)[concat bytes];
            NSUInteger offset = [[sessionKey packetData] length];
            memcpy(ptr, [[sessionKey packetData] bytes], offset);
            
            memcpy(ptr+offset, [[payload packetData] bytes], [[payload packetData] length]);
            m_envelopeData = [[NSData alloc]initWithData:concat];
            
        }
    }
    return self;
}

- (NSString *)armouredMessage {
    
    NSMutableString *outputString = [[NSMutableString alloc]init];
    [outputString appendString:@"-----BEGIN PGP MESSAGE-----\nVersion: NouveauPG 1.10 (iOS)\nComment: http://nouveauPG.com\n\n"];
    
    [outputString appendString:[m_envelopeData base64EncodedString]];
    
    // RFC 4880
    
    long crc = 0xB704CEL;
    unsigned char *ptr = (unsigned char *)[m_envelopeData bytes];
    for (int i = 0; i < [m_envelopeData length]; i++) {
        crc ^= (*(ptr+i)) << 16;
        for (int j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc ^= 0x1864CFBL;
            }
        }
    }
    crc &= 0xFFFFFFL;
    
    char data[3];
    data[0] = ( crc >> 16 ) & 0xff;
    data[1] = ( crc >> 8 ) & 0xff;
    data[2] = crc & 0xff;
    
    NSData *crcData = [[NSData alloc]initWithBytes:data length:3];
    
    [outputString appendFormat:@"\n=%@\n------END PGP MESSAGE-----",[crcData base64EncodedString]];
    return outputString;
}

@end
