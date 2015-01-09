//
//  OpenPGPEncryptedPacket.m
//  UITest
//
//  Created by John Hill on 3/18/14.
//  Copyright (c) 2014 __MyCompanyName__. All rights reserved.
//

#import "OpenPGPEncryptedPacket.h"
#import <openssl/evp.h>
#import <openssl/sha.h>

@implementation OpenPGPEncryptedPacket

- (OpenPGPPacket *)decryptWithSessionKey: (const unsigned char *)sessionKey algo: (int)algorithm {
    unsigned char iv[16];
    unsigned char digest[20];
    int buffer = 2;
    if ([m_packetData length] > 191) {
        buffer = 3;
    } else if( [m_packetData length] > 8382 ) {
        buffer = 6;
    }
    
    unsigned char *ptr = (unsigned char *)[m_packetData bytes];
    
    size_t szUnencryptedBuffer = [m_packetData length] - buffer - 1;
    int outputLength = -1;
    unsigned char *unencryptedBuffer = malloc(szUnencryptedBuffer);
    
    memset(iv, 0, 16);
    EVP_CIPHER *cipher = EVP_aes_128_cfb128();
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    
    EVP_DecryptInit(&ctx, cipher, sessionKey, iv);
    EVP_DecryptUpdate(&ctx, unencryptedBuffer, &outputLength, ptr+buffer+1, szUnencryptedBuffer);
    EVP_cleanup();
    
    unsigned char *payload = unencryptedBuffer + 18;
    size_t szPayload = outputLength - 18;
    
    OpenPGPPacket *packet = [[OpenPGPPacket alloc]initWithData:[NSData dataWithBytes:payload length:szPayload]];
    free(unencryptedBuffer);
    return packet;
}

@end
