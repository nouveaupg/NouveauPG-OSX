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
    if ([m_packetData length] > 194) {
        buffer = 3;
    } else if( [m_packetData length] > 8386 ) {
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
    unsigned char *mdc;
    size_t szPayload;
    
    if (*payload == 0xcb) {
        // found literal packet
        if (*(payload+1) < 192) {
            szPayload = *(payload+1);
            szPayload += 2;
        }
        else if( *(payload+1) < 224 ) {
            szPayload = ((*(payload + 1) - 192)<<8) + *(payload + 2) + 192;
            szPayload += 3;
        }
        else if( *(payload+1) == 0xff ) {
            szPayload = *(payload + 2) << 24 | ((*(payload + 3) & 0xff) << 16);
            szPayload |= (*(payload + 4) & 0xff) << 8;
            szPayload |= *(payload + 5) & 0xff;
            szPayload += 6;
        }
        else {
            NSLog(@"Partial length header");
            szPayload = 0;
        }
    }
    mdc = payload + szPayload;
    
    SHA_CTX *hashContext = malloc(sizeof(SHA_CTX));
    SHA_Init(hashContext);
    SHA_Update(hashContext, payload, szPayload + 2);
    SHA_Final(digest, hashContext);
    free(hashContext);
    //SHA1(payload, szPayload+2, digest);

    if (memcmp(mdc, digest, 20)==0) {
        // TODO: doesn't work but NBD
        NSLog(@"Message validated.");
    }
    
        OpenPGPPacket *newPacket = [[OpenPGPPacket alloc]initWithData:[NSData dataWithBytes:unencryptedBuffer+18 length:szPayload]];
        
        if (newPacket) {
            return newPacket;
        }
        
    

    
    return nil;
}

@end
