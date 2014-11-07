//
//  OpenPGPSignature.m
//  UITest
//
//  Created by John Hill on 10/7/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import "OpenPGPSignature.h"

#define kSignatureVersion3 3
#define kSignatureVersion4 4

#include <openssl/sha.h>

@implementation OpenPGPSignature

@synthesize signatureVersion;
@synthesize signatureType;
@synthesize publicKeyAlgo;
@synthesize hashAlgo;

- (id) initWithPacket: (OpenPGPPacket *)packet {
    if (self = [self initWithData:[packet packetData]]) {
        unsigned char *ptr = (unsigned char *)[m_packetData bytes];
        NSUInteger len = [m_packetData length];
        NSInteger offset = 0;
        if (self.newPacketFormat) {
            if (len < 192) {
                offset = 2;
            }
            else if(len < 8384 ) {
                offset = 3;
            }
            else {
                offset = 6;
            }
        }
        else {
            if (len < 256) {
                offset = 2;
            }
            else if( len < 65536 ) {
                offset = 3;
            }
            else {
                offset = 5;
            }
        }
        
        if (*(ptr + offset) == 3) {
            signatureVersion = 3;
        }
        else if (*(ptr + offset) == 4) {
            signatureVersion = 4;
            offset++;
            
            signatureType = *(ptr+offset);
            offset++;
            
            publicKeyAlgo = *(ptr+offset);
            offset++;
            
            hashAlgo = *(ptr+offset);
            offset++;
            
            unsigned int hashedBytes = *(ptr+offset);
            hashedBytes <<= 8;
            offset++;
            hashedBytes |= *(ptr+offset);
            offset++;
            m_hashedSubpacketData = [[NSData alloc]initWithBytes:(ptr+offset) length:hashedBytes];
            offset += hashedBytes;
            unsigned int unhashedBytes = *(ptr+offset);
            unhashedBytes <<= 8;
            offset++;
            unhashedBytes |= *(ptr+offset);
            offset++;
            if (unhashedBytes > 0) {
                 m_unhashedSubpacketData = [[NSData alloc]initWithBytes:(ptr+offset) length:unhashedBytes];
                offset += unhashedBytes;
            }
            
            // parse subpackets
            
            ptr = (unsigned char *)[m_hashedSubpacketData bytes];
            NSInteger len = [m_hashedSubpacketData length];
            while (len > 0) {
                NSUInteger subpacketLength = *ptr;
                NSLog(@"Hashed subpacket tag: %d; length: %ld",*(ptr+1),len);
                ptr += subpacketLength + 1;
                len -= subpacketLength + 1;
            }
            
            ptr = (unsigned char *)[m_unhashedSubpacketData bytes];
            len = [m_unhashedSubpacketData length];
            while (len > 0) {
                NSUInteger subpacketLength = *ptr;
                NSLog(@"Unhashed subpacket tag: %d; length: %ld",*(ptr+1),len);
                ptr += subpacketLength + 1;
                len -= subpacketLength + 1;
            }
            
            ptr = (unsigned char *)[m_packetData bytes];
            offset += 2;
            unsigned int signatureLen = *(ptr+offset);
            signatureLen <<= 8;
            offset++;
            signatureLen |= *(ptr+offset);
            offset++;
            unsigned int signatureBytes = (signatureLen + 7) / 8;
            
            m_signature = [[NSData alloc] initWithBytes:(ptr+offset) length:signatureBytes];
        }
        
    }
    return self;
}

+(OpenPGPPacket *)signSubkey: (OpenPGPPublicKey *)subkey withPrivateKey:(OpenPGPPublicKey *)signingKey {
    OpenPGPPacket *outputPacket = nil;
    NSUInteger modulusBytes = (signingKey.publicKeySize + 7) / 8;
    size_t packetLen = modulusBytes + 31;
    size_t hashedBytes = 0;
    unsigned char *packetBody = malloc(packetLen);
    memset(packetBody, 0xcd, packetLen);
    unsigned char digest[20];
    OpenPGPPacket *keyPacket = [signingKey exportPublicKey];
    SHA1([[keyPacket packetData] bytes], [[keyPacket packetData] length], digest);
    
    if (packetBody) {
        time_t signatureCreated = time(0);
        
        packetBody[0] = 4;
        packetBody[1] = 0x18;
        packetBody[2] = 1;
        packetBody[3] = 2;
        packetBody[4] = 0;
        packetBody[5] = 9;
        packetBody[6] = 5;
        packetBody[7] = 2;
        packetBody[8] = signatureCreated >> 24;
        packetBody[9] = (signatureCreated >> 16) & 0xff;
        packetBody[10] = (signatureCreated >> 8) & 0xff;
        packetBody[11] = signatureCreated &  0xff;
        packetBody[12] = 2;
        packetBody[13] = 27;
        packetBody[14] = 0x1; // key flags
        packetBody[15] = 0;
        packetBody[16] = 10;
        packetBody[17] = 9;
        packetBody[18] = 16;
        memcpy((packetBody+19), (digest+12), 8);
        packetBody[27] = 0xff;
        packetBody[28] = 0xff;
        packetBody[29] = signingKey.publicKeySize >> 8;
        packetBody[30] = signingKey.publicKeySize & 0xff;
        
        SHA_CTX *hashContext = malloc(sizeof(SHA_CTX));
    
        OpenPGPPacket *primaryKeyPacket = [signingKey exportPublicKey];
        OpenPGPPacket *subkeyPacket = [subkey exportPublicKey];
        
        unsigned char *subkeyBuffer = malloc([subkeyPacket length]);
        memcpy(subkeyBuffer, [[subkeyPacket packetData] bytes], [[subkeyPacket packetData] length]);
        subkeyBuffer[0] = 0x99;
        //unsigned char digest[20];
        
        SHA1_Init(hashContext);
        SHA1_Update(hashContext, [[primaryKeyPacket packetData] bytes], [[primaryKeyPacket packetData] length]);
        SHA1_Update(hashContext, subkeyBuffer, [[subkeyPacket packetData] length]);
        SHA1_Update(hashContext, packetBody, 15);
        unsigned char trailer[6];
        hashedBytes = 15;
        trailer[0] = 4;
        trailer[1] = 0xff;
        trailer[2] = hashedBytes >> 24;
        trailer[3] = (hashedBytes >> 16) & 0xff;
        trailer[4] = (hashedBytes >> 8) & 0xff;
        trailer[5] = hashedBytes & 0xff;
        SHA1_Update(hashContext, trailer, 6);
        SHA1_Final(digest, hashContext);
        
        packetBody[27] = digest[0];
        packetBody[28] = digest[1];
        
        NSData *mpi = [signingKey signHashWithPrivateKey:digest length:20];
        
        BIGNUM *bn_mpi = BN_new();
        BN_bin2bn([mpi bytes], [mpi length], bn_mpi);
        int mpiBitCount = BN_num_bits(bn_mpi);
        BN_free(bn_mpi);
        
        packetBody[29] = (mpiBitCount >> 8) & 0xff;
        packetBody[30] = mpiBitCount & 0xff;
        
        memcpy((packetBody+31), [mpi bytes], [mpi length]);
        outputPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:2 oldFormat:YES];
    }
    
    return outputPacket;
}

-(bool) validateWithPublicKey: (OpenPGPPublicKey *)signingKey userId: (NSString *)uid {
    NSData *decryptedSig = [signingKey decryptSignature:m_signature];
    if ( decryptedSig ) {
        unsigned char *ptr = (unsigned char *)[decryptedSig bytes];
        unsigned char trailer[6];
        unsigned char digest[EVP_MAX_MD_SIZE];
        int digestLen;
        
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        //SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
        
        NSUInteger hashedData = 0;
        
        EVP_MD *mdAlgo = NULL;
        switch (hashAlgo) {
            case 1:
                mdAlgo = EVP_md5();
                break;
            case 3:
                mdAlgo = EVP_ripemd160();
                break;
            case 8:
                mdAlgo = EVP_sha256();
                break;
            case 9:
                mdAlgo = EVP_sha384();
                break;
            case 10:
                mdAlgo = EVP_sha512();
                break;
            case 11:
                mdAlgo = EVP_sha224();
                break;
                
            default:
                mdAlgo = EVP_sha1();
                break;
        }
        
        EVP_DigestInit(ctx, mdAlgo);
        //SHA1_Init(ctx);
        
        if( signatureType >= 0x10 && signatureType <= 0x13 ) {
            OpenPGPPacket *publicKeyPacket = [signingKey exportPublicKey];
            EVP_DigestUpdate(ctx, [[publicKeyPacket packetData]bytes], [[publicKeyPacket packetData]length]);
            //SHA1_Update(ctx, [[publicKeyPacket packetData]bytes], [[publicKeyPacket packetData]length]);
            NSUInteger uidlen = [uid length];
            trailer[0] = 0xb4;
            trailer[1] = uidlen >> 24;
            trailer[2] = (uidlen >> 16) & 0xff;
            trailer[3] = (uidlen >> 8) & 0xff;
            trailer[4] = uidlen & 0xff;
            //SHA1_Update(ctx, trailer, 5);
            //SHA1_Update(ctx, [uid UTF8String], uidlen);
            EVP_DigestUpdate(ctx, trailer, 5);
            EVP_DigestUpdate(ctx, [uid UTF8String], uidlen);
            trailer[0] = 4;
            trailer[1] = signatureType;
            trailer[2] = publicKeyAlgo;
            trailer[3] = hashAlgo;
            NSUInteger hashedSubpacketBytes = [m_hashedSubpacketData length];
            trailer[4] = (hashedSubpacketBytes>>8) & 0xff;
            trailer[5] = hashedSubpacketBytes & 0xff;
            //SHA1_Update(ctx, trailer, 6);
            //SHA1_Update(ctx, [m_hashedSubpacketData bytes], [m_hashedSubpacketData length]);
            EVP_DigestUpdate(ctx, trailer, 6);
            EVP_DigestUpdate(ctx, [m_hashedSubpacketData bytes], [m_hashedSubpacketData length]);
            hashedData = [m_hashedSubpacketData length] + 6;
            trailer[0] = 4;
            trailer[1] = 0xff;
            trailer[2] = hashedData >> 24;
            trailer[3] = (hashedData >> 16) & 0xff;
            trailer[4] = (hashedData >> 8) & 0xff;
            trailer[5] = hashedData & 0xff;
            //SHA1_Update(ctx, trailer, 6);
            EVP_DigestUpdate(ctx, trailer, 6);
            EVP_DigestFinal_ex(ctx, digest, &digestLen);
            //SHA1_Final(digest, ctx);
            EVP_MD_CTX_destroy(ctx);
            
            if (!memcmp(digest, (ptr+([decryptedSig length]-digestLen)), digestLen)) {
                NSLog(@"Validated signature! (hashAlgo: %ld)",(long)hashAlgo);
                return true;
            }
            else {
                NSLog(@"Could not validate signature! (hashAlgo: %ld, sig type: 0x%02lx)",(long)hashAlgo,(long)signatureType);
            }
        }
    }
    return false;
}

-(bool) validateSubkey:(OpenPGPPublicKey *)subkey withSigningKey:(OpenPGPPublicKey *)signingKey {
    NSData *decryptedSig = [signingKey decryptSignature:m_signature];
    if( decryptedSig ) {
        unsigned char *ptr = (unsigned char *)[decryptedSig bytes];
        unsigned char trailer[6];
        unsigned char digest[EVP_MAX_MD_SIZE];
        int digestLen;
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        //SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
        EVP_MD *mdAlgo = NULL;
        switch (hashAlgo) {
            case 1:
                mdAlgo = EVP_md5();
                break;
            case 3:
                mdAlgo = EVP_ripemd160();
                break;
            case 8:
                mdAlgo = EVP_sha256();
                break;
            case 9:
                mdAlgo = EVP_sha384();
                break;
            case 10:
                mdAlgo = EVP_sha512();
                break;
            case 11:
                mdAlgo = EVP_sha224();
                break;
                
            default:
                mdAlgo = EVP_sha1();
                break;
        }
        
        EVP_DigestInit(ctx, mdAlgo);
        NSUInteger hashedData = 0;
        //SHA1_Init(ctx);
        if (signatureType == 0x18) {
            OpenPGPPacket *signingKeyPacket = [signingKey exportPublicKey];
            EVP_DigestUpdate(ctx, [[signingKeyPacket packetData] bytes], [[signingKeyPacket packetData] length]);
            //SHA1_Update(ctx, [[signingKeyPacket packetData] bytes], [[signingKeyPacket packetData] length]);
            OpenPGPPacket *subkeyPacket = [subkey exportPublicKey];
            unsigned char *subkeyBuffer = malloc([[subkeyPacket packetData] length]);
            memcpy(subkeyBuffer, [[subkeyPacket packetData] bytes], [[subkeyPacket packetData] length]);
            subkeyBuffer[0] = 0x99;
            EVP_DigestUpdate(ctx, subkeyBuffer, [[subkeyPacket packetData] length]);
            //SHA1_Update(ctx, subkeyBuffer, [[subkeyPacket packetData] length]);
            free(subkeyBuffer);
            trailer[0] = 4;
            trailer[1] = signatureType;
            trailer[2] = publicKeyAlgo;
            trailer[3] = hashAlgo;
            NSUInteger hashedSubpacketBytes = [m_hashedSubpacketData length];
            trailer[4] = (hashedSubpacketBytes>>8) & 0xff;
            trailer[5] = hashedSubpacketBytes & 0xff;
            //SHA1_Update(ctx, trailer, 6);
            //SHA1_Update(ctx, [m_hashedSubpacketData bytes], [m_hashedSubpacketData length]);
            EVP_DigestUpdate(ctx, trailer, 6);
            EVP_DigestUpdate(ctx, [m_hashedSubpacketData bytes], [m_hashedSubpacketData length]);
            hashedData = [m_hashedSubpacketData length] + 6;
            trailer[0] = 4;
            trailer[1] = 0xff;
            trailer[2] = hashedData >> 24;
            trailer[3] = (hashedData >> 16) & 0xff;
            trailer[4] = (hashedData >> 8) & 0xff;
            trailer[5] = hashedData & 0xff;
            EVP_DigestUpdate(ctx,trailer, 6);
            EVP_DigestFinal_ex(ctx, digest, &digestLen);
            //SHA1_Update(ctx, trailer, 6);
            //SHA1_Final(digest, ctx);
            //free(ctx);
            EVP_MD_CTX_destroy(ctx);
            
            if (!memcmp(digest, (ptr+([decryptedSig length]-digestLen)), digestLen)) {
                NSLog(@"Validated signature! (hashAlgo: %ld)",(long)hashAlgo);
                return true;
            }
            else {
                NSLog(@"Could not validate signature! (hashAlgo: %ld, sig type: %02lx)",(long)hashAlgo,(long)signatureType);
            }
        }
    }
    return false;
}

+(OpenPGPPacket *)signUserId: (NSString *)userId withPublicKey: (OpenPGPPublicKey *)key {
    OpenPGPPacket *outputPacket = nil;
    OpenPGPPacket *keyPacket = [key exportPublicKey];
    unsigned char digest[20];
    unsigned char trailer[6];
    SHA1([[keyPacket packetData] bytes], [[keyPacket packetData] length], digest);
    NSUInteger modulusBytes = (key.publicKeySize + 7) / 8;
    size_t packetLen = modulusBytes + 43;
    
    unsigned char *packetBody = malloc(packetLen);
    if(packetBody) {
        time_t signatureCreated = time(0);
        packetBody[0] = 4;
        packetBody[1] = 0x13;
        packetBody[2] = 1;
        packetBody[3] = 2;
        packetBody[4] = 0;
        packetBody[5] = 21;
        packetBody[6] = 5;
        packetBody[7] = 2;
        packetBody[8] = (signatureCreated >> 24) & 0xff;
        packetBody[9] = (signatureCreated >> 16) & 0xff;
        packetBody[10] = (signatureCreated >> 8) & 0xff;
        packetBody[11] = signatureCreated & 0xff;
        packetBody[12] = 2;
        packetBody[13] = 25; // primary user id
        packetBody[14] = 0x1;
        packetBody[15] = 2;
        packetBody[16] = 11; // symmetric algorithms
        packetBody[17] = 7; // AES-128 only
        packetBody[18] = 2;
        packetBody[19] = 21; // hash algorithms
        packetBody[20] = 2; // SHA-1 only
        packetBody[21] = 2;
        packetBody[22] = 22; // compression algorithms
        packetBody[23] = 0; // no compression only
        packetBody[24] = 2;
        packetBody[25] = 30; // features
        packetBody[26] = 1; // supports MDC
        packetBody[27] = 0;
        packetBody[28] = 10; // unhashed data
        packetBody[29] = 9;
        packetBody[30] = 16;
        memcpy((packetBody+31),(digest+12),8);
        packetBody[39] = 0xff;
        packetBody[40] = 0xff;
        packetBody[41] = 0xff;
        packetBody[42] = 0xff;
        
        SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
        SHA1_Init(ctx);
        SHA1_Update(ctx, [[keyPacket packetData] bytes], [[keyPacket packetData] length]);
        trailer[0] = 0xb4;
        trailer[1] = ([userId length] >> 24) & 0xff;
        trailer[2] = ([userId length] >> 16) & 0xff;
        trailer[3] = ([userId length] >> 8) & 0xff;
        trailer[4] = ([userId length]) & 0xff;
        SHA1_Update(ctx, trailer, 5);
        SHA1_Update(ctx, [userId UTF8String], [userId length]);
        SHA1_Update(ctx, packetBody, 27);
        trailer[0] = 4;
        trailer[1] = 0xff;
        trailer[2] = 0;
        trailer[3] = 0;
        trailer[4] = 0;
        trailer[5] = 27;
        SHA1_Update(ctx, trailer, 6);
        SHA1_Final(digest, ctx);
        free(ctx);
        
        packetBody[39] = digest[0];
        packetBody[40] = digest[1];
        
        NSData *mpi = [key signHashWithPrivateKey:digest length:20];
        
        BIGNUM *bn_mpi = BN_new();
        BN_bin2bn([mpi bytes], [mpi length], bn_mpi);
        int mpiBitCount = BN_num_bits(bn_mpi);
        BN_free(bn_mpi);
        
        packetBody[41] = (mpiBitCount >> 8) & 0xff;
        packetBody[42] = mpiBitCount & 0xff;
        
        memcpy((packetBody+43), [mpi bytes], [mpi length]);
        outputPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:2 oldFormat:YES];
        
        free(packetBody);
    }
    
    return outputPacket;
}

+(OpenPGPPacket *)signWithUserId:(NSString *)userId publicKey: (OpenPGPPublicKey *)key {
    // deprecated: use +(OpenPGPPacket *)signString: withKey: using:
    OpenPGPPacket *outputPacket = nil;
    OpenPGPPacket *keyPacket = [key exportPublicKey];
    unsigned char digest[20];
    SHA1([[keyPacket packetData] bytes], [[keyPacket packetData] length], digest);
    
    NSUInteger modulusBytes = (key.publicKeySize + 7) / 8;
    size_t packetLen = modulusBytes + 43;
    size_t hashedBytes = 0;
    unsigned char *packetBody = malloc(packetLen);
    if (packetBody) {
        time_t signatureCreated = time(0);
        memset(packetBody, 0xcd, packetLen);
        // no real reason to change any of these options
        packetBody[0] = 4;
        packetBody[1] = 0x13;
        packetBody[2] = 1;
        packetBody[3] = 2;
        packetBody[4] = 0;
        packetBody[5] = 21;
        packetBody[6] = 5;
        packetBody[7] = 2;
        packetBody[8] = signatureCreated >> 24;
        packetBody[9] = (signatureCreated >> 16) & 0xff;
        packetBody[10] = (signatureCreated >> 8) & 0xff;
        packetBody[11] = signatureCreated &  0xff;
        packetBody[12] = 2;
        packetBody[13] = 25;
        packetBody[14] = 0x1; // key flags
        packetBody[15] = 2;
        packetBody[16] = 11; // symmetric algorithms
        packetBody[17] = 7;
        packetBody[18] = 2;
        packetBody[19] = 21; // hash algorithms
        packetBody[20] = 2;
        packetBody[21] = 2;
        packetBody[22] = 22; // compression algorithms
        packetBody[23] = 0;
        packetBody[24] = 2;
        packetBody[25] = 30;
        packetBody[26] = 1;
        //packetBody[27] = 9;
        //packetBody[28] = 16;
        //memcpy((packetBody+29),(digest+12),8);
        packetBody[27] = 0;
        packetBody[28] = 10; // unhashed data
        packetBody[29] = 9;
        packetBody[30] = 16;
        memcpy((packetBody+31),(digest+12),8);
        packetBody[39] = 0xff;
        packetBody[40] = 0xff;
        packetBody[41] = key.publicKeySize >> 8;
        packetBody[42] = key.publicKeySize & 0xff;
        
        OpenPGPPacket *pubKey = [key exportPublicKey];
        NSData *packetData = [pubKey packetData];
        
        SHA_CTX *hashContext = malloc(sizeof(SHA_CTX));
        unsigned char *userIdBuffer = malloc([userId length] + 5);
        
        if (userIdBuffer && hashContext) {
            SHA1_Init(hashContext);
            SHA1_Update(hashContext, [packetData bytes], [packetData length]);
            hashedBytes += [packetData length];
            userIdBuffer[0] = 0xB4;
            userIdBuffer[1] = [userId length] >> 24;
            userIdBuffer[2] = ([userId length] >> 16) & 0xff;
            userIdBuffer[3] = ([userId length] >> 8) & 0xff;
            userIdBuffer[4] = [userId length] & 0xff;
            memcpy(userIdBuffer, [userId UTF8String], [userId length]);
            SHA1_Update(hashContext, userIdBuffer, [userId length] + 5);
            hashedBytes += [userId length] + 5;
            // maybe wrong
            unsigned char trailer[6];
            trailer[0] = 4;
            trailer[1] = 0x13;
            trailer[2] = 1;
            trailer[3] = 2;
            trailer[4] = packetBody[4];
            trailer[5] = packetBody[5];
    
            SHA1_Update(hashContext, trailer, 6);
            
            SHA1_Update(hashContext, (packetBody + 6), (packetBody[4]<<8) | packetBody[5]);
            hashedBytes = 27;
            trailer[0] = 4;
            trailer[1] = 0xff;
            trailer[2] = hashedBytes >> 24;
            trailer[3] = (hashedBytes >> 16) & 0xff;
            trailer[4] = (hashedBytes >> 8) & 0xff;
            trailer[5] = hashedBytes & 0xff;
            
            SHA1_Update(hashContext, trailer, 6);
            SHA1_Final(digest, hashContext);
            free(hashContext);
            free(userIdBuffer);
            
            packetBody[39] = digest[0];
            packetBody[40] = digest[1];
            
            NSLog(@"Digest bytes: %02x%02x",digest[0],digest[1]);
            
            NSData *mpi = [key signHashWithPrivateKey:digest length:20];
            memcpy((packetBody+43), [mpi bytes], [mpi length]);
            outputPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:2 oldFormat:YES];
        }else {
            NSLog(@"Could not allocate userIdBuffer or hashContext (malloc fail).");
        }
        free(packetBody);
    }
    else {
        NSLog(@"Could not allocate packetBody buffer.");
    }
    
    return outputPacket;
}

+(OpenPGPPacket *)signSubkey: (OpenPGPPublicKey *)subkey withPrimaryKey: (OpenPGPPublicKey *)primary using: (NSInteger)algo {
    EVP_MD *hashFunction = NULL;
    if (algo == 8) {
        hashFunction = EVP_sha256();
    }
    else if( algo == 10 ) {
        hashFunction = EVP_sha512();
    }
    else if( algo == 2 ) {
        hashFunction = EVP_sha1();
    }
    else {
        return nil;
    }
    
    OpenPGPPacket *outputPacket = nil;
    NSUInteger modulusBytes = (primary.publicKeySize + 7) / 8;
    size_t packetLen = modulusBytes + 31;
    size_t hashedBytes = 0;
    unsigned char *packetBody = malloc(packetLen);
    memset(packetBody, 0xcd, packetLen);
    unsigned char digest[EVP_MAX_MD_SIZE];
    int digestLen;
    OpenPGPPacket *keyPacket = [primary exportPublicKey];
    SHA1([[keyPacket packetData] bytes], [[keyPacket packetData] length], digest);
    
    if (packetBody) {
        time_t signatureCreated = time(0);
        
        packetBody[0] = 4;
        packetBody[1] = 0x18;
        packetBody[2] = 1;
        packetBody[3] = 2;
        packetBody[4] = 0;
        packetBody[5] = 9;
        packetBody[6] = 5;
        packetBody[7] = 2;
        packetBody[8] = signatureCreated >> 24;
        packetBody[9] = (signatureCreated >> 16) & 0xff;
        packetBody[10] = (signatureCreated >> 8) & 0xff;
        packetBody[11] = signatureCreated &  0xff;
        packetBody[12] = 2;
        packetBody[13] = 27;
        packetBody[14] = 0x1; // key flags
        packetBody[15] = 0;
        packetBody[16] = 10;
        packetBody[17] = 9;
        packetBody[18] = 16;
        memcpy((packetBody+19), (digest+12), 8);
        packetBody[27] = 0xff;
        packetBody[28] = 0xff;
        packetBody[29] = primary.publicKeySize >> 8;
        packetBody[30] = primary.publicKeySize & 0xff;
        
        EVP_MD_CTX *hashContext = EVP_MD_CTX_create();
        
        OpenPGPPacket *primaryKeyPacket = [primary exportPublicKey];
        OpenPGPPacket *subkeyPacket = [subkey exportPublicKey];
        
        unsigned char *subkeyBuffer = malloc([subkeyPacket length]);
        memcpy(subkeyBuffer, [[subkeyPacket packetData] bytes], [[subkeyPacket packetData] length]);
        subkeyBuffer[0] = 0x99;

        EVP_DigestInit(hashContext,hashFunction);
        EVP_DigestUpdate(hashContext, [[primaryKeyPacket packetData] bytes], [[primaryKeyPacket packetData] length]);
        EVP_DigestUpdate(hashContext, subkeyBuffer, [[subkeyPacket packetData] length]);
        unsigned char trailer[6];
        hashedBytes = 15;
        trailer[0] = 4;
        trailer[1] = 0xff;
        trailer[2] = hashedBytes >> 24;
        trailer[3] = (hashedBytes >> 16) & 0xff;
        trailer[4] = (hashedBytes >> 8) & 0xff;
        trailer[5] = hashedBytes & 0xff;
        EVP_DigestUpdate(hashContext, trailer, 6);
        EVP_DigestFinal(hashContext, digest, &digestLen);
        
        packetBody[27] = digest[0];
        packetBody[28] = digest[1];
        
        NSData *mpi = [primary signHashWithPrivateKey:digest length:digestLen];
        
        BIGNUM *bn_mpi = BN_new();
        BN_bin2bn([mpi bytes], [mpi length], bn_mpi);
        int mpiBitCount = BN_num_bits(bn_mpi);
        BN_free(bn_mpi);
        
        packetBody[29] = (mpiBitCount >> 8) & 0xff;
        packetBody[30] = mpiBitCount & 0xff;
        
        memcpy((packetBody+31), [mpi bytes], [mpi length]);
        outputPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:2 oldFormat:YES];
    }
    
    return outputPacket;
}

+(OpenPGPPacket *)signString: (NSString *)input withKey: (OpenPGPPublicKey *)keypair using: (NSInteger)algo
{
    EVP_MD *hashFunction = NULL;
    if (algo == 8) {
        hashFunction = EVP_sha256();
    }
    else if( algo == 10 ) {
        hashFunction = EVP_sha512();
    }
    else if( algo == 2 ) {
        hashFunction = EVP_sha1();
    }
    else {
        return nil;
    }
    
    OpenPGPPacket *outputPacket = nil;
    OpenPGPPacket *keyPacket = [keypair exportPublicKey];
    unsigned char digest[EVP_MAX_MD_SIZE];
    int digestLen;
    unsigned char trailer[6];
    SHA1([[keyPacket packetData] bytes], [[keyPacket packetData] length], digest);
    NSUInteger modulusBytes = (keypair.publicKeySize + 7) / 8;
    size_t packetLen = modulusBytes + 43;
    
    unsigned char *packetBody = malloc(packetLen);
    if(packetBody) {
        time_t signatureCreated = time(0);
        packetBody[0] = 4;
        packetBody[1] = 0x13;
        packetBody[2] = 1;
        packetBody[3] = 2;
        packetBody[4] = 0;
        packetBody[5] = 21;
        packetBody[6] = 5;
        packetBody[7] = 2;
        packetBody[8] = (signatureCreated >> 24) & 0xff;
        packetBody[9] = (signatureCreated >> 16) & 0xff;
        packetBody[10] = (signatureCreated >> 8) & 0xff;
        packetBody[11] = signatureCreated & 0xff;
        packetBody[12] = 2;
        packetBody[13] = 25; // primary user id
        packetBody[14] = 0x1;
        packetBody[15] = 2;
        packetBody[16] = 11; // symmetric algorithms
        packetBody[17] = 7; // AES-128 only
        packetBody[18] = 2;
        packetBody[19] = 21; // hash algorithms
        packetBody[20] = algo; // SHA-1 only
        packetBody[21] = 2;
        packetBody[22] = 22; // compression algorithms
        packetBody[23] = 0; // no compression only
        packetBody[24] = 2;
        packetBody[25] = 30; // features
        packetBody[26] = 1; // supports MDC
        packetBody[27] = 0;
        packetBody[28] = 10; // unhashed data
        packetBody[29] = 9;
        packetBody[30] = 16;
        memcpy((packetBody+31),(digest+12),8);
        packetBody[39] = 0xff;
        packetBody[40] = 0xff;
        packetBody[41] = 0xff;
        packetBody[42] = 0xff;
        
        //SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
        //SHA1_Init(ctx);
        //SHA1_Update(ctx, [[keyPacket packetData] bytes], [[keyPacket packetData] length]);
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx, hashFunction);
        EVP_DigestUpdate(ctx, [[keyPacket packetData] bytes], [[keyPacket packetData] length]);
        trailer[0] = 0xb4;
        trailer[1] = ([input length] >> 24) & 0xff;
        trailer[2] = ([input length] >> 16) & 0xff;
        trailer[3] = ([input length] >> 8) & 0xff;
        trailer[4] = ([input length]) & 0xff;
        EVP_DigestUpdate(ctx, trailer, 5);
        EVP_DigestUpdate(ctx, [input UTF8String], [input length]);
        EVP_DigestUpdate(ctx, packetBody, 27);
        trailer[0] = 4;
        trailer[1] = 0xff;
        trailer[2] = 0;
        trailer[3] = 0;
        trailer[4] = 0;
        trailer[5] = 27;
        EVP_DigestUpdate(ctx, trailer, 6);
        EVP_DigestFinal_ex(ctx, digest, &digestLen);
        EVP_MD_CTX_destroy(ctx);
        
        packetBody[39] = digest[0];
        packetBody[40] = digest[1];
        
        NSData *mpi = [keypair signHashWithPrivateKey:digest length:digestLen];
        
        BIGNUM *bn_mpi = BN_new();
        BN_bin2bn([mpi bytes], [mpi length], bn_mpi);
        int mpiBitCount = BN_num_bits(bn_mpi);
        BN_free(bn_mpi);
        
        packetBody[41] = (mpiBitCount >> 8) & 0xff;
        packetBody[42] = mpiBitCount & 0xff;
        
        memcpy((packetBody+43), [mpi bytes], [mpi length]);
        outputPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:2 oldFormat:YES];
        
        free(packetBody);
    }
    
    return outputPacket;
}

@end
