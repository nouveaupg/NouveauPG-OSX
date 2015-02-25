//
//  OpenPGPPublicKey.m
//  PrivacyForAll
//
//  Created by John Hill on 9/23/13.
//  Copyright (c) 2013 John Hill. All rights reserved.
//

#import "OpenPGPPublicKey.h"
#import "OpenPGPPacket.h"
#import "UserIDPacket.h"

#include <openssl/rsa.h> 
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

@implementation OpenPGPPublicKey

@synthesize publicKeySize;
@synthesize publicKeyType;
@synthesize keyId;

-(bool)decryptKey: (NSString *)passphrase {

    unsigned char *unencrypedBuffer = malloc([m_encryptedKey length]);
    unsigned char keystream[20];
    bool success = false;
    int unencryptedBytes;
    if (unencrypedBuffer) {
        SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
        SHA1_Init(ctx);
        // TODO: ASSUMES 128 bit block size for private cipher
        SHA1_Update(ctx, m_salt, 8);
        SHA1_Update(ctx, [passphrase UTF8String], [passphrase length]);
        SHA1_Final(keystream, ctx);
        free(ctx);
        
        EVP_CIPHER *cipher = EVP_aes_128_cfb128();
        EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(cipher_ctx);
        EVP_DecryptInit(cipher_ctx, cipher, keystream, m_iv);
        unsigned char *encryptedBuffer = [m_encryptedKey bytes];
        EVP_DecryptUpdate(cipher_ctx, unencrypedBuffer, &unencryptedBytes, encryptedBuffer, [m_encryptedKey length]);
        EVP_CIPHER_CTX_free(cipher_ctx);
        EVP_cleanup();
        
        if (unencryptedBytes == [m_encryptedKey length]) {
            // Validate hash
            size_t hashOffset = unencryptedBytes - 20;
            ctx = malloc(sizeof(SHA_CTX));
            SHA1_Init(ctx);
            SHA1_Update(ctx, unencrypedBuffer, hashOffset);
            SHA1_Final(keystream, ctx);
            free(ctx);
            if(memcmp((unencrypedBuffer+hashOffset), keystream, 20) == 0 ) {
                unsigned int declaredBits = (*unencrypedBuffer << 8) | (*(unencrypedBuffer + 1) & 0xff);
                unsigned int offset = 2;
                unsigned int byteLen = (declaredBits + 7) / 8;
                BIGNUM *newValue = BN_new();
                BN_bin2bn((unencrypedBuffer + offset), byteLen, newValue);
                if (declaredBits == BN_num_bits(newValue)) {
                    m_rsaKey->d = newValue;
                    offset += byteLen;
                    success = true;
                }
                else {
                    success = false;
                    NSLog(@"Decoded BIGINT does not match declared size for d");
                }
                declaredBits = (*(unencrypedBuffer + offset) << 8) | (*(unencrypedBuffer+offset + 1 ) & 0xff);
                offset += 2;
                byteLen = (declaredBits + 7) / 8;
                newValue = BN_new();
                BN_bin2bn((unencrypedBuffer + offset), byteLen, newValue);
                if (declaredBits == BN_num_bits(newValue)) {
                    m_rsaKey->p = newValue;
                    offset += byteLen;
                }
                else {
                    success = false;
                    NSLog(@"Decoded BIGINT does not match declared size for p");
                }
                declaredBits = (*(unencrypedBuffer + offset) << 8) | (*(unencrypedBuffer+offset + 1 ) & 0xff);
                offset += 2;
                byteLen = (declaredBits + 7) / 8;
                newValue = BN_new();
                BN_bin2bn((unencrypedBuffer + offset), byteLen, newValue);
                if (declaredBits == BN_num_bits(newValue)) {
                    m_rsaKey->q = newValue;
                    offset += byteLen;
                }
                else {
                    success = false;
                    NSLog(@"Decoded BIGINT does not match declared size for q");
                }
                declaredBits = (*(unencrypedBuffer + offset) << 8) | (*(unencrypedBuffer+offset + 1 ) & 0xff);
                offset += 2;
                byteLen = (declaredBits + 7) / 8;
                newValue = BN_new();
                BN_bin2bn((unencrypedBuffer + offset), byteLen, newValue);
                if (declaredBits == BN_num_bits(newValue)) {
                    m_rsaKey->iqmp = newValue;
                    offset += byteLen;
                }
                else {
                    success = false;
                    NSLog(@"Decoded BIGINT does not match declared size for iqmp");
                }
                if(success) {
                    m_encryptedKey = nil;
                }

            }
            else {
                NSLog(@"Invalid SHA-1 integrity check for decrypted key material in key: %@",self.keyId);
            }
            memset(unencrypedBuffer, 0, unencryptedBytes);
        }
        free(unencrypedBuffer);
    }
    
    return success;
}

-(bool)isEncrypted {
    if (m_encryptedKey) {
        return TRUE;
    }
    return FALSE;
}

-(OpenPGPPacket *)exportPrivateKeyUnencrypted {
    OpenPGPPacket *privateKeyPacket = nil;
    int modulusBytes = (BN_num_bits(m_rsaKey->n)+7)/8;
    int exponentBytes = (BN_num_bits(m_rsaKey->e)+7)/8;
    int secretExponentBytes = (BN_num_bits(m_rsaKey->d)+7)/8;
    int secretPrimeP = (BN_num_bits(m_rsaKey->p)+7)/8;
    int secretPrimeQ = (BN_num_bits(m_rsaKey->q)+7)/8;
    int secretInvQModP = (BN_num_bits(m_rsaKey->iqmp)+7)/8;
    
    // 10 = version byte + 4 timestamp bytes + public algo byte + lengths for n and e MPI's
    size_t packetLen = 10 + modulusBytes + exponentBytes;
    // 11 = s2k byte + lengths for 4 MPI's (8 bytes) + 2 checksum bytes
    packetLen += 11 + secretExponentBytes + secretPrimeP + secretPrimeQ + secretInvQModP;
    size_t offset = 0;
    unsigned char *packetBody = malloc(packetLen);
    if (packetBody) {
        packetBody[0] = 4;
        packetBody[1] = m_generatedTimestamp >> 24;
        packetBody[2] = (m_generatedTimestamp >> 16) & 0xff;
        packetBody[3] = (m_generatedTimestamp >> 8) & 0xff;
        packetBody[4] = m_generatedTimestamp & 0xff;
        packetBody[5] = 1;
        packetBody[6] = BN_num_bits(m_rsaKey->n) >> 8;
        packetBody[7] = BN_num_bits(m_rsaKey->n) & 0xff;
        BN_bn2bin(m_rsaKey->n, (packetBody + 8));
        offset += modulusBytes;
        packetBody[8+offset] = BN_num_bits(m_rsaKey->e) >> 8;
        packetBody[9+offset] = BN_num_bits(m_rsaKey->e) & 0xff;
        offset += 10;
        BN_bn2bin(m_rsaKey->e, (packetBody + offset));
        offset += (BN_num_bits(m_rsaKey->e) + 7)/8;
        
        // secret section
        
        packetBody[offset++] = 0;
        
        size_t secretOffset = offset;
        
        packetBody[offset++] = BN_num_bits(m_rsaKey->d) >> 8;
        packetBody[offset++] = BN_num_bits(m_rsaKey->d) & 0xff;
        BN_bn2bin(m_rsaKey->d, (packetBody + offset));
        offset +=  secretExponentBytes;
        
        packetBody[offset++] = BN_num_bits(m_rsaKey->p) >> 8;
        packetBody[offset++] = BN_num_bits(m_rsaKey->p) & 0xff;
        BN_bn2bin(m_rsaKey->p, (packetBody + offset));
        offset += secretPrimeP;
        
        packetBody[offset++] = BN_num_bits(m_rsaKey->q) >> 8;
        packetBody[offset++] = BN_num_bits(m_rsaKey->q) & 0xff;
        BN_bn2bin(m_rsaKey->q, (packetBody + offset));
        offset += secretPrimeQ;
        
        packetBody[offset++] = BN_num_bits(m_rsaKey->iqmp) >> 8;
        packetBody[offset++] = BN_num_bits(m_rsaKey->iqmp) & 0xff;
        BN_bn2bin(m_rsaKey->iqmp, (packetBody + offset));
        offset += secretInvQModP;
        
        // 8 = 2 byte length field for each MPI (8 bytes total)
        unsigned long long checksum = 0;
        size_t secretLen = secretExponentBytes + secretInvQModP + secretPrimeP + secretPrimeQ + 8;
        for (size_t x = secretOffset; x < offset; x++) {
            checksum += packetBody[x];
        }
        unsigned int chkvalue = checksum % 65536;
        packetBody[offset++] = (chkvalue >> 8) & 0xff;
        packetBody[offset++] = chkvalue & 0xff;
        
        if (m_subkey) {
            privateKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:7 oldFormat:YES];
        }
        else {
            privateKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:5 oldFormat:YES];
        }
    }
    
    return privateKeyPacket;
}

-(OpenPGPPacket *)exportPrivateKey: (NSString *)passphrase {
    OpenPGPPacket *privateKeyPacket = nil;
    int modulusBytes = (BN_num_bits(m_rsaKey->n)+7)/8;
    int exponentBytes = (BN_num_bits(m_rsaKey->e)+7)/8;
    int secretExponentBytes = (BN_num_bits(m_rsaKey->d)+7)/8;
    int secretPrimeP = (BN_num_bits(m_rsaKey->p)+7)/8;
    int secretPrimeQ = (BN_num_bits(m_rsaKey->q)+7)/8;
    int secretInvQModP = (BN_num_bits(m_rsaKey->iqmp)+7)/8;
    int cipherOutputLen;
    
    unsigned char keystream[20];
    
    size_t packetLen = exponentBytes + modulusBytes + 66;
    packetLen += secretExponentBytes + secretInvQModP;
    packetLen += secretPrimeP + secretPrimeQ;
    
    size_t offset = 0;
    unsigned char *packetBody = malloc(packetLen);
    memset(packetBody, 0xcd, packetLen);
    if(packetBody) {
        packetBody[0] = 4;
        packetBody[1] = m_generatedTimestamp >> 24;
        packetBody[2] = (m_generatedTimestamp >> 16) & 0xff;
        packetBody[3] = (m_generatedTimestamp >> 8) & 0xff;
        packetBody[4] = m_generatedTimestamp & 0xff;
        packetBody[5] = 1;
        packetBody[6] = BN_num_bits(m_rsaKey->n) >> 8;
        packetBody[7] = BN_num_bits(m_rsaKey->n) & 0xff;
        BN_bn2bin(m_rsaKey->n, (packetBody + 8));
        offset += modulusBytes;
        packetBody[8+offset] = BN_num_bits(m_rsaKey->e) >> 8;
        packetBody[9+offset] = BN_num_bits(m_rsaKey->e) & 0xff;
        BN_bn2bin(m_rsaKey->e, (packetBody + 10 + offset));
        offset += (BN_num_bits(m_rsaKey->e) + 7)/8;
        // secret key section
        
        packetBody[10+offset] = 254; // Use SHA-1 to validate key material
        packetBody[11+offset] = 7; // AES-128 to encrypt key material
        packetBody[12+offset] = 0x1; // Salted S2K
        packetBody[13+offset] = 0x2; // Use SHA-1 hash for S2K
        
        RAND_bytes((packetBody+14+offset), 24);
        //RAND_bytes((packetBody+22), 8);
        int privateKeyBoundary = offset;
        
        
        int protectedLen = secretExponentBytes + secretInvQModP + secretPrimeP + secretPrimeQ + 28;
        unsigned char *protected = malloc(protectedLen);
        if(protected) {
            offset = 0;
            protected[0] = BN_num_bits(m_rsaKey->d) >> 8;
            protected[1] = BN_num_bits(m_rsaKey->d) & 0xff;
            BN_bn2bin(m_rsaKey->d, (protected+2));
            offset += secretExponentBytes + 2;
            protected[offset] = BN_num_bits(m_rsaKey->p) >> 8;
            protected[offset+1] = BN_num_bits(m_rsaKey->p) & 0xff;
            BN_bn2bin(m_rsaKey->p, (protected + offset + 2));
            offset += secretPrimeP + 2;
            protected[offset] = BN_num_bits(m_rsaKey->q) >> 8;
            protected[offset+1] = BN_num_bits(m_rsaKey->q) & 0xff;
            BN_bn2bin(m_rsaKey->q, (protected + offset + 2));
            offset += secretPrimeQ + 2;
            protected[offset] = BN_num_bits(m_rsaKey->iqmp) >> 8;
            protected[offset+1] = BN_num_bits(m_rsaKey->iqmp) & 0xff;
            BN_bn2bin(m_rsaKey->iqmp, (protected+offset+2));
            int keyMaterialLen = secretExponentBytes + secretInvQModP + secretPrimeP + secretPrimeQ + 8;
            // SHA-1 to check validity of key material
            SHA1(protected, keyMaterialLen, (protected + keyMaterialLen) );
            
            // Now we generate the AES key to encrypt the RSA private key material
            
            SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
            SHA1_Init(ctx);
            unsigned char *salt = (packetBody + 14 + privateKeyBoundary);
            unsigned char *iv = (salt + 8);
            
            SHA1_Update(ctx, salt, 8);
            SHA1_Update(ctx, [passphrase UTF8String], [passphrase length]);
            SHA1_Final(keystream, ctx);
            free(ctx);
            
            EVP_CIPHER *cipher = EVP_aes_128_cfb128();
            EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX_init(cipher_ctx);
            EVP_EncryptInit(cipher_ctx, cipher, keystream, iv);
            EVP_EncryptUpdate(cipher_ctx, (iv+16), &cipherOutputLen, protected, protectedLen);
            EVP_CIPHER_CTX_free(cipher_ctx);
            //EVP_cleanup();
            
            
            memset(protected, 0, protectedLen);
            
            EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX_init(decrypt_ctx);
            EVP_DecryptInit(decrypt_ctx, cipher, keystream, iv);
            EVP_DecryptUpdate(decrypt_ctx, protected, &protectedLen, (iv+16), cipherOutputLen);
            EVP_CIPHER_CTX_free(decrypt_ctx);
            
            if (m_subkey) {
                privateKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:7 oldFormat:YES];
            }
            else {
                privateKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:5 oldFormat:YES];
            }
            free(protected);
        }
        free(packetBody);
    }
    
    return privateKeyPacket;
}

-(OpenPGPPacket *)exportPublicKey {
    OpenPGPPacket *publicKeyPacket = nil;
    
    int modulusBytes = (BN_num_bits(m_rsaKey->n)+7)/8;
    int exponentBytes = (BN_num_bits(m_rsaKey->e)+7)/8;
    
    size_t packetLen = exponentBytes + modulusBytes + 10;
    unsigned char *packetBody = malloc(packetLen);
    memset(packetBody, 0xcd, packetLen);
    if(packetBody) {
        packetBody[0] = 4;
        packetBody[1] = m_generatedTimestamp >> 24;
        packetBody[2] = (m_generatedTimestamp >> 16) & 0xff;
        packetBody[3] = (m_generatedTimestamp >> 8) & 0xff;
        packetBody[4] = m_generatedTimestamp & 0xff;
        packetBody[5] = 1;
        packetBody[6] = BN_num_bits(m_rsaKey->n) >> 8;
        packetBody[7] = BN_num_bits(m_rsaKey->n) & 0xff;
        BN_bn2bin(m_rsaKey->n, (packetBody + 8));
        packetBody[8+modulusBytes] = BN_num_bits(m_rsaKey->e) >> 8;
        packetBody[9+modulusBytes] = BN_num_bits(m_rsaKey->e) & 0xff;
        BN_bn2bin(m_rsaKey->e, (packetBody + 10 + modulusBytes));
        if (m_subkey) {
            publicKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:14 oldFormat:YES];
        }
        else {
            publicKeyPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:packetBody length:packetLen] tag:6 oldFormat:YES];
        }
        free(packetBody);
    }
    return publicKeyPacket;
}

-(NSData *)decryptSignature: (NSData *)encryptedSig {
    NSData *retValue = nil;
    
    unsigned char *output = malloc([encryptedSig length]);
    int result = RSA_public_decrypt([encryptedSig length], [encryptedSig bytes], output, m_rsaKey, RSA_NO_PADDING);
    if (result == [encryptedSig length]) {
        retValue = [[NSData alloc]initWithBytes:output length:result];
    }
    free(output);
    
    return retValue;
}

-(id)initWithKeyLength:(int)bits isSubkey:(BOOL)subkey {
    if (self = [super init]) {
        m_rsaKey = RSA_generate_key(bits, 3, NULL, NULL);
        m_generatedTimestamp = time(0);
        m_subkey = subkey;
        publicKeySize = bits;
        
        OpenPGPPacket *packet = [self exportPublicKey];
        SHA1([[packet packetData] bytes], [[packet packetData] length], m_fingerprint);
        self.keyId = [NSString stringWithFormat:@"%02x%02x%02x%02x",m_fingerprint[16],m_fingerprint[17],m_fingerprint[18],m_fingerprint[19]];
    }
    return self;
}

-(id)initWithEncryptedPacket:(OpenPGPPacket *)keyPacket {
    if (self = [super init]) {
        int offset = 0;
        if ([keyPacket packetTag] == 5 || [keyPacket packetTag] == 7) {
            unsigned char *ptr = (unsigned char *)[[keyPacket packetData] bytes];
            ptr += 3;
            offset += 3;
            
            if ([keyPacket packetTag] == 7) {
                m_subkey = true;
            }
            else {
                m_subkey = false;
            }
            
            if (*ptr == 4) {
                m_generatedTimestamp = *(ptr+1)<<24 | *(ptr+2)<<16 | *(ptr+3)<<8 | *(ptr+4);
                unsigned char *algo = ptr + 5;
                offset += 5;
                if( *algo == 1 || *algo == 2 ) {
                    publicKeyType = kPublicKeyType_RSAEncryptAndSign;
                    
                    m_rsaKey = RSA_new();
                    BIGNUM *mod_n = BN_new();
                    BIGNUM *exp_e = BN_new();
                    
                    int mpi_len;
                    ptr = algo + 1;
                    offset += 1;
                    mpi_len = ((*ptr << 8 | *(ptr+1)) + 7) / 8;
                    ptr += 2;
                    offset += 2;
                    
                    BN_bin2bn(ptr, mpi_len, mod_n);
                   
                    publicKeySize = BN_num_bits(mod_n);
                    
                    ptr += mpi_len;
                    offset += mpi_len;
                    mpi_len = ((*ptr << 8 | *(ptr+1)) + 7) / 8;
                    ptr += 2;
                    offset += 2;
                    BN_bin2bn(ptr, mpi_len, exp_e);
                    offset += mpi_len;
                    
                    m_rsaKey->e = exp_e;
                    m_rsaKey->n = mod_n;
                    
                    
                    ptr = ((unsigned char *)[[keyPacket packetData] bytes] + offset);
                    if (*ptr == 254) {
                        // algo
                        ptr++;
                        // s2k
                        ptr++;
                        // TODO: ASSUMES encryption algorithm will have 128 bit blocks
                        m_salt = malloc(8);
                        m_iv = malloc(16);
                        memcpy(m_salt, ptr+2, 8);
                        ptr+= 10;
                        memcpy(m_iv, ptr, 16);
                        offset += 28;
                        
                        unsigned char *encryptedBuffer;
                        size_t encryptedBufferLen = [[keyPacket packetData]length] - offset;
                        encryptedBuffer = malloc(encryptedBufferLen);
                        if (encryptedBuffer) {
                            memcpy(encryptedBuffer, (unsigned char *)([[keyPacket packetData] bytes]+offset), encryptedBufferLen);
                            m_encryptedKey = [[NSData alloc]initWithBytes:encryptedBuffer length:encryptedBufferLen];
                            free(encryptedBuffer);
                        }
                    }
                    else if( *ptr == 0 ) {
                        // unencrypted key
                        // secret exponent d
                        int secretExponentBits = 0;
                        ptr++;
                        
                        secretExponentBits = *ptr;
                        secretExponentBits <<= 8;
                        ptr++;
                        secretExponentBits |= *ptr;
                        ptr++;
                        
                        BIGNUM *bn = BN_new();
                        mpi_len = (secretExponentBits + 7) / 8;
                        BN_bin2bn(ptr, mpi_len, bn);
                        m_rsaKey->d = bn;
                        
                        ptr += mpi_len;
                        // secret prime P
                        bn = BN_new();
                        int secretPrimePBits = *ptr;
                        secretPrimePBits <<= 8;
                        ptr++;
                        secretPrimePBits |= *ptr;
                        ptr++;
                        
                        mpi_len = (secretPrimePBits + 7) / 8;
                        BN_bin2bn(ptr, mpi_len, bn);
                       
                        m_rsaKey->p = bn;
                        ptr += mpi_len;
                        bn = BN_new();
                        // secret prime Q
                        int secretPrimeQBits = *ptr;
                        secretPrimeQBits <<= 8;
                        ptr++;
                        secretPrimeQBits |= *ptr;
                        ptr++;
                        
                        mpi_len = (secretPrimeQBits + 7) / 8;
                        BN_bin2bn(ptr, mpi_len, bn);
                        m_rsaKey->q = bn;
                        
                         //NSLog(@"BN_num_bits (q): %d",BN_num_bits(m_rsaKey->q));
                        //assert(BN_num_bits(m_rsaKey->q) == secretPrimeQBits);
                        
                        ptr += mpi_len;
                        bn = BN_new();
                        // inverse of p % q
                        int inverseBits = *ptr;
                        inverseBits <<= 8;
                        ptr++;
                        inverseBits |= *ptr;
                        ptr++;
                        
                        mpi_len = (inverseBits + 7) / 8;
                        BN_bin2bn(ptr, mpi_len, bn);
                        m_rsaKey->iqmp = bn;
                        
                        //NSLog(@"BN_num_bits (q): %d",BN_num_bits(m_rsaKey->iqmp));
                        //assert(BN_num_bits(m_rsaKey->iqmp) == inverseBits);
                        
                    }
                    
                    
                    OpenPGPPacket *publicKeyPacket = [self exportPublicKey];
                    
                    unsigned char digest[20];
                    
                    ptr = malloc([[publicKeyPacket packetData] length]);
                    SHA_CTX *ctx = malloc(sizeof(SHA_CTX));
                    SHA_Init(ctx);
                    memcpy(ptr, [[publicKeyPacket packetData] bytes], [[publicKeyPacket packetData] length]);
                    *ptr = 0x99;
                    SHA1_Update(ctx, ptr, [[publicKeyPacket packetData] length]);
                    SHA1_Final(digest, ctx);
                    free(ptr);
                    free(ctx);
                    
                    memcpy(m_fingerprint, digest, 20);
                    
                    
                    keyId = [[NSString stringWithFormat:@"%02x%02x%02x%02x",digest[16],digest[17],digest[18],digest[19]] copy];
                    
                    if(m_encryptedKey) {
                        NSLog(@"Initialized encrypted RSA Key ID: %@",keyId);
                    }
                    else {
                        NSLog(@"Initialized unencrypted RSA Key ID: %@",keyId);
                    }

                    
                }
                else {
                    m_publicKeyType = - 1;
                    NSLog(@"DSA not currently supported!");
                }
            }
            else {
                NSLog(@"Unsupported public key format: %d",*ptr);
            }
        }
    }
    return self;
}

-(unsigned char *)decryptBytes: (const unsigned char *)encryptedBytes length:(int)len {
    unsigned char *output;
    unsigned char *unencryptedBuffer = malloc(len);

    int result = RSA_private_decrypt(len, encryptedBytes, unencryptedBuffer, m_rsaKey, RSA_NO_PADDING);
    
    int offset = 1;
    
    if (result > 0 && *unencryptedBuffer == 0) {
        while (unencryptedBuffer[offset] != 0) {
            offset++;
        }
    }
    offset++;
    if (unencryptedBuffer[offset] == 7) {
        offset++;
        output = malloc(16);
        memcpy(output, unencryptedBuffer+offset, 16);
        memset(unencryptedBuffer, len, 0x0);
        free(unencryptedBuffer);
        return output;
    }
    else {
        NSLog(@"Unsupported symmetric algorithm: %d",unencryptedBuffer[offset]);
    }
    free(unencryptedBuffer);
    return NULL;
}

-(id)initWithPacket:(OpenPGPPacket *)keyPacket {
    if(self = [super init]) {
        m_encryptedKey = nil;
        if ([keyPacket packetTag] == 6 || [keyPacket packetTag] == 14) {
            unsigned char *ptr = (unsigned char *)[[keyPacket packetData] bytes];
            ptr += 3;
            
            if ([keyPacket packetTag] == 14) {
                m_subkey = true;
            }
            else {
                m_subkey = false;
            }
            
            if (*ptr == 4) {
                m_generatedTimestamp = *(ptr+1)<<24 | *(ptr+2)<<16 | *(ptr+3)<<8 | *(ptr+4);
                unsigned char *algo = ptr + 5;
                if( *algo == 1 ) {
                    publicKeyType = kPublicKeyType_RSAEncryptAndSign;
                    
                    m_rsaKey = RSA_new();
                    BIGNUM *mod_n = BN_new();
                    BIGNUM *exp_e = BN_new();
                    
                    int mpi_len;
                    ptr = algo + 1;
                    mpi_len = ((*ptr << 8 | *(ptr+1)) + 7) / 8;
                    ptr += 2;
                    
                    BN_bin2bn(ptr, mpi_len, mod_n);
                    
                    publicKeySize = BN_num_bits(mod_n);
                    
                    ptr += mpi_len;
                    mpi_len = ((*ptr << 8 | *(ptr+1)) + 7) / 8;
                    ptr += 2;
                    BN_bin2bn(ptr, mpi_len, exp_e);
                    
                    m_rsaKey->e = exp_e;
                    m_rsaKey->n = mod_n;
                    
                    unsigned char digest[20];
                    
                    ptr = malloc([[keyPacket packetData] length]);
                    memcpy(ptr, [[keyPacket packetData] bytes], [[keyPacket packetData] length]);
                    *ptr = 0x99;
                    
                    SHA1(ptr, [[keyPacket packetData] length], digest);
                    free(ptr);
                    
                    memcpy(m_fingerprint, digest, 20);
                    
                    self.keyId = [NSString stringWithFormat:@"%02x%02x%02x%02x",digest[16],digest[17],digest[18],digest[19]];
                    NSLog(@"Initialized RSA Key ID: %@",keyId);
                }
                else {
                    publicKeyType = - 1;
                    NSLog(@"Unsupported public key format: %d", *ptr);
                }
            }
            else {
                NSLog(@"Unsupported public key format: %d",*ptr);
            }
        }
    }
    return self;
}

-(unsigned char *)fingerprintBytes {
    return m_fingerprint;
}

-(bool)isSubkey {
    return m_subkey;   
}

-(bool)hasPrivateKey {
    if (m_rsaKey->d != NULL) {
        return YES;
    }
    if (m_encryptedKey) {
        return YES;
    }
    return NO;
}

-(OpenPGPPacket *)encryptBytes: (const unsigned char *)sessionKey length:(int)keyLen {
    int keyBits = self.publicKeySize;
    int frameSize = (keyBits+7)/8;
    int checksum = 0;
    int randomFill = 0;
    unsigned char *keyBuffer = malloc(frameSize);
    OpenPGPPacket *outPacket = nil;
    if (keyBuffer) {
        memset(keyBuffer, 0, frameSize);
        for (int i = 0; i < keyLen; i++) {
            checksum += sessionKey[i];
        }
        keyBuffer[0] = 0;
        keyBuffer[1] = 2;
        
        randomFill = frameSize - 22;
        unsigned char *randomPool = malloc(randomFill);
        int i = 0;
        RAND_bytes(randomPool, randomFill);
        RAND_bytes((keyBuffer+2), randomFill);
        // zero is the escape signal so we need to purge all randomly generated zeros
        // from the padding
        for (int x = 2; x < (randomFill + 2); x++) {
            if (*(keyBuffer+x) == 0) {
                //NSLog(@"Purging zero byte (%d) from padding",x);
                while (randomPool[i++] == 0) {
                    if (i >= randomFill) {
                        break;
                    }
                }
                *(keyBuffer+x) = randomPool[i];
            }
        }
        free(randomPool);
        
        keyBuffer[randomFill+2] = 0;
        keyBuffer[randomFill+3] = 7; // AES/128 bit key encryption
        memcpy((keyBuffer + randomFill + 4), sessionKey, keyLen);
        keyBuffer[frameSize-1] = checksum & 0xff;
        keyBuffer[frameSize-2] = (checksum >> 8) & 0xff;
        
        unsigned char *encryptedKeyBuffer = malloc(frameSize);
        if (encryptedKeyBuffer) {
            
            int result = RSA_public_encrypt(frameSize, keyBuffer, encryptedKeyBuffer, m_rsaKey, RSA_NO_PADDING);
            
            memset(keyBuffer, 0, frameSize); // padded buffers contain very easy to detect patterns and should be overwritten when they are no longer needed
            free(keyBuffer);
            if (result == frameSize) {
                int packetLen = result + 12;
                unsigned char *packetBody = malloc(packetLen);
                packetBody[0] = 3;
                memcpy((packetBody+1), (m_fingerprint + 12), 8);
                packetBody[9] = 1;
                packetBody[10] = (keyBits>>8) & 0xff;
                packetBody[11] = keyBits & 0xff;
                memcpy((packetBody+12), encryptedKeyBuffer, frameSize);
                outPacket = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytesNoCopy:packetBody length:packetLen] tag:1 oldFormat:true];
            }
            free(encryptedKeyBuffer);
        }
        else {
            NSLog(@"Could not create buffer for encrypted session key.");
        }
    }
    return outPacket;
}

-(NSData *)signHashWithPrivateKey: (unsigned char *)hash length:(int)len {
    if ([self hasPrivateKey]) {
        int frameSize = (BN_num_bits(m_rsaKey->n)+7)/8;
        unsigned char asn_sha1[15] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
        
        unsigned char asn_sha256[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20};
        
        unsigned char asn_sha512[19] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40};
        
        unsigned char *asn;
        unsigned int asnLen;
        
        switch (len) {
            case 32:
                asnLen = 19;
                asn = asn_sha256;
                break;
            case 64:
                asnLen = 19;
                asn = asn_sha512;
                break;
                
            default:
                asnLen = 15;
                asn = asn_sha1;
                break;
        }
        
        unsigned char *frame = malloc(frameSize);
        int paddingFill = frameSize - (len + asnLen + 3);
        if (frame) {
            frame[0] = 0;
            frame[1] = 1;
            memset((frame+2),0xff, paddingFill);
            frame[2+paddingFill] = 0;
            memcpy((frame+paddingFill+3), asn, asnLen);
            memcpy((frame+paddingFill+asnLen+3), hash, len);
            unsigned char *output = malloc(frameSize);
            if (output) {
                int result = RSA_private_encrypt(frameSize, frame, output, m_rsaKey, RSA_NO_PADDING);
                memset(frame, 0, frameSize);
                free(frame);
                if(result == frameSize) {
                    NSData *outputData = [NSData dataWithBytes:output length:frameSize];
                    free(output);
                    return outputData;
                }
                else {
                    NSLog(@"Error: could not encrypt");
                    free(output);
                }
            }
            else {
                NSLog(@"Error creating output buffer: malloc error");
            }
        }
        else {
            NSLog(@"Malloc errors during hash signing.");
        }
    }
    return nil;
}



@end
