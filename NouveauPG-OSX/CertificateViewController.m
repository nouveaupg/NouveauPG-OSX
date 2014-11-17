//
//  CertificateViewController.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "CertificateViewController.h"
#import "IdenticonImage.h"
#import "AppDelegate.h"

@interface CertificateViewController ()

@end

@implementation CertificateViewController

@synthesize certificate;

-(void)setIdenticon: (NSInteger)identiconCode {
    IdenticonImage *identiconImage = [[IdenticonImage alloc]initWithIdenticonCode:identiconCode];
    [m_mainIdenticon setImage:identiconImage];
}

-(void)setUserId:(NSString *)userId {
    m_userId = [[NSString alloc]initWithString:userId];
    [m_userIdField setStringValue:userId];
}

-(void)setEmail:(NSString *)email {
    if(email) {
        [m_emailField setStringValue:email];
    }
    else {
        [m_emailField setStringValue:@""];
    }
}

-(void)setPublicKey:(OpenPGPPublicKey *)publicKey {
    m_publicKey = publicKey;
}

-(void)setKeyId:(NSString *)keyId {
    [m_keyIdField setStringValue:keyId];
}

-(IBAction)publicKeyCertificate:(id)sender {
    AppDelegate *appDelegate = [NSApp delegate];
    [appDelegate presentPublicKeyCertificate:certificate UserID:m_userId];
}

-(IBAction)composeMessage:(id)sender {
    AppDelegate *appDelegate = [NSApp delegate];
    [appDelegate composeMessageForPublicKey:m_publicKey UserID:m_userId];
}

-(void)setPublicKeyAlgo:(NSString *)publicKeyAlgo {
    if(publicKeyAlgo) {
      [m_publicKeyAlgoField setStringValue:publicKeyAlgo];
    }
}

-(void)setFingerprint: (NSString *)fingerprint {
    NSMutableString *formattedFingerprint = [[NSMutableString alloc]initWithCapacity:24];

    for( int x = 0; x < 40; x++ ) {
        [formattedFingerprint appendFormat:@"%c",[fingerprint characterAtIndex:x]];
        int t = x + 1;
        if (t > 0 && (t % 8) == 0 && t < 40) {
            [formattedFingerprint appendFormat:@":"];
        }
    }
    
    [m_fingerprintField setStringValue:formattedFingerprint];
}

-(void)setPrimarySignature: (NSString *)signature {
    [m_primarySignatureField setStringValue:signature];
}
-(void)setSubkeySignature: (NSString *)signature {
    if(signature) {
        [m_subkeySignatureField setStringValue:signature];
        [m_subkeyCertIcon setHidden:NO];
    } else {
        [m_subkeySignatureField setStringValue:@""];
        [m_subkeyCertIcon setHidden:YES];
    }
}

-(void)setPrivateCertificate:(bool)isPrivate {
    if (isPrivate) {
        [m_decryptButton setHidden:NO];
        [m_privateCertButton setHidden:NO];
    }
    else {
        [m_decryptButton setHidden:YES];
        [m_privateCertButton setHidden:YES];
    }
}

- (void)viewDidLoad {
    //[super viewDidLoad];
    // Do view setup here.
}

@end
