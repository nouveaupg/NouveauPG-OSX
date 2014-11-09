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
    [m_fingerprintField setStringValue:fingerprint];
}

-(void)setPrimarySignature: (NSString *)signature {
    [m_primarySignatureField setStringValue:signature];
}
-(void)setSubkeySignature: (NSString *)signature {
    [m_subkeySignatureField setStringValue:signature];
}

- (void)viewDidLoad {
    //[super viewDidLoad];
    // Do view setup here.
}

@end
