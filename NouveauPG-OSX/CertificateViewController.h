//
//  CertificateViewController.h
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "OpenPGPPublicKey.h"

@interface CertificateViewController : NSViewController {
    IBOutlet NSTextField *m_userIdField;
    IBOutlet NSTextField *m_emailField;
    IBOutlet NSTextField *m_fingerprintField;
    IBOutlet NSTextField *m_primarySignatureField;
    IBOutlet NSTextField *m_subkeySignatureField;
    IBOutlet NSTextField *m_publicKeyAlgoField;
    IBOutlet NSImageCell *m_mainIdenticon;
    
    OpenPGPPublicKey *m_publicKey;
}

-(void)setUserId:(NSString *)userId;
-(void)setEmail:(NSString *)email;
-(void)setFingerprint: (NSString *)fingerprint;
-(void)setPrimarySignature: (NSString *)signature;
-(void)setSubkeySignature: (NSString *)signature;
-(void)setPublicKeyAlgo: (NSString *)publicKeyAlgo;
-(void)setPublicKey:(OpenPGPPublicKey *)publicKey;
-(void)setIdenticon: (NSInteger)identiconCode;

-(IBAction)composeMessage:(id)sender;

@end
