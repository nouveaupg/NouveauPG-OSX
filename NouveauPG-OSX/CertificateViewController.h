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
    IBOutlet NSTextField *m_keyIdField;
    IBOutlet NSImageView *m_subkeyCertIcon;
    IBOutlet NSImageView *m_userIdCertIcon;
    IBOutlet NSButton *m_decryptButton;
    IBOutlet NSButton *m_privateCertButton;
    IBOutlet NSTextField *m_userIdCertLabel;
    IBOutlet NSTextField *m_createdLabel;
    IBOutlet NSTextField *m_expireLabel;
    IBOutlet NSTextField *m_subkeyCertLabel;
    IBOutlet NSButton *m_lockButton;
    IBOutlet NSBox *m_subkeyBox;
    IBOutlet NSBox *m_subkeySignedBox;
    IBOutlet NSBox *m_subkeyExpiresBox;
    IBOutlet NSTextField *m_secretKeyLabel;
    IBOutlet NSTextField *m_subkeySigned;
    IBOutlet NSTextField *m_subkeyExpires;
    
    IBOutlet NSImageView *m_primaryWarnIcon;
    IBOutlet NSImageView *m_primaryIcon;
    IBOutlet NSImageView *m_subkeyWarnIcon;
    IBOutlet NSImageView *m_subkeyIcon;
    
    OpenPGPPublicKey *m_publicKey;
    NSString *m_userId;
    NSString *m_keyId;
    
    NSDate *m_creationDate;
    NSDate *m_expirationDate;
}

-(void)warnPrimarySig: (NSString *)message;
-(void)warnSecondarySig: (NSString *)message;
-(void)setUserId:(NSString *)userId;
-(void)setEmail:(NSString *)email;
-(void)setFingerprint: (NSString *)fingerprint;
-(void)setPrimarySignature: (NSString *)signature;
-(void)setSubkeySignature: (NSString *)signature;
-(void)setPublicKeyAlgo: (NSString *)publicKeyAlgo;
-(void)setPublicKey:(OpenPGPPublicKey *)publicKey;
-(void)setIdenticon: (NSInteger)identiconCode;
-(void)setKeyId:(NSString *)keyId;
-(void)setPrivateCertificate:(bool)isPrivate;
-(void)setIdentityLocked:(bool)locked;
-(void)setSubkeyKeyId:(NSString *)keyId signed:(NSDate *)timestamp until: (NSDate *)expires;
-(void)setValidSince:(NSDate *)created until:(NSDate *)expires;

-(IBAction)composeMessage:(id)sender;
-(IBAction)publicKeyCertificate:(id)sender;
-(IBAction)decryptButton:(id)sender;
-(IBAction)privateKeyCertificate:(id)sender;
-(IBAction)lockIdentity:(id)sender;

@property (copy) NSString *certificate;
@property (assign) bool warn;

@end
