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
@synthesize warn;

-(void)warnSecondarySig: (NSString *)message {
    [m_subkeyWarnIcon setHidden:NO];
    [m_subkeyIcon setHidden:YES];
    
    self.warn = true;
    
    [m_subkeySignatureField setTextColor:[NSColor redColor]];
    [m_subkeySignatureField setStringValue:message];
}

-(void)warnPrimarySig: (NSString *)message {
    [m_primaryWarnIcon setHidden:NO];
    [m_primaryIcon setHidden:YES];
    
    self.warn = true;
    
    [m_primarySignatureField setTextColor:[NSColor redColor]];
    [m_primarySignatureField setStringValue:message];
}

-(void)setSubkeyKeyId:(NSString *)keyId signed:(NSDate *)timestamp until:(NSDate *)expires {
    if (keyId == nil) {
        [m_subkeyBox setHidden:YES];
        [m_subkeyExpiresBox setHidden:YES];
        [m_subkeySignedBox setHidden:YES];
        
        return;
    }
    else {
        [m_subkeyBox setHidden:NO];
        [m_subkeyExpiresBox setHidden:NO];
        [m_subkeySignedBox setHidden:NO];
    }
    [m_subkeyCertLabel setHidden:NO];
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc]init];
    [formatter setTimeStyle:NSDateFormatterShortStyle];
    [formatter setDateStyle:NSDateFormatterShortStyle];
    
    //NSString *format = [NSString stringWithFormat:@"Subkey: %@ (signed %@)",keyId,[formatter stringFromDate:timestamp]];
    [m_subkeyCertLabel setStringValue:[keyId uppercaseString]];
    [m_subkeySigned setStringValue:[formatter stringFromDate:timestamp]];
    
    if (expires) {
        [m_subkeyExpires setStringValue:[formatter stringFromDate:expires]];
    }
    else {
        [m_subkeyExpires setStringValue:@"Never"];
    }
}

-(IBAction)decryptButton:(id)sender {
    AppDelegate *app = [[NSApplication sharedApplication] delegate];
    [app presentDecryptSheet:m_keyId];
}

-(IBAction)privateKeyCertificate:(id)sender {
    AppDelegate *app = [[NSApplication sharedApplication] delegate];
    [app presentPrivateKeyCertificate:m_keyId];
}

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

-(void)setIdentityLocked:(bool)locked {
    if (locked) {
        [m_lockButton setHidden:YES];
        
        [m_decryptButton setImage:[NSImage imageNamed:@"tiny_lock"]];
        [m_privateCertButton setImage:[NSImage imageNamed:@"tiny_lock"]];
    }
    else {
        [m_lockButton setHidden:NO];
        
        [m_decryptButton setImage:nil];
        [m_privateCertButton setImage:nil];
    }
}

-(void)setPublicKey:(OpenPGPPublicKey *)publicKey {
    m_publicKey = publicKey;
}

-(void)setKeyId:(NSString *)keyId {
    m_keyId = [[NSString alloc]initWithString:keyId];
    [m_keyIdField setStringValue:[NSString stringWithFormat:@"(Key ID: %@)",keyId]];
}

-(IBAction)publicKeyCertificate:(id)sender {
    AppDelegate *appDelegate = [NSApp delegate];
    [appDelegate presentPublicKeyCertificate:certificate UserID:m_userId];
}

-(IBAction)composeMessage:(id)sender {
    NSDate *now = [NSDate date];
    if ([now isGreaterThan:m_expirationDate]) {
        NSAlert *alert = [NSAlert alertWithMessageText:@"Certificate expired" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"This certificate has expired and should not be used."];
        [alert runModal];
        
        return;
    }
    
    AppDelegate *appDelegate = [NSApp delegate];
    [appDelegate composeMessageForPublicKey:m_publicKey UserID:m_userId];
}

-(void)setPublicKeyAlgo:(NSString *)publicKeyAlgo {
    if(publicKeyAlgo) {
      [m_publicKeyAlgoField setStringValue:publicKeyAlgo];
    }
}

-(void)setFingerprint: (NSString *)fingerprint {
    NSMutableString *formattedFingerprint = [[NSMutableString alloc]initWithCapacity:50];

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
    [m_primaryIcon setHidden:NO];
    [m_primaryWarnIcon setHidden:YES];
    
    [m_primarySignatureField setTextColor:[NSColor colorWithRed:.5 green:.5 blue:0 alpha:1]];
    [m_primarySignatureField setStringValue:signature];
}
-(void)setSubkeySignature: (NSString *)signature {
    [m_subkeyIcon setHidden:NO];
    [m_subkeyWarnIcon setHidden:YES];
    
    [m_subkeySignatureField setTextColor:[NSColor colorWithRed:.5 green:.5 blue:0 alpha:1]];
    if(signature) {
        [m_subkeySignatureField setStringValue:signature];
        [m_subkeyIcon setHidden:NO];
    } else {
        [m_subkeySignatureField setStringValue:@""];
        [m_subkeyIcon setHidden:YES];
    }
}

-(void)setPrivateCertificate:(bool)isPrivate {
    if (isPrivate) {
        [m_decryptButton setHidden:NO];
        [m_privateCertButton setHidden:NO];
        [m_secretKeyLabel setHidden:NO];
        
        [m_subkeyBox setHidden:YES];
        [m_subkeySignedBox setHidden:YES];
        [m_subkeyExpiresBox setHidden:YES];
    }
    else {
        [m_decryptButton setHidden:YES];
        [m_privateCertButton setHidden:YES];
        [m_secretKeyLabel setHidden:YES];
        
        [m_subkeyBox setHidden:NO];
        [m_subkeySignedBox setHidden:NO];
        [m_subkeyExpiresBox setHidden:NO];
        
        [m_lockButton setHidden:YES];
    }
}

-(IBAction)lockIdentity:(id)sender {
    AppDelegate *app = [[NSApplication sharedApplication] delegate];
    [app lockIdentity:sender];
}

-(void)setValidSince:(NSDate *)created until:(NSDate *)expires {
    if (!created) {
        [m_createdLabel setStringValue:@"### INVALID ###"];
        [m_expireLabel setStringValue:@"### INVALID ###"];
        
        return;
    }
    
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc]init];
    [formatter setTimeStyle:NSDateFormatterShortStyle];
    [formatter setDateStyle:NSDateFormatterShortStyle];
    
    m_creationDate = [created copy];
    [m_createdLabel setStringValue:[formatter stringFromDate:created]];
    
    if (expires) {
        m_expirationDate = [expires copy];
        [m_expireLabel setStringValue:[formatter stringFromDate:expires]];
    }
    else {
        [m_expireLabel setStringValue:@"Never"];
    }
    
}

- (void)viewDidLoad {
    //[super viewDidLoad];
    // Do view setup here.
}

@end
