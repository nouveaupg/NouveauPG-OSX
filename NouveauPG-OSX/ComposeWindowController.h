//
//  ComposeWindowController.h
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "OpenPGPPublicKey.h"

#define kComposePanelStateComposeMessage 1
#define kComposePanelStateEncryptMessage 2
#define kComposePanelStateExportKeystore 3
#define kComposePanelStateExportCertificate 4
#define kComposePanelStateDecryptMessage 5
#define kComposePanelStateReadMessage 6

@interface ComposeWindowController : NSWindowController {
    IBOutlet NSButton *m_leftButton;
    IBOutlet NSButton *m_centerButton;
    IBOutlet NSButton *m_rightButton;
    IBOutlet NSTextField *m_prompt;
    
    IBOutlet NSTextView *m_textView;
    
    NSString *m_userId;
    bool encrypted;
    
    OpenPGPPublicKey *m_publicKey;
}

-(void)presentComposePanel: (NSWindow *)parent withPublicKey:(OpenPGPPublicKey *)publicKey UserId:(NSString *)userId;
-(void)presentPublicKeyCertPanel: (NSWindow *)parent publicKeyCertificate:(NSString *)certText UserId:(NSString *)userId;
-(void)presentPrivateKeyCertPanel: (NSWindow *)parent certificate:(NSString *)certText UserId:(NSString *)userId;
-(void)presentDecryptPanel: (NSWindow *)parent keyId: (NSString *)keyId userId:(NSString *)userId;
-(void)presentDecryptedMessage: (NSWindow *)parent owner: (NSString *)keyId encryptedMessage: (NSString *)message;
-(OpenPGPPublicKey *)validateOpenPGPMessage;

-(IBAction)dismiss:(id)sender;
-(IBAction)leftButton:(id)sender;
-(IBAction)centerButton:(id)sender;
-(IBAction)rightButton:(id)sender;

@property (assign,nonatomic) NSInteger state;

@end
