//
//  PasswordWindow.h
//  NouveauPG-OSX
//
//  Created by John Hill on 11/17/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "OpenPGPPublicKey.h"

#define kPasswordWindowStateUnlockIdentity 1
#define kPasswordWindowStateChangePassword 2

@interface PasswordWindow : NSWindowController

@property (assign) NSInteger state;

-(IBAction)confirmButton:(id)sender;
-(IBAction)cancelButton:(id)sender;

-(void)presentPasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent;
-(void)presentChangePasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent;

@end
