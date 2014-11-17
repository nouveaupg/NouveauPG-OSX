//
//  PasswordWindow.m
//  NouveauPG-OSX
//
//  Created by John Hill on 11/17/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "PasswordWindow.h"

@interface PasswordWindow () {
    IBOutlet NSTextField *m_promptField;
    IBOutlet NSSecureTextField *m_passwordField;
    IBOutlet NSSecureTextField *m_repeatPasswordField;
    
    OpenPGPPublicKey *m_privateKey;
}

@end

@implementation PasswordWindow

-(IBAction)cancelButton:(id)sender {
    [NSApp stopModal];
}

-(IBAction)confirmButton:(id)sender {
    
}

-(void)presentPasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent {
    NSWindow *window = [self window];
    m_privateKey = privateKey;
    
    [m_promptField setStringValue:prompt];
    [m_repeatPasswordField setHidden:YES];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:nil contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

-(void)presentChangePasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent {
    m_privateKey = privateKey;
    
    [m_promptField setStringValue:prompt];
    [m_repeatPasswordField setHidden:NO];
}

- (void)windowDidLoad {
    [super windowDidLoad];
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
}

@end
