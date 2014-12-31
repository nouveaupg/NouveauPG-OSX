//
//  PasswordWindow.m
//  NouveauPG-OSX
//
//  Created by John Hill on 11/17/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "PasswordWindow.h"
#import "AppDelegate.h"
#import "Identities.h"

@interface PasswordWindow () {
    IBOutlet NSTextField *m_promptField;
    IBOutlet NSSecureTextField *m_passwordField;
    IBOutlet NSSecureTextField *m_repeatPasswordField;
    
    OpenPGPPublicKey *m_privateKey;
}

@end

@implementation PasswordWindow

@synthesize state;

-(IBAction)cancelButton:(id)sender {
    [NSApp stopModal];
}

-(IBAction)confirmButton:(id)sender {
    AppDelegate *app = [[NSApplication sharedApplication] delegate];
    if (state == kPasswordWindowStateUnlockIdentity) {
        NSString *password = [m_passwordField stringValue];
        if ([m_privateKey decryptKey:password]) {
            Identities *selected = [app identityForKeyId:m_privateKey.keyId];
            
            if ([selected.secondaryKey isEncrypted]) {
                if ([selected.secondaryKey decryptKey:password]) {
                    NSLog(@"Subkey decrypted.");
                }
                else {
                    NSLog(@"Error: could not decrypt subkey.");
                }
                
                [app refreshCertificateViewController];
                [NSApp stopModal];
            }
            else {
                NSLog(@"Info: Subkey not encrypted.");
            }
        }
        else {
            NSAlert *alert = [NSAlert alertWithMessageText:@"Couldn't unlock identity" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Incorrect password. Try a different password."];
            [alert runModal];
        }
    }
    else if( state == kPasswordWindowStateImportIdentity ) {
        if ([[m_passwordField stringValue]isEqualToString:[m_repeatPasswordField stringValue]]) {
            if([app encryptIdentityWithPassword:[m_passwordField stringValue]]) {
                NSLog(@"PasswordWindowController: Successfully imported certificate.");
            }
            else {
                NSAlert *alert = [NSAlert alertWithMessageText:@"Error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Did not import identity"];
                [alert runModal];
            }
            [NSApp stopModal];
        }
        else {
            NSAlert *alert = [NSAlert alertWithMessageText:@"Can't import identity" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Passwords don't match"];
            [alert runModal];
        }
    }
}

-(void)presentPasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent {
    NSWindow *window = [self window];
    m_privateKey = privateKey;
    state = kPasswordWindowStateUnlockIdentity;
    
    [m_promptField setStringValue:prompt];
    [m_repeatPasswordField setHidden:YES];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:nil contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

-(void)presentChangePasswordPrompt:(NSString *)prompt privateKey:(OpenPGPPublicKey *)privateKey window:(NSWindow *)parent {
    NSWindow *window = [self window];
    state = kPasswordWindowStateImportIdentity;
    
    [m_promptField setStringValue:prompt];
    [m_repeatPasswordField setHidden:NO];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:nil contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

- (void)windowDidLoad {
    [super windowDidLoad];
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
}

@end
