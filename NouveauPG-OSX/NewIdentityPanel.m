//
//  NewIdentityPanel.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/31/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "NewIdentityPanel.h"
#import "UserIDPacket.h"
#import "OpenPGPSignature.h"
#import "NSString+Base64.h"
#import "Identities.h"
#import "AppDelegate.h"

@interface NewIdentityPanel () {
    IBOutlet NSTextField *m_usernameField;
    IBOutlet NSTextField *m_emailField;
    IBOutlet NSSecureTextField *m_passwordField;
    IBOutlet NSSecureTextField *m_passwordRepeatField;
    IBOutlet NSProgressIndicator *m_passwordStrengthIndicator;
    IBOutlet NSButton *m_rightButton;
    IBOutlet NSButton *m_leftButton;
    
    NSInteger m_keyBits;
}

-(IBAction)dismissPanel:(id)sender;
-(IBAction)generateIdentity:(id)sender;
-(IBAction)changeKeySize:(id)sender;

@end

@implementation NewIdentityPanel

-(IBAction)generateIdentity:(id)sender {
    
    NSString *password;
    if ([[m_passwordField stringValue] isEqualToString:[m_passwordRepeatField stringValue]]) {
        password = [NSString stringWithString:[m_passwordField stringValue]];
    }
    else {
        NSAlert *alert = [NSAlert alertWithMessageText:@"Passwords don't match." defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@""];
        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
        return;
    }
    
    // validate input

    int keyBits = 2048;
    if (m_keyBits == 4096) {
        keyBits = 4096;
    }
    
    // formulate RFC 822 User ID if there is an e-mail address provided or else the name is the full user id
    NSString *username = [m_usernameField stringValue];
    NSString *email = [m_emailField stringValue];
    
    NSString *userId;
    if (email && [email length] > 0) {
        userId = [NSString stringWithFormat:@"%@ <%@>",username,email];
    }
    else {
        userId = [NSString stringWithString:username];
    }
    
    AppDelegate *appDelegate = [[NSApplication sharedApplication] delegate];
    bool success = [appDelegate generateNewIdentity:userId keySize:keyBits password:password];
    [NSApp stopModal];
    
    if (!success) {
        NSAlert *alert = [NSAlert alertWithMessageText:@"Could not create identity" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"An error occurred while attempting to create a new identity."];
        [alert runModal];
    }
    
}

-(void)controlTextDidChange:(NSNotification *)notification {
    NSString *passwordValue = [m_passwordField stringValue];
    
    int diversity = 26;
    
    NSCharacterSet *uppercase = [NSCharacterSet uppercaseLetterCharacterSet];
    NSCharacterSet *digits = [NSCharacterSet decimalDigitCharacterSet];
    NSCharacterSet *symbols = [NSCharacterSet symbolCharacterSet];
    NSCharacterSet *punc = [NSCharacterSet punctuationCharacterSet];
    
    bool uppercaseFound = false;
    bool digitsFound = false;
    bool symbolsFound = false;
    bool puncFound = false;
    
    for (int x = 0; x < [passwordValue length]; x++) {
        unichar c = [passwordValue characterAtIndex:x];
        if ([uppercase characterIsMember:c]) {
            uppercaseFound = true;
        }
        if ([digits characterIsMember:c]) {
            digitsFound = true;
        }
        if ([symbols characterIsMember:c]) {
            symbolsFound = true;
        }
        if ([punc characterIsMember:c]) {
            puncFound = true;
        }
    }
    
    if (uppercaseFound) {
        diversity += 26;
    }
    if (digitsFound) {
        diversity += 10;
    }
    if (symbolsFound) {
        diversity += 14;
    }
    if (puncFound) {
        diversity += 26;
    }

    BIGNUM *base = BN_new();
    BN_set_word(base, diversity);
    BIGNUM *count = BN_new();
    BN_set_word(count, [passwordValue length]);
    BIGNUM *result = BN_new();
    BN_CTX *temp = BN_CTX_new();
    BN_exp(result, base, count, temp);
    BN_CTX_free(temp);
    BN_free(count);
    BN_free(base);

    double entropy = BN_num_bits(result);
    BN_free(result);

    [m_passwordStrengthIndicator setDoubleValue:entropy/128];
    
    if ([[m_passwordRepeatField stringValue] isEqualToString:passwordValue]) {
        [m_rightButton setKeyEquivalent:@"\r"];
    }
    else {
        [m_rightButton setKeyEquivalent:@""];
    }
}

-(IBAction)dismissPanel:(id)sender {
    [NSApp stopModal];
}

-(void)presentNewIdentityPanel: (NSWindow *)parent {
    NSWindow *window = [self window];
    
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:nil contextInfo:nil];
    [NSApp runModalForWindow:window];
    
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

-(IBAction)changeKeySize:(id)sender {
    NSButtonCell *selectedCell = [sender selectedCell];
    m_keyBits = [selectedCell tag];
}

- (void)windowDidLoad {
    [super windowDidLoad];
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
}

@end
