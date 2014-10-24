//
//  ComposeWindowController.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "ComposeWindowController.h"
#import "LiteralPacket.h"
#import "EncryptedEnvelope.h"

@interface ComposeWindowController ()

@end

@implementation ComposeWindowController

-(IBAction)leftButton:(id)sender {
    
}

-(IBAction)centerButton:(id)sender {
    
}

-(IBAction)rightButton:(id)sender {
    
    if (!encrypted) {
        NSString *inputString = [NSString stringWithString:[m_textView string]];
        LiteralPacket *literal = [[LiteralPacket alloc]initWithUTF8String:inputString];
        EncryptedEnvelope *envelope = [[EncryptedEnvelope alloc]initWithLiteralPacket:literal publicKey:m_publicKey];
        [m_textView setString:[envelope armouredMessage]];
        [m_textView setEditable:NO];
        [m_textView selectAll:self];
        [m_rightButton setTitle:@"Copy"];
        [m_leftButton setHidden:NO];
        
        encrypted = true;
    }
    else {
        [m_textView selectAll:self];
        [m_textView copy:self];
        [NSApp stopModal];
    }
    
}

-(IBAction)dismiss:(id)sender {
    [NSApp stopModal];
}

- (void)presentComposePanel:(NSWindow *)parent withPublicKey: (OpenPGPPublicKey *)publicKey {
    NSWindow *window = [self window];
    
    m_publicKey = publicKey;
    
    //[parent beginCriticalSheet:window completionHandler:^(NSModalResponse returnCode) {
    //    NSLog(@"completionHandler called");
    //}];
    [m_rightButton setKeyEquivalent:@"\r"];
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:@selector(dismiss:) contextInfo:nil];
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
