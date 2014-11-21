//
//  ComposeWindowController.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "ComposeWindowController.h"
#import "PasswordWindow.h"
#import "LiteralPacket.h"
#import "EncryptedEnvelope.h"

@interface ComposeWindowController ()

@end

@implementation ComposeWindowController

-(IBAction)leftButton:(id)sender {
    if(_state == kComposePanelStateEncryptMessage) {
        // save encrypted, 'armoured' message
        
        NSSavePanel *panelSave = [NSSavePanel savePanel];
        [panelSave setPrompt:@"Save"];
        [panelSave setNameFieldStringValue:@"output.asc"];
        
        NSInteger result = [panelSave runModal];
        
        if (result) {
            NSString *outputString = [m_textView string];
            NSError *error;
            [outputString writeToURL:[panelSave URL] atomically:NO encoding:NSUTF8StringEncoding error:&error];
            
            if (error) {
                NSAlert *alert = [NSAlert alertWithMessageText:@"File save error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"%@",[error description]];
                [alert runModal];
            }
            
            [NSApp stopModal];
        }
        
    }
    else if(_state == kComposePanelStateExportCertificate) {
        NSSavePanel *panelSave = [NSSavePanel savePanel];
        [panelSave setPrompt:@"Save"];
        NSString *defaultFilename = [NSString stringWithFormat:@"certificate.asc"];
        [panelSave setNameFieldStringValue:defaultFilename];
        
        NSInteger result = [panelSave runModal];
        
        if (result) {
            NSString *outputString = [m_textView string];
            NSError *error;
            [outputString writeToURL:[panelSave URL] atomically:NO encoding:NSUTF8StringEncoding error:&error];
            
            if (error) {
                NSAlert *alert = [NSAlert alertWithMessageText:@"File save error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"%@",[error description]];
                [alert runModal];
            }
            
            [NSApp stopModal];
        }
    }
    else if(_state == kComposePanelStateExportKeystore) {
        NSSavePanel *panelSave = [NSSavePanel savePanel];
        [panelSave setPrompt:@"Save"];
        NSString *defaultFilename = [NSString stringWithFormat:@"keystore.asc"];
        [panelSave setNameFieldStringValue:defaultFilename];
        
        NSInteger result = [panelSave runModal];
        
        if (result) {
            NSString *outputString = [m_textView string];
            NSError *error;
            [outputString writeToURL:[panelSave URL] atomically:NO encoding:NSUTF8StringEncoding error:&error];
            
            if (error) {
                NSAlert *alert = [NSAlert alertWithMessageText:@"File save error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"%@",[error description]];
                [alert runModal];
            }
            
            [NSApp stopModal];
        }
    }
    else if(_state == kComposePanelStateComposeMessage) {
        NSOpenPanel *panel = [NSOpenPanel openPanel];
        NSInteger result = [panel runModal];
        if (result) {
            NSError *error;
            NSString *inputString = [[NSString alloc]initWithContentsOfURL:[panel URL] encoding:NSUTF8StringEncoding error:&error];
            
            if (!error) {
                LiteralPacket *literal = [[LiteralPacket alloc]initWithUTF8String:inputString];
                EncryptedEnvelope *envelope = [[EncryptedEnvelope alloc]initWithLiteralPacket:literal publicKey:m_publicKey];
                
                [m_textView setString:[envelope armouredMessage]];
                [m_textView setEditable:NO];
                [m_textView selectAll:self];
                [m_rightButton setTitle:@"Copy"];
                [m_leftButton setHidden:NO];
                [m_leftButton setTitle:@"Save as file..."];
                [m_prompt setStringValue:[NSString stringWithFormat:@"Encrypted message for %@",m_userId]];
                
                _state = kComposePanelStateEncryptMessage;
            }
            else {
                NSLog(@"Error opening file.");
            }
            
        }
    }
}

-(IBAction)centerButton:(id)sender {
    
}

-(IBAction)rightButton:(id)sender {
    if (_state == kComposePanelStateComposeMessage) {
        NSString *inputString = [NSString stringWithString:[m_textView string]];
        LiteralPacket *literal = [[LiteralPacket alloc]initWithUTF8String:inputString];
        EncryptedEnvelope *envelope = [[EncryptedEnvelope alloc]initWithLiteralPacket:literal publicKey:m_publicKey];
        
        [m_textView setString:[envelope armouredMessage]];
        [m_textView setEditable:NO];
        [m_textView selectAll:self];
        [m_rightButton setTitle:@"Copy"];
        [m_leftButton setHidden:NO];
        [m_leftButton setTitle:@"Save as file..."];
        [m_prompt setStringValue:[NSString stringWithFormat:@"Encrypted message for %@",m_userId]];
        
        _state = kComposePanelStateEncryptMessage;
    }
    else if( _state == kComposePanelStateDecryptMessage ) {
        PasswordWindow *passwdWindow = [[PasswordWindow alloc]initWithWindowNibName:@"PasswordWindow"];
        [passwdWindow presentPasswordPrompt:@"Enter password for private key" privateKey:m_publicKey window:self.window];
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

-(void)presentPublicKeyCertPanel: (NSWindow *)parent publicKeyCertificate:(NSString *)certText UserId:(NSString *)userId {
    NSWindow *window = [self window];
    
    //[parent beginCriticalSheet:window completionHandler:^(NSModalResponse returnCode) {
    //    NSLog(@"completionHandler called");
    //}];
    m_userId = [[NSString alloc]initWithString:userId];
    [m_prompt setStringValue:[NSString stringWithFormat:@"Public key certificate for %@",userId]];
    [m_rightButton setKeyEquivalent:@"\r"];
    [m_rightButton setTitle:@"Copy"];
    [m_leftButton setTitle:@"Save to file..."];
    [m_leftButton setHidden:NO];
    [m_textView setString:certText];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:@selector(dismiss:) contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

-(void)presentPrivateKeyCertPanel: (NSWindow *)parent certificate:(NSString *)certText UserId:(NSString *)userId {
    NSWindow *window = [self window];
    
    m_userId = [[NSString alloc]initWithString:userId];
    [m_prompt setStringValue:[NSString stringWithFormat:@"Private keystore for %@",userId]];
    [m_textView setString:certText];
    [m_rightButton setKeyEquivalent:@"\r"];
    [m_rightButton setTitle:@"Copy"];
    [m_leftButton setTitle:@"Save as file..."];
    [m_leftButton setHidden:NO];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:@selector(dismiss:) contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

-(void)presentDecryptPanel: (NSWindow *)parent keyId: (NSString *)keyId userId:(NSString *)userId {
    NSWindow *window = [self window];
    
    m_userId = [[NSString alloc]initWithString:userId];
    [m_prompt setStringValue:@"Paste OpenPGP message below"];
    [m_rightButton setKeyEquivalent:@"\r"];
    [m_rightButton setTitle:@"Decrypt"];
    [m_leftButton setTitle:@"Load from file..."];
    [m_leftButton setHidden:NO];
    
    [NSApp beginSheet:window modalForWindow:parent modalDelegate:self didEndSelector:@selector(dismiss:) contextInfo:nil];
    [NSApp runModalForWindow:window];
    // sheet is up here...
    
    [NSApp endSheet:window];
    [window orderOut:self];
}

- (void)presentComposePanel:(NSWindow *)parent withPublicKey: (OpenPGPPublicKey *)publicKey UserId:(NSString *)userId {
    NSWindow *window = [self window];
    
    m_publicKey = publicKey;
    
    //[parent beginCriticalSheet:window completionHandler:^(NSModalResponse returnCode) {
    //    NSLog(@"completionHandler called");
    //}];
    m_userId = [[NSString alloc]initWithString:userId];
    [m_prompt setStringValue:[NSString stringWithFormat:@"Compose secret message for %@",userId]];
    [m_rightButton setKeyEquivalent:@"\r"];
    [m_leftButton setTitle:@"Load from file..."];
    [m_leftButton setHidden:NO];
    
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
