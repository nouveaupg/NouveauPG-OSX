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
#import "Identities.h"
#import "AppDelegate.h"
#import "OpenPGPEncryptedPacket.h"

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
                NSAlert *alert = [NSAlert alertWithMessageText:@"Error opening file" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Could not open file selected. NouveauPG only supports plain text files."];
                [alert runModal];
            }
            
        }
    }
}

-(IBAction)centerButton:(id)sender {
    
}

-(OpenPGPPublicKey *)validateOpenPGPMessage {
    
    OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:[m_textView string]];
    if ([message validChecksum]) {
        for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:message]) {
            if ([eachPacket packetTag] == 1) {
                unsigned char *ptr = (unsigned char *)[[eachPacket packetData] bytes];
                NSUInteger packetLen = [[eachPacket packetData] length];
                if (packetLen > 13) {
                    if (ptr[3] != 3) {
                        NSLog(@"Wrong version for Public-Key Encrypted Session Packet. Expected 3, actual %d",ptr[3]);
                        return nil;
                    }
                    if (ptr[12] != 1) {
                        NSLog(@"Unsupported public key type.");
                        return nil;
                    }
                    NSString *keyId = [NSString stringWithFormat:@"%02x%02x%02x%02x",ptr[8],ptr[9],ptr[10],ptr[11]];
                    AppDelegate *app = [[NSApplication sharedApplication]delegate];
                    
                    OpenPGPPublicKey *found = nil;
                    for (Identities *each in app.identities) {
                        if ([keyId isEqualToString:each.keyId]) {
                            NSLog(@"Primary key found: %@",keyId);
                            found = each.primaryKey;
                            break;
                        }
                        else if([keyId isEqualToString:each.secondaryKey.keyId]) {
                            NSLog(@"Subkey found: %@", keyId);
                            found = each.secondaryKey;
                            break;
                        }
                    }
                    if (!found) {
                        NSLog(@"Key ID: %@ not found in keychain",keyId);
                    }
                    return found;
                }
            }
        }
    }
    else {
        NSLog(@"No valid OpenPGP message found.");
    }
    
    return nil;
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
        OpenPGPPublicKey *encryptionKey = [self validateOpenPGPMessage];
        
        bool isEncrypted = [encryptionKey isEncrypted];
        if (isEncrypted) {
            bool result = [encryptionKey decryptKey:@""];
            if (result) {
                unsigned char *sessionKey = NULL;
                OpenPGPMessage *encryptedMessage = [[OpenPGPMessage alloc]initWithArmouredText:[m_textView string]];
                NSMutableArray *encryptedPackets = [[NSMutableArray alloc]initWithCapacity:1];
                if ([encryptedMessage validChecksum]) {
                    for (OpenPGPPacket *each in [OpenPGPPacket packetsFromMessage:encryptedMessage]) {
                        if ([each packetTag] == 1) {
                            unsigned char *ptr = (unsigned char *)[[each packetData] bytes];
                            
                            if ([[each packetData] length] >= 271) {
                                unsigned int declaredBits = (*(ptr + 13) << 8) | (*(ptr + 14) & 0xff);
                                sessionKey = [encryptionKey decryptBytes:(ptr+15) length:(declaredBits + 7)/8];
                            }
                            
                        }
                        else if( [each packetTag] == 18 ) {
                            OpenPGPEncryptedPacket *newPacket = [[OpenPGPEncryptedPacket alloc]initWithData:[each packetData]];
                            [encryptedPackets addObject:newPacket];
                        }
                    }
                    if (sessionKey) {
                        // decrypt the message with the session key.
                        
                        NSMutableData *outputData = [[NSMutableData alloc] init];
                        for( OpenPGPEncryptedPacket *each in encryptedPackets ) {
                            OpenPGPPacket *resultantPacket = [each decryptWithSessionKey:sessionKey algo:7];
                            LiteralPacket *newLiteral = [[LiteralPacket alloc]initWithData:[resultantPacket packetData]];
                            [outputData appendData:[newLiteral content]];
                        }
                        
                        if ([outputData length] > 0) {
                            NSString *stringData = [[NSString alloc]initWithData:outputData encoding:NSUTF8StringEncoding];
                            if (stringData) {
                                [m_textView setString:stringData];
                                
                                [m_textView selectAll:self];
                                [m_prompt setStringValue:@"Decrypted message"];
                                [m_rightButton setTitle:@"Copy"];
                                [m_leftButton setTitle:@"Save as file..."];
                                
                                _state = kComposePanelStateReadMessage;
                            }
                        }

                    }
                }
                else {
                    NSLog(@"No valid OpenPGP message found.");
                }
            }
            else {
                
                NSAlert *alert = [NSAlert alertWithMessageText:@"Could not decrypt message" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The identity must be unlocked before you can decrypt with it."];
                [alert runModal];
                [NSApp stopModal];
            }
            /*
            PasswordWindow *passwdWindow = [[PasswordWindow alloc]initWithWindowNibName:@"PasswordWindow"];
            [passwdWindow presentPasswordPrompt:@"Enter password for private key" privateKey:m_publicKey window:self.window];
             */
        }
        else {
            NSLog(@"Key not encrypted.");
            
            unsigned char *sessionKey = NULL;
            OpenPGPMessage *encryptedMessage = [[OpenPGPMessage alloc]initWithArmouredText:[m_textView string]];
            NSMutableArray *encryptedPackets = [[NSMutableArray alloc]initWithCapacity:1];
            if ([encryptedMessage validChecksum]) {
                for (OpenPGPPacket *each in [OpenPGPPacket packetsFromMessage:encryptedMessage]) {
                    if ([each packetTag] == 1) {
                        unsigned char *ptr = (unsigned char *)[[each packetData] bytes];
                        
                        if ([[each packetData] length] >= 271) {
                            unsigned int declaredBits = (*(ptr + 13) << 8) | (*(ptr + 14) & 0xff);
                            // decrypt the session key
                            sessionKey = [encryptionKey decryptBytes:(ptr+15) length:(declaredBits + 7)/8];
                        }
                    }
                    else if( [each packetTag] == 18 ) {
                        // collect all encrypted packets to be decrypted with the session key
                        
                        OpenPGPEncryptedPacket *newPacket = [[OpenPGPEncryptedPacket alloc]initWithData:[each packetData]];
                        [encryptedPackets addObject:newPacket];
                    }
                }
                if (sessionKey) {
                    // decrypt the message with the session key.
                    NSMutableData *outputData = [[NSMutableData alloc] init];
                    for( OpenPGPEncryptedPacket *each in encryptedPackets ) {
                        OpenPGPPacket *resultantPacket = [each decryptWithSessionKey:sessionKey algo:7];
                        LiteralPacket *newLiteral = [[LiteralPacket alloc]initWithData:[resultantPacket packetData]];
                        [outputData appendData:[newLiteral content]];
                    }
                    
                    if ([outputData length] > 0) {
                        NSString *stringData = [[NSString alloc]initWithData:outputData encoding:NSUTF8StringEncoding];
                        if (stringData) {
                            [m_textView setString:stringData];
                            
                            [m_textView selectAll:self];
                            [m_prompt setStringValue:@"Decrypted message"];
                            [m_rightButton setTitle:@"Copy"];
                            [m_leftButton setTitle:@"Save as file..."];
                            
                            _state = kComposePanelStateReadMessage;
                        }
                    }
                }
            }
            else {
                NSLog(@"No valid OpenPGP message found.");
            }
        }
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
