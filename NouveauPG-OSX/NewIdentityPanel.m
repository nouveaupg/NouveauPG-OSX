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

@interface NewIdentityPanel () {
    IBOutlet NSTextField *m_usernameField;
    IBOutlet NSTextField *m_emailField;
    IBOutlet NSSecureTextField *m_passwordField;
    IBOutlet NSSecureTextField *m_passwordRepeatField;
    IBOutlet NSProgressIndicator *m_passwordStrengthIndicator;
    IBOutlet NSButton *m_rightButton;
    IBOutlet NSButton *m_leftButton;
}

-(IBAction)dismissPanel:(id)sender;
-(IBAction)generateIdentity:(id)sender;

@end

@implementation NewIdentityPanel

-(IBAction)generateIdentity:(id)sender {
    
    NSString *password;
    if ([[m_passwordField stringValue] isEqualToString:[m_passwordRepeatField stringValue]]) {
        password = [NSString stringWithString:[m_passwordField stringValue]];
    }
    
    
    // validate input
    
    OpenPGPPublicKey *primaryKey = [[OpenPGPPublicKey alloc]initWithKeyLength:2048 isSubkey:NO];
    OpenPGPPublicKey *subkey = [[OpenPGPPublicKey alloc]initWithKeyLength:2048 isSubkey:YES];
    
    NSString *username = [m_usernameField stringValue];
    NSString *email = [m_emailField stringValue];
    
    NSString *userId;
    if (email && [email length] > 0) {
        userId = [NSString stringWithFormat:@"%@ <%@>",username,email];
    }
    else {
        userId = [NSString stringWithString:username];
    }
    
    UserIDPacket *userIdPkt = [[UserIDPacket alloc]initWithString:userId];
    
    OpenPGPPacket *userIdSig = [OpenPGPSignature signString:userId withKey:primaryKey using:2];
    OpenPGPPacket *subkeySig = [OpenPGPSignature signSubkey:subkey withPrivateKey:primaryKey];
    
    NSMutableArray *packets = [[NSMutableArray alloc]initWithCapacity:5];
    [packets addObject:[primaryKey exportPublicKey]];
    [packets addObject:userIdPkt];
    [packets addObject:[subkey exportPublicKey]];
    [packets addObject:userIdSig];
    [packets addObject:subkeySig];
    
    NSMutableData *publicKeyCertData = [[NSMutableData alloc]initWithCapacity:10000];
    for (OpenPGPPacket *each in packets) {
        [publicKeyCertData appendData:[each packetData]];
    }

    unsigned char *messageData = (unsigned char *)[publicKeyCertData bytes];
    NSUInteger messageSize = [publicKeyCertData length];
    // RFC 4880
    
    long crc = 0xB704CEL;
    for (int i = 0; i < messageSize; i++) {
        crc ^= (*(messageData+i)) << 16;
        for (int j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc ^= 0x1864CFBL;
            }
        }
    }
    crc &= 0xFFFFFFL;
    
    char data[3];
    data[0] = ( crc >> 16 ) & 0xff;
    data[1] = ( crc >> 8 ) & 0xff;
    data[2] = crc & 0xff;
    
    NSData *crcData = [NSData dataWithBytes:data length:3];
    NSMutableString *stringBuilder = [[NSMutableString alloc]initWithFormat:@"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: %@\n\n",kVersionString];
    [stringBuilder appendString:[publicKeyCertData base64EncodedString]];
    [stringBuilder appendFormat:@"\n=%@\n-----END PGP PUBLIC KEY BLOCK-----",[crcData base64EncodedString]];
    
    NSString *publicKeyCertificate = [[NSString alloc]initWithString:stringBuilder];
    
    [packets removeAllObjects];
    
    [packets addObject:[primaryKey exportPrivateKey:password]];
    [packets addObject:userIdPkt];
    [packets addObject:[subkey exportPrivateKey:password]];
    [packets addObject:userIdSig];
    [packets addObject:subkeySig];
    
    NSString *privateKeystore = [OpenPGPMessage privateKeystoreFromPacketChain:packets];
    
    NSLog(@"%@\n\n%@",publicKeyCertificate,privateKeystore);
    
}

-(IBAction)dismissPanel:(id)sender {
    [NSApp stopModal];
}

-(void)presentNewIdentityPanel: (NSWindow *)parent {
    NSWindow *window = [self window];
    
    [m_rightButton setKeyEquivalent:@"\r"];
    
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
