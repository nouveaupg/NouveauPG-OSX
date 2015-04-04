//
//  ActivationWindowController.m
//  NouveauPG
//
//  Created by John Hill on 4/4/15.
//  Copyright (c) 2015 John Hill. All rights reserved.
//

#import "ActivationWindowController.h"

#import "OpenPGPMessage.h"
#import "OpenPGPPacket.h"
#import "OpenPGPPublicKey.h"
#import "OpenPGPSignature.h"

#define kTrialPeriod 86400 * 30 // in seconds

@interface ActivationWindowController ()



-(IBAction)dismiss:(id)sender;

@end

@implementation ActivationWindowController

-(IBAction)activate:(id)sender {
    bool valid = [self validateSignature:[m_signatureField stringValue]];
    if (valid) {
        [NSApp stopModal];
        [[NSUserDefaults standardUserDefaults]setObject:[m_signatureField stringValue] forKey:@"signature"];
    }
    else {
        [m_pasteLabel setHidden:YES];
        [m_invalidSigLabel setHidden:NO];
    }
}

-(IBAction)dismiss:(id)sender {
    [NSApp stopModal];
}

-(IBAction)terminateProgram: (id) sender {
    exit(0);
}

-(bool)validateSignature:(NSString *)signature {
    NSString *uuid = [[NSUserDefaults standardUserDefaults]objectForKey:@"uuid"];
    
    NSError *error = nil;
    NSString *certificateText = [NSString stringWithContentsOfURL:[[NSBundle mainBundle]URLForResource:@"validation_certificate" withExtension:nil] encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        [self presentError:error];
        return FALSE;
    }
    OpenPGPMessage *publicCertificate = [[OpenPGPMessage alloc]initWithArmouredText:certificateText];
    if ([publicCertificate validChecksum]) {
        OpenPGPPublicKey *publicKey = nil;
        for (OpenPGPPacket *each in [OpenPGPPacket packetsFromMessage:publicCertificate]) {
            if ([each packetTag] == 6) {
                publicKey = [[OpenPGPPublicKey alloc]initWithPacket:each];
                break;
            }
        }
        if (publicKey) {
            OpenPGPSignature *sig = nil;
            OpenPGPMessage *signatureMessage = [[OpenPGPMessage alloc]initWithArmouredText:signature];
            if ([signatureMessage validChecksum]) {
                for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:signatureMessage] ) {
                    if ([eachPacket packetTag] == 2) {
                        sig = [[OpenPGPSignature alloc]initWithPacket:eachPacket];
                        break;
                    }
                }
                if (sig) {
                    if([sig validateWithPublicKey:publicKey userId:uuid]) {
                        NSLog(@"Validation succesful!");
                        return true;
                    }
                    else {
                        NSLog(@"Validation error: Signature not valid.");
                        return false;
                    }
                }
                else {
                    NSLog(@"Validation error: Signature not found!" );
                }
            }
            else {
                NSLog(@"Validation error: Invalid signature!");
            }
        }
        else {
            NSLog(@"Validation error: no public key found.");
        }
    }
    else {
        NSLog(@"Validation error: no valid public certificate found.");
    }
    
    return false;
}

-(void)presentActivationWindow: (NSWindow *)parent Uuid:(NSString *)uuid date:(NSDate *)installed {
    NSWindow *window = [self window];
    
    //[parent beginCriticalSheet:window completionHandler:^(NSModalResponse returnCode) {
    //    NSLog(@"completionHandler called");
    //}];
    m_installationUuid = [[NSString alloc]initWithString:uuid];
    m_installedDate = [installed copy];
    
    [m_uuidField setStringValue:m_installationUuid];
    NSString *instructions;
    
    double elapsed = fabs([[NSDate date] timeIntervalSinceDate:installed]);
    
    int seconds = floor(elapsed);
    int days = seconds / 86400;
    
    if (elapsed > kTrialPeriod) {
        instructions = @"Your trial period has elapsed.\nActivate this installation anonymously at\nhttp://nouveaupg.com/activate";
        [m_dismissButton setEnabled:FALSE];
    }
    else {
        instructions = [NSString stringWithFormat:@"%d out of 30 days remaining in trial period.\nActivate this installation anonymously at\nfhttp://nouveaupg.com/activate",days];
        [m_quitButton setHidden:YES];
    }
    [m_instructionsField setStringValue:instructions];
    
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
