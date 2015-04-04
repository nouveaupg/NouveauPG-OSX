//
//  ActivationWindowController.h
//  NouveauPG
//
//  Created by John Hill on 4/4/15.
//  Copyright (c) 2015 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ActivationWindowController : NSWindowController {
    NSDate *m_installedDate;
    NSString *m_installationUuid;
    
    IBOutlet NSTextField *m_instructionsField;
    IBOutlet NSTextField *m_uuidField;
    IBOutlet NSTextField *m_signatureField;
    IBOutlet NSButton *m_quitButton;
    IBOutlet NSButton *m_dismissButton;
    IBOutlet NSTextField *m_pasteLabel;
    IBOutlet NSTextField *m_invalidSigLabel;
    
    
}

-(void)presentActivationWindow: (NSWindow *)parent Uuid:(NSString *)uuid date:(NSDate *)installed;
-(IBAction)terminateProgram: (id) sender;
-(IBAction)activate:(id)sender;
-(bool)validateSignature:(NSString *)signature;


@end
