//
//  NewIdentityPanel.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/31/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "NewIdentityPanel.h"

@interface NewIdentityPanel ()

@end

@implementation NewIdentityPanel

-(void)presentNewIdentityPanel: (NSWindow *)parent {
    NSWindow *window = [self window];
    
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
