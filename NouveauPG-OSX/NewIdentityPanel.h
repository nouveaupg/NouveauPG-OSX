//
//  NewIdentityPanel.h
//  NouveauPG-OSX
//
//  Created by John Hill on 10/31/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "OpenPGPPublicKey.h"
#import "OpenPGPPacket.h"
#import "OpenPGPMessage.h"

@interface NewIdentityPanel : NSWindowController

-(void)presentNewIdentityPanel: (NSWindow *)parent;

@end
