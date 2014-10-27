//
//  Recipient.m
//  NouveauPG-OSX
//
//  Created by John Hill on 9/22/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "Recipient.h"


@implementation Recipient

@dynamic certificate;
@dynamic userId;
@dynamic added;
@dynamic keyId;
@dynamic dateSigned;
@dynamic publicKeyAlgo;
@dynamic name;
@dynamic email;
@dynamic fingerprint;

@synthesize primary;
@synthesize subkey;
@synthesize userIdSig;
@synthesize subkeySig;

@end
