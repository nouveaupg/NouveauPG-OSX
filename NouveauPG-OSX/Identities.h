//
//  Identities.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/22/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>

#import "OpenPGPPublicKey.h"


@interface Identities : NSManagedObject

@property (nonatomic, retain) NSString * email;
@property (nonatomic, retain) NSString * keyId;
@property (nonatomic, retain) NSString * name;
@property (nonatomic, retain) NSString * privateKeystore;
@property (nonatomic, retain) NSString * publicCertificate;
@property (nonatomic, retain) NSDate * created;
@property (strong, nonatomic) OpenPGPPublicKey *primaryKey;
@property (strong, nonatomic) OpenPGPPublicKey *secondaryKey;
@property (nonatomic, retain) NSString *fingerprint;

@end
