//
//  Recipient.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/22/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>


@interface Recipient : NSManagedObject

@property (nonatomic, retain) NSString * certificate;
@property (nonatomic, retain) NSString * userId;
@property (nonatomic, retain) NSDate * added;
@property (nonatomic, retain) NSString * keyId;
@property (nonatomic, retain) NSDate * dateSigned;
@property (nonatomic, retain) NSString * publicKeyAlgo;
@property (nonatomic, retain) NSString * name;
@property (nonatomic, retain) NSString * email;
@property (nonatomic, retain) NSString * fingerprint;

@end
