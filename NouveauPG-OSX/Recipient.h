//
//  Recipient.h
//  NouveauPG
//
//  Created by John Hill on 5/9/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>
#import "RecipientDetails.h"

@interface Recipient : NSManagedObject

@property (nonatomic, retain) NSString * userId;
@property (nonatomic, retain) NSString * certificate;
@property (nonatomic, retain) NSDate * added;
@property (nonatomic, retain) RecipientDetails *details;

@end
