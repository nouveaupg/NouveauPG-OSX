//
//  RecipientDetails.h
//  NouveauPG
//
//  Created by John Hill on 5/9/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>

@class Recipient;

@interface RecipientDetails : NSManagedObject

@property (nonatomic, retain) NSString * keyId;
@property (nonatomic, retain) NSString * publicKeyAlgo;
@property (nonatomic, retain) NSString * userName;
@property (nonatomic, retain) NSString * email;
@property (nonatomic, retain) NSDate * dateSigned;
@property (nonatomic, retain) Recipient *parent;

@end
