//
//  Message.h
//  NouveauPG
//
//  Created by John Hill on 7/11/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>


@interface Message : NSManagedObject

@property (nonatomic, retain) NSString * body;
@property (nonatomic, retain) NSDate * created;
@property (nonatomic, retain) NSDate * edited;
@property (nonatomic, retain) NSString * descriptor;

@property (nonatomic, retain) NSString *keyId;

@end
