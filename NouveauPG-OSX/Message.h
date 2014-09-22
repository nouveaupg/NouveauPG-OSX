//
//  Message.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/22/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>


@interface Message : NSManagedObject

@property (nonatomic, retain) NSDate * created;
@property (nonatomic, retain) NSDate * modified;
@property (nonatomic, retain) NSDate * read;
@property (nonatomic, retain) NSString * descriptor;
@property (nonatomic, retain) NSString * body;

@end
