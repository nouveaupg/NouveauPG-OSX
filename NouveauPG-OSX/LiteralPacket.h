//
//  LiteralPacket.h
//  UITest
//
//  Created by John Hill on 11/11/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OpenPGPPacket.h"

@interface LiteralPacket : OpenPGPPacket 

-(id)initWithUTF8String:(NSString *)string;
-(id)initWithData:(NSData *)packetData;

@property NSTimeInterval timestamp;
@property (copy) NSString *filename;
@property (retain) NSData *content;

@end
