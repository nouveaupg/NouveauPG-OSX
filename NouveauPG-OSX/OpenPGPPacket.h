//
//  OpenPGPPacket.h
//  Test
//
//  Created by John Hill on 8/23/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OpenPGPMessage.h"

@interface OpenPGPPacket : NSObject {
    NSData *m_packetData;
    NSInteger m_packetTag;
}

- (id)initWithData:(NSData *)packetData;
- (id)initWithPacketBody:(NSData *)bodyData tag: (NSInteger)packetTag oldFormat: (bool)oldPacketFormat;
- (NSUInteger) length;
- (NSInteger) packetTag;
- (NSData *) packetData;

+ (NSArray *) packetsFromMessage: (OpenPGPMessage *)pgpMessage;

@property bool newPacketFormat;

@end
