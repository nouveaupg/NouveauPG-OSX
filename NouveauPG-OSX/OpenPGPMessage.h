//
//  OpenPGPMessage.h
//  Test
//
//  Created by John Hill on 8/23/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpenPGPMessage : NSObject
{
    NSData *m_decodedData;
    bool m_validChecksum;
    NSString *m_originalArmouredText;
}

-(id)initWithData: (NSData *)packetData;
-(id)initWithArmouredText:(NSString *)armouredMessage;
+ (NSData *)base64DataFromString: (NSString *)string;
+ (NSString *)privateKeystoreFromPacketChain: (NSArray *)packets;
-(bool)validChecksum;
-(NSData *)data;
-(NSString *)originalArmouredText;

@end
