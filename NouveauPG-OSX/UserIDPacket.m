//
//  UserIDPacket.m
//  PrivacyForAll
//
//  Created by John Hill on 8/25/13.
//  Copyright (c) 2013 John Hill. All rights reserved.
//

#import "UserIDPacket.h"

@implementation UserIDPacket

-(id)initWithString:(NSString *)stringData {
    if (self = [super init]) {
        m_stringData = [[NSString alloc]initWithString:stringData];
        m_packetTag = 13;
        // TODO: need to prepend header
        m_packetData = [[NSData alloc]initWithBytes:[m_stringData UTF8String] length:[m_stringData length]];
    }
    return self;
}

-(id)initWithPacket: (OpenPGPPacket *)packetData {
    if (self = [super initWithData:[packetData packetData]]) {
        int offset = 0;
        
        if (m_packetTag == 13) {
            unsigned char *ptr = (unsigned char *)[m_packetData bytes];
            NSUInteger len = [m_packetData length];
            if (self.newPacketFormat) {
                if (len <= 194) {
                    offset = 2;
                }
                else if(len <= 8383 ) {
                    offset = 3;
                }
                else {
                    offset = 6;
                }
            }
            else {
                if (len <= 257) {
                    offset = 2;
                }
                else if( len <= 65538 ) {
                    offset = 3;
                }
                else {
                    offset = 5;
                }
            }
            m_stringData = [[NSString alloc]initWithBytes:(ptr+offset) length:(len-offset) encoding:NSUTF8StringEncoding];
            NSLog(@"UserID: %@",m_stringData);
        }
        else {
            NSLog(@"Wrong packet tag, tried to load %ld, only tag 13 is accepted.",m_packetTag);
            return nil;
        }
    }
    return self;
}

-(NSString *)stringValue {
    return m_stringData;
}

@end
