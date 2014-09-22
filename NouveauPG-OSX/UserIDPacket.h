//
//  UserIDPacket.h
//  PrivacyForAll
//
//  Created by John Hill on 8/25/13.
//  Copyright (c) 2013 John Hill. All rights reserved.
//

#import "OpenPGPPacket.h"

@interface UserIDPacket : OpenPGPPacket {
    NSString *m_stringData;
}

-(id)initWithPacket: (OpenPGPPacket *)packetData;
-(id)initWithString: (NSString *)stringData;
-(NSString *)stringValue;

@end
