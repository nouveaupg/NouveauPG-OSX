//
//  EncryptedEnvelope.h
//  UITest
//
//  Created by John Hill on 11/11/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "LiteralPacket.h"
#import "OpenPGPPublicKey.h"

@interface EncryptedEnvelope : NSObject {
    NSData *m_envelopeData;
}

- (id) initWithLiteralPacket: (LiteralPacket *)packet publicKey: (OpenPGPPublicKey *)key;
// NOTE: initWithTextMessage is not fully implemented
- (id) initWithTextMessage: (NSString *)message forKey: (OpenPGPPublicKey *)publicKey;
- (NSString *)armouredMessage;

@end
