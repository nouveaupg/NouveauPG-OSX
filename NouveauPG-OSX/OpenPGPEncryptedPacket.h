//
//  OpenPGPEncryptedPacket.h
//  UITest
//
//  Created by John Hill on 3/18/14.
//  Copyright (c) 2014 __MyCompanyName__. All rights reserved.
//

#import "OpenPGPPacket.h"

@interface OpenPGPEncryptedPacket : OpenPGPPacket

- (OpenPGPPacket *)decryptWithSessionKey: (const unsigned char *)sessionKey algo: (int)algorithm;

@end
