//
//  IdenticonImage.h
//  NouveauPG-OSX
//
//  Created by John Hill on 10/25/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface IdenticonImage : NSImage

-(id)initWithIdenticonCode: (NSInteger)code;
void drawPatch( CGContextRef gtx, CGRect rect, int patch, int turn, bool invert, CGColorRef fillColor, CGColorRef backColor );
- (void)drawIdenticon: (NSInteger)identiconCode;

@end
