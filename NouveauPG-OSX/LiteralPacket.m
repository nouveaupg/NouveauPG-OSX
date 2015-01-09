//
//  LiteralPacket.m
//  UITest
//
//  Created by John Hill on 11/11/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import "LiteralPacket.h"

@implementation LiteralPacket

@synthesize timestamp;
@synthesize filename;
@synthesize content;

-(id)initWithData:(NSData *)packetData {
    if (self = [super initWithData:packetData]) {
        unsigned char *ptr = (unsigned char *) [packetData bytes];
        int buffer = 2;
        int offset = 0;
        if (*(ptr+1) < 192) {
            buffer = 2;
        }
        else if( *(ptr + 1) < 224 ) {
            buffer = 3;
        }
        else if( *(ptr+1) == 0xff ) {
            buffer = 6;
        }
        else {
            NSLog(@"Partial length encoding not supported.");
            buffer = -1;
        }
        if ([self packetTag] == 11) {
            if (*(ptr + buffer) == 't') {
                NSLog(@"Text literal packet found.");
            }
            else if( *(ptr + buffer) == 'u' ) {
                NSLog(@"Unicode literal packet found.");
            }
            else if( *(ptr + buffer) == 'b' ) {
                NSLog(@"Binary literal packet found.");
            }
            else {
                NSLog(@"Could not decode literal packet.");
                return nil;
            }
            offset = 1;
            int filenameLen = *(ptr+buffer+offset);
            offset++;
            filename = [NSString stringWithCString:(ptr + buffer +offset) length:filenameLen];
            offset += filenameLen;
            unsigned int rawTimestamp = *(ptr + buffer + offset) << 24;
            offset++;
            rawTimestamp |= (*(ptr+buffer+offset) & 0xff) << 16;
            offset++;
            rawTimestamp |= (*(ptr+buffer+offset) & 0xff) << 8;
            offset++;
            rawTimestamp |= *(ptr+buffer+offset) & 0xff;
            offset++;
            timestamp = rawTimestamp;
            content = [[NSData alloc]initWithBytes:(ptr + buffer + offset) length:[packetData length] - (offset + buffer)];
            
        }
    }
    return self;
}

-(id)initWithUTF8String:(NSString *)string {
    if (self = [super init]) {
        NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
        
        NSUInteger packetLength = [stringData length];
        NSUInteger headerLength;
        packetLength += 14;
        if (packetLength < 192) {
            headerLength = 2;
        }
        else if (packetLength > 191 && packetLength < 8383) {
            headerLength = 3;
        }
        else {
            headerLength = 6;
        }
        m_packetTag = 11;
        unsigned char *ptr = malloc(headerLength + packetLength);
        if(ptr) {
            *ptr = 0xc0 | m_packetTag;
            if (headerLength == 2) {
                *(ptr+1) = packetLength;
            }
            else if( headerLength == 3 ) {
                unsigned long len = packetLength - 192;
                *(ptr+1) = (len >> 8) + 192;
                *(ptr+2) = len & 0xff;
            }
            else {
                *(ptr+1) = 0xff;
                *(ptr+2) = packetLength >> 24;
                *(ptr+3) = (packetLength >> 16) & 0xff;
                *(ptr+4) = (packetLength >> 8) & 0xff;
                *(ptr+5) = packetLength & 0xff;
            }
            *(ptr+headerLength) = 0x62;
            *(ptr+headerLength + 1) = 8;
            memcpy((ptr + headerLength + 2), "_CONSOLE", 8);
            NSUInteger timestamp = (NSUInteger)[[NSDate date] timeIntervalSince1970];
            *(ptr+headerLength + 10) = timestamp >> 24;
            *(ptr+headerLength + 11) = timestamp >> 16 & 0xff;
            *(ptr+headerLength + 11) = timestamp >> 8 & 0xff;
            *(ptr+headerLength + 13) = timestamp & 0xff;
            memcpy((ptr+headerLength + 14), [stringData bytes], [stringData length]);
            
            m_packetData = [[NSData alloc]initWithBytes:ptr length:headerLength + packetLength];
            free(ptr);
        }
        else {
            return nil;
        }
    }
    return self;
}

@end
