//
//  OpenPGPPacket.m
//  Test
//
//  Created by John Hill on 8/23/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import "OpenPGPPacket.h"

@implementation OpenPGPPacket

@synthesize newPacketFormat;

- (NSData *)packetData {
    return m_packetData;
}

- (NSInteger) packetTag {
    return m_packetTag;
}

- (id)initWithPacketBody:(NSData *)bodyData tag: (NSInteger)packetTag oldFormat: (bool)oldPacketFormat {
    if( self = [super init] ) {
        m_packetTag = packetTag;
        
        NSUInteger packetLen = [bodyData length];
        NSUInteger newPacketLen = 0;
        unsigned char packetHeader = 0x80;
        unsigned char *ptr;
        if (oldPacketFormat) {
            if (packetLen < 256) {
                newPacketLen = packetLen + 2;
                packetHeader |= packetTag << 2;
            }
            else if( packetLen < 65536 ) {
                newPacketLen = packetLen + 3;
                packetHeader |= packetTag << 2;
                packetHeader |= 0x1;
            }
            else {
                newPacketLen = packetLen + 4;
                packetHeader |= packetTag << 2;
                packetHeader |= 0x2;
            }
            ptr = malloc(newPacketLen);
            if (ptr) {
                *ptr = packetHeader;
                if (newPacketLen < 256) {
                    *(ptr+1) = packetLen;
                    memcpy((ptr+2), [bodyData bytes], packetLen);
                }
                else if(newPacketLen < 65536 ) {
                    *(ptr+1) = packetLen >> 8;
                    *(ptr+2) = packetLen & 0xff;
                    memcpy((ptr+3), [bodyData bytes], packetLen);
                }
                else {
                    *(ptr+1) = packetLen >> 24;
                    *(ptr+2) = (packetLen >> 16) & 0xff;
                    *(ptr+3) = (packetLen >> 8) & 0xff;
                    *(ptr+4) = packetLen & 0xff;
                    memcpy((ptr+5), [bodyData bytes], packetLen);
                }
                m_packetData = [[NSData alloc]initWithBytes:ptr length:newPacketLen];
                memset(ptr, 0, newPacketLen);
                free(ptr);
            }
        }
        else {
            packetHeader = 0xC0 | packetTag;
            if (packetLen < 192) {
                newPacketLen = packetLen + 2;
            }
            else if( packetLen < 8384 ) {
                newPacketLen = packetLen + 3;
            }
            else {
                newPacketLen = packetLen + 6;
            }
            ptr = malloc(newPacketLen);
            if (ptr) {
                *ptr = packetHeader;
                if (packetLen < 192) {
                    *(ptr + 1) = packetLen;
                    memcpy((ptr+2),[bodyData bytes],packetLen);
                }
                else if( packetLen < 8384 ) {
                    unsigned long len = packetLen - 192;
                    *(ptr + 1) = (len >> 8) + 192;
                    *(ptr + 2) = len & 0xff;
                    memcpy((ptr+3),[bodyData bytes],packetLen);
                }
                else {
                    *(ptr+1) = 0xff;
                    *(ptr+2) = packetLen >> 24;
                    *(ptr+3) = (packetLen >> 16) & 0xff;
                    *(ptr+4) = (packetLen >> 8) & 0xff;
                    *(ptr+5) = packetLen & 0xff;
                    memcpy((ptr+6), [bodyData bytes], packetLen);
                }
                m_packetData = [[NSData alloc]initWithBytes:ptr length:newPacketLen];
                memset(ptr, 0, newPacketLen);
                free(ptr);
            }
        }
        
        return self;
    }
    return nil;
}

+ (NSArray *) packetsFromMessage: (OpenPGPMessage *)pgpMessage {
    if (!pgpMessage) {
        return [NSArray array];
    }
    NSData *messageData = [pgpMessage data];
    OpenPGPPacket *newPacket = [[OpenPGPPacket alloc]initWithData:messageData];
    NSMutableArray *allPackets = [[NSMutableArray alloc] initWithObjects:newPacket, nil];
    unsigned char *ptr = (unsigned char *)[messageData bytes];
    NSUInteger messageLength = [messageData length];
    NSUInteger offset = 0;
    while(newPacket) {
        offset += [newPacket length];
#ifdef DEBUG_PACKET
        NSLog(@"%.02f%% of %lu bytes processed.",(double)offset/(double)[messageData length] * 100.f,[messageData length]);
#endif
        if( offset < [messageData length] ) {
            newPacket = [[OpenPGPPacket alloc]initWithData:[NSData dataWithBytes:(ptr+offset) length:messageLength - offset]];
            if (newPacket) {
                [allPackets addObject:newPacket];
            }
        }
        else {
            break;
        }
    }
    return allPackets;
}

- (NSUInteger) length {
    return [m_packetData length];
}

- (id)initWithData:(NSData *)packetData {
    if (self = [super init]) {
        unsigned int packet_length = 0;
        
        unsigned char *ptr = (unsigned char *)[packetData bytes];
        if ((*ptr >> 7) & 0x1) {
            if ((*ptr >> 6) & 0x1) {
                newPacketFormat = true;
                
                m_packetTag = *ptr & 63;
                
                if (*(ptr+1) == 0xff) {
                    packet_length = (*(ptr+2) << 24) | (*(ptr+3) << 16) | (*(ptr+4) << 8) | *(ptr+5) + 6;
                }
                else if (*(ptr+1) < 192) {
                    packet_length = *(ptr+1) + 2;
                }
                else if (*(ptr+1) <= 223 ) {
                    packet_length = ((*(ptr+1) - 192) << 8) + ( *(ptr+2)) + 192 + 3;
                }
                else {
#ifdef DEBUG_PACKET
                    NSLog(@"Partial packet header length encoding.");
#endif
                    // partial encoding
                    unsigned int offset = 2;
                    unsigned int partialBodyLen = 1 << (*(ptr+1) & 0x1F);
                    
                    NSMutableData *accumulator = [[NSMutableData alloc]init];
                    [accumulator appendBytes:(ptr+offset) length:partialBodyLen];
                    offset += partialBodyLen;
                    unsigned char *nextChunkHeader = (unsigned char *)(ptr + offset);
                    
                    
                    while (*nextChunkHeader > 223) {
                        partialBodyLen = 1 << (*nextChunkHeader & 0x1F);
                        offset++;
                        [accumulator appendBytes:(ptr+offset) length:partialBodyLen];
                        offset += partialBodyLen;
                        
                        nextChunkHeader = (ptr+offset);
                    }
                    if (*nextChunkHeader <= 223) {
                        if( *nextChunkHeader <= 192 ) {
                            partialBodyLen = *nextChunkHeader;
                            [accumulator appendBytes:(nextChunkHeader + 1) length:partialBodyLen];
                        }
                        else {
                            partialBodyLen = ((*nextChunkHeader - 192) << 8) + *(nextChunkHeader+1) + 192;
                            [accumulator appendBytes:(nextChunkHeader + 2) length:partialBodyLen];
                        }
                        return [[OpenPGPPacket alloc]initWithPacketBody:accumulator tag:18 oldFormat:false];
                    }
                    
                    return nil;
                }
                m_packetData = [[NSData alloc]initWithBytes:ptr length:packet_length];
#ifdef DEBUG_PACKET
                NSLog(@"Found new format packet with tag %ld and %d bytes.",m_packetTag,packet_length);
#endif
            }
            else {
                newPacketFormat = false;
                
                m_packetTag = (*ptr & 0x3F) >> 2;
                
                if ((*ptr & 0x3) == 0) {
                    packet_length = *(ptr+1);
                    packet_length += 2;
                }
                else if( (*ptr & 0x3) == 1 ) {
                    packet_length = (*(ptr+1) << 8) | (*(ptr+2));
                    packet_length += 3;
                }
                else if( (*ptr & 0x3) == 2 ) {
                    packet_length = (*(ptr+1) << 24) | (*(ptr+2) << 16) | (*(ptr+3) << 8) | *(ptr+4);
                    packet_length += 5;
                }
                else {
                    NSLog(@"Unsupported packet type: new format, indeterminate length.");
                    return nil;
                }
                m_packetData = [[NSData alloc]initWithBytes:ptr length:packet_length];
#ifdef DEBUG_PACKET
                NSLog(@"Found old format packet with tag %ld and %d bytes.",m_packetTag,packet_length);
#endif
            }
#ifdef DEBUG_PACKET
            NSLog(@"Overall packet length: %lu", [m_packetData length]);
#endif
        }
        else {
            // not a valid packet if it doesn't start with a 1 bit
            return nil;
        }
    }
    return self;
}

@end
