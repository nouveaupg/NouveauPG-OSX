//
//  OpenPGPMessage.m
//  Test
//
//  Created by John Hill on 8/23/13.
//  Copyright (c) 2013 __MyCompanyName__. All rights reserved.
//

#import "OpenPGPMessage.h"
#import "OpenPGPPacket.h"
#import "NSString+Base64.h"

@implementation OpenPGPMessage

#define kVersionString @"NouveauPG 1.10 (iOS)"

#define kParsingHeaders 0
#define kParsingContent 1
#define kParsingChecksum 2

-(id)initWithArmouredText:(NSString *)armouredMessage {
    if ( self = [super init] ) {
        
        NSRange header = [armouredMessage rangeOfString:@"-----BEGIN PGP PUBLIC KEY BLOCK-----"];
        NSRange footer;
        NSString *messageBody = nil;
        NSInteger parserState = -1;
        
        m_validChecksum = false;
        m_decodedData = nil;
        
        if (header.location != NSNotFound) {
            footer = [armouredMessage rangeOfString:@"-----END PGP PUBLIC KEY BLOCK-----"];
            if (footer.location != NSNotFound) {
                messageBody = [armouredMessage substringWithRange:NSMakeRange(header.location + header.length, footer.location - (header.location+header.length))];
                m_originalArmouredText = [armouredMessage substringWithRange:NSMakeRange(header.location, (footer.location + footer.length) - header.location)];
            }
        }
        
        if (!messageBody) {
            header = [armouredMessage rangeOfString:@"-----BEGIN PGP MESSAGE-----"];
            if (header.location != NSNotFound) {
                footer = [armouredMessage rangeOfString:@"-----END PGP MESSAGE-----"];
                if (footer.location != NSNotFound) {
                    messageBody = [armouredMessage substringWithRange:NSMakeRange(header.location + header.length, footer.location - (header.location+header.length))];
                    m_originalArmouredText = [armouredMessage substringWithRange:NSMakeRange(header.location, (footer.location + footer.length) - header.location)];
                }
            }
        }
        
        if (!messageBody) {
            header = [armouredMessage rangeOfString:@"-----BEGIN PGP PRIVATE KEY BLOCK-----"];
            if (header.location != NSNotFound) {
                footer = [armouredMessage rangeOfString:@"-----END PGP PRIVATE KEY BLOCK-----"];
                if (footer.location != NSNotFound) {
                    messageBody = [armouredMessage substringWithRange:NSMakeRange(header.location + header.length, footer.location - (header.location+header.length))];
                }
            }
        }
        
        /* 
        
        if (!messageBody) {
            header = [armouredMessage rangeOfString:@"-----BEGIN PGP SIGNATURE-----"];
            if (header.location != NSNotFound) {
                footer = [armouredMessage rangeOfString:@"-----END PGP SIGNATURE-----"];
                if (footer.location != NSNotFound) {
                    messageBody = [armouredMessage substringWithRange:NSMakeRange(header.location + header.length, footer.location - (header.location+header.length))];
                }
            }
        }
         
        */
        
        if (messageBody) {
            NSMutableString *contentAccumulator = [[NSMutableString alloc]initWithCapacity:[messageBody length]];
            NSArray *lines = [messageBody componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\r\n"]];
            for (NSString* line in lines) {
                NSString *trimmedString = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (parserState == -1) {
                    // Look for the headers, the only place there should be any colons
                    //NSRange colonRange = [trimmedString rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@":"]];
                    //if (colonRange.location != NSNotFound) {
                        parserState = kParsingHeaders;
                    //}
                }
                else if (parserState == kParsingHeaders) {
                    // when we find the blank line, we start to expect data
                    if ([trimmedString length] == 0) {
                        parserState = kParsingContent;
                    }
                }
                else if( parserState == kParsingContent ) {
                    // we just append Base64 encoded data to the accumulator and strip out whitespace
                    // the way Base64 is specified, the '=' sign will never be the first character of a line.
                    // when we find a line that begins with '=' we know we've reached the checksum
                    
                    if ([trimmedString length] == 0) {
                    // this takes care of CR/LF pairs
                        continue;
                    }
                    
                    if ([trimmedString characterAtIndex:0] == '=') {
                        m_decodedData = [OpenPGPMessage base64DataFromString:contentAccumulator];
                        if ( m_decodedData ) {
                            parserState = kParsingChecksum;
                            NSString *encodedChecksum = [trimmedString substringWithRange:NSMakeRange(1, [trimmedString length] -1)];
                            NSData *checksumData = [OpenPGPMessage base64DataFromString:encodedChecksum];
                            
                            long checksum = 0x0;
                            unsigned char *ptr = (unsigned char *)[checksumData bytes];
                            checksum |= (*ptr) << 16;
                            checksum |= (*(ptr + 1)) << 8;
                            checksum |= (*(ptr + 2));
                            
                            // RFC 4880
                            
                            long crc = 0xB704CEL;
                            ptr = (unsigned char *)[m_decodedData bytes];
                            for (int i = 0; i < [m_decodedData length]; i++) {
                                crc ^= (*(ptr+i)) << 16;
                                for (int j = 0; j < 8; j++) {
                                    crc <<= 1;
                                    if (crc & 0x1000000) {
                                        crc ^= 0x1864CFBL;
                                    }
                                }
                            }
                            crc &= 0xFFFFFFL;
                            
                            if (checksum == crc) {
                                m_validChecksum = true;
                            }
                            return self;
                        }
                    }
                    else {
                        [contentAccumulator appendString:trimmedString];
                    }
                }
            }
        }
    }
    return nil;
}

-(id)initWithData: (NSData *)packetData {
    if (!packetData) {
        return nil;
    }
    if (self = [super init]) {
        m_decodedData = [packetData copy];
        m_validChecksum = true;
    }
    return self;
}

-(bool)validChecksum {
    return m_validChecksum;
}

-(NSData *)data {
    return m_decodedData;
}

-(NSString *)originalArmouredText {
    return m_originalArmouredText;
}

+ (NSData *)base64DataFromString: (NSString *)string
{
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[3];
    short i, ixinbuf;
    Boolean flignore, flendtext = false;
    const unsigned char *tempcstring;
    NSMutableData *theData;
    
    if (string == nil)
    {
        return [NSData data];
    }
    
    ixtext = 0;
    
    tempcstring = (const unsigned char *)[string UTF8String];
    
    lentext = [string length];
    
    theData = [NSMutableData dataWithCapacity: lentext];
    
    ixinbuf = 0;
    
    while (true)
    {
        if (ixtext >= lentext)
        {
            break;
        }
        
        ch = tempcstring [ixtext++];
        
        flignore = false;
        
        if ((ch >= 'A') && (ch <= 'Z'))
        {
            ch = ch - 'A';
        }
        else if ((ch >= 'a') && (ch <= 'z'))
        {
            ch = ch - 'a' + 26;
        }
        else if ((ch >= '0') && (ch <= '9'))
        {
            ch = ch - '0' + 52;
        }
        else if (ch == '+')
        {
            ch = 62;
        }
        else if (ch == '=')
        {
            flendtext = true;
        }
        else if (ch == '/')
        {
            ch = 63;
        }
        else
        {
            flignore = true; 
        }
        
        if (!flignore)
        {
            short ctcharsinbuf = 3;
            Boolean flbreak = false;
            
            if (flendtext)
            {
                if (ixinbuf == 0)
                {
                    break;
                }
                
                if ((ixinbuf == 1) || (ixinbuf == 2))
                {
                    ctcharsinbuf = 1;
                }
                else
                {
                    ctcharsinbuf = 2;
                }
                
                ixinbuf = 3;
                
                flbreak = true;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4)
            {
                ixinbuf = 0;
                
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                
                for (i = 0; i < ctcharsinbuf; i++)
                {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak)
            {
                break;
            }
        }
    }
    
    return theData;
}

+ (NSString *)privateKeystoreFromPacketChain: (NSArray *)packets {
    NSMutableString *armouredText = [[NSMutableString alloc]initWithUTF8String:"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"];
    [armouredText appendFormat:@"Version: %@\n\n",kVersionString];
    NSMutableData *data = [[NSMutableData alloc]init];
    for (OpenPGPPacket *eachPacket in packets) {
        [data appendData:[eachPacket packetData]];
    }
    [armouredText appendString:[data base64EncodedString]];
    
    unsigned char crcData[3];
    unsigned char *ptr = (unsigned char *)[data bytes];
    long crc = 0xB704CEL;
    for (int i = 0; i < [data length]; i++) {
        crc ^= (*(ptr+i)) << 16;
        for (int j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc ^= 0x1864CFBL;
            }
        }
    }
    crc &= 0xFFFFFFL;
    
    crcData[0] = ( crc >> 16 ) & 0xff;
    crcData[1] = ( crc >> 8 ) & 0xff;
    crcData[2] = crc & 0xff;
    NSData *privateCRC = [NSData dataWithBytes:crcData length:3];
    [armouredText appendFormat:@"\n=%@\n-----END PGP PRIVATE KEY BLOCK-----",[privateCRC base64EncodedString]];
    return armouredText;
}

@end
