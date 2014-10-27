//
//  IdenticonImage.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/25/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "IdenticonImage.h"

#define PATCH_GRIDS 5

@implementation IdenticonImage

-(id)initWithIdenticonCode: (NSInteger)code {
    self = [super initWithSize:NSMakeSize(90, 90)];
    if (self) {
        [self drawIdenticon:code];
    }
    
    return self;
}

- (void)drawIdenticon: (NSInteger)identiconCode {
    CGFloat cgSize =  self.size.width / 3;
    int cornerType = (identiconCode >> 3) & 15;
    int centerpiece = identiconCode & 3;
    if (centerpiece == 3) {
        centerpiece = 0;
    }
    else if( centerpiece == 1 ) {
        centerpiece = 4;
    }
    else {
        centerpiece = 8;
    }
    int sideType = (identiconCode >> 10) & 15;
    int sideTurn = (identiconCode >> 15) & 3;
    int cornerTurn = (identiconCode >> 3) & 15;
    
    int red = (identiconCode >> 27) & 31;
    int green = (identiconCode >> 21) & 31;
    int blue = (identiconCode >> 16) & 31;
    
    bool middleInvert = ((identiconCode >> 2) & 1) != 0;
    bool cornerInvert = ((identiconCode >> 7) & 1) != 0;
    bool sideInvert = ((identiconCode >> 14) & 1) != 0;
    
    NSColor *fillColor = [NSColor colorWithRed:(red << 3)/256.0 green:(green << 3)/256.0 blue:(blue << 3)/256.0 alpha:1.0f];
    
    NSColor *backColor = [NSColor whiteColor];
    
    [self lockFocus];
    // Drawing code
    CGContextRef context = [[NSGraphicsContext currentContext] graphicsPort];
    
    
    CGLayerRef topLeftPatch = CGLayerCreateWithContext(context, self.size, NULL);
    CGContextRef gtx = CGLayerGetContext(topLeftPatch);
    
    CGRect rect = CGRectMake(0, 0, self.size.width, self.size.height);
    drawPatch(gtx, rect, cornerType, cornerTurn++, cornerInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef topPatch = CGLayerCreateWithContext(context, self.size, NULL);
    gtx = CGLayerGetContext(topPatch);
    drawPatch(gtx, rect, sideType, sideTurn++, sideInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef topRightPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(topRightPatch);
    drawPatch(gtx, rect, cornerType, cornerTurn++, cornerInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef leftPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(leftPatch);
    drawPatch(gtx, rect, sideType, sideTurn++, sideInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef centerPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(centerPatch);
    drawPatch(gtx, rect, centerpiece, 0, middleInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef rightPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(rightPatch);
    drawPatch(gtx, rect, sideType, sideTurn++, sideInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef bottomLeftPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(bottomLeftPatch);
    drawPatch(gtx, rect, cornerType, cornerTurn++, cornerInvert, fillColor.CGColor, backColor.CGColor)
    ;
    
    CGLayerRef bottomPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(bottomPatch);
    drawPatch(gtx, rect, sideType, sideTurn++, sideInvert, fillColor.CGColor, backColor.CGColor);
    
    CGLayerRef bottomRightPatch = CGLayerCreateWithContext(context, rect.size, NULL);
    gtx = CGLayerGetContext(bottomRightPatch);
    drawPatch(gtx, rect, cornerType, cornerTurn++, cornerInvert, fillColor.CGColor, backColor.CGColor);
    
    CGContextDrawLayerInRect(context, CGRectMake(0, 0, cgSize, cgSize), topLeftPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize, 0, cgSize, cgSize), topPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize*2, 0, cgSize, cgSize), topRightPatch);
    CGContextDrawLayerInRect(context, CGRectMake(0, cgSize, cgSize, cgSize), leftPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize, cgSize, cgSize, cgSize), centerPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize*2, cgSize, cgSize, cgSize), rightPatch);
    CGContextDrawLayerInRect(context, CGRectMake(0, cgSize*2, cgSize, cgSize), bottomLeftPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize, cgSize*2, cgSize, cgSize), bottomPatch);
    CGContextDrawLayerInRect(context, CGRectMake(cgSize*2, cgSize*2, cgSize, cgSize), bottomRightPatch);
    
    CGLayerRelease(topLeftPatch);
    CGLayerRelease(topPatch);
    CGLayerRelease(topRightPatch);
    CGLayerRelease(centerPatch);
    CGLayerRelease(rightPatch);
    CGLayerRelease(leftPatch);
    CGLayerRelease(bottomRightPatch);
    CGLayerRelease(bottomLeftPatch);
    CGLayerRelease(bottomPatch);
    
    [self unlockFocus];
}

void drawPatch( CGContextRef gtx, CGRect rect, int patch, int turn, bool invert, CGColorRef fillColor, CGColorRef backColor ) {
    assert(patch>=0);
    assert(turn>=0);
    
    float patchSize = rect.size.width;
    float patchScale = patchSize / 4.0f;
    float patchOffset = patchSize / 2.0f;
    int pathLen = 0;
    
    int patchMod = patch % 15;
    unsigned char patchVertices[7];
    
    if (patchMod == 0) {
        patchVertices[0] = 0;
        patchVertices[1] = 4;
        patchVertices[2] = 24;
        patchVertices[3] = 20;
        pathLen = 4;
    }
    else if( patchMod == 1 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 4;
        patchVertices[2] = 20;
        pathLen = 3;
    }
    else if( patchMod == 2 ) {
        patchVertices[0] = 2;
        patchVertices[1] = 24;
        patchVertices[2] = 20;
        pathLen = 3;
    }
    else if( patchMod == 3 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 2;
        patchVertices[2] = 20;
        patchVertices[3] = 22;
        pathLen = 4;
    }
    else if( patchMod == 4 ) {
        patchVertices[0] = 2;
        patchVertices[1] = 14;
        patchVertices[2] = 22;
        patchVertices[3] = 10;
        pathLen = 4;
    }
    else if( patchMod == 5 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 14;
        patchVertices[2] = 24;
        patchVertices[3] = 22;
        pathLen = 4;
    }
    else if( patchMod == 6 ) {
        patchVertices[0] = 2;
        patchVertices[1] = 24;
        patchVertices[2] = 22;
        patchVertices[3] = 13;
        patchVertices[4] = 11;
        patchVertices[5] = 22;
        patchVertices[6] = 20;
        pathLen = 7;
    }
    else if( patchMod == 7 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 14;
        patchVertices[2] = 22;
        pathLen = 3;
    }
    else if( patchMod == 8 ) {
        patchVertices[0] = 6;
        patchVertices[1] = 8;
        patchVertices[2] = 18;
        patchVertices[3] = 16;
        pathLen = 4;
    }
    else if( patchMod == 9 ) {
        patchVertices[0] = 4;
        patchVertices[1] = 20;
        patchVertices[2] = 10;
        patchVertices[3] = 12;
        patchVertices[4] = 2;
        pathLen = 5;
    }
    else if( patchMod == 10 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 2;
        patchVertices[2] = 12;
        patchVertices[3] = 10;
        pathLen = 4;
    }
    else if( patchMod == 11 ) {
        patchVertices[0] = 10;
        patchVertices[1] = 14;
        patchVertices[2] = 22;
        pathLen = 3;
    }
    else if( patchMod == 12 ) {
        patchVertices[0] = 20;
        patchVertices[1] = 12;
        patchVertices[2] = 24;
        pathLen = 3;
    }
    else if( patchMod == 13 ) {
        patchVertices[0] = 10;
        patchVertices[1] = 2;
        patchVertices[2] = 12;
        pathLen = 3;
    }
    else if( patchMod == 14 ) {
        patchVertices[0] = 0;
        patchVertices[1] = 2;
        patchVertices[2] = 10;
        pathLen = 3;
    }
    
    int turns = turn % 4;
    bool inverted = invert;
    
    if (patchMod == 15) {
        inverted = !invert;
    }
    
    CGContextSetFillColorWithColor(gtx, backColor);
    CGContextFillRect(gtx, rect);
    if (inverted) {
        CGContextSetFillColorWithColor(gtx, fillColor);
        CGContextFillRect(gtx, rect);
    }
    
    CGMutablePathRef path = CGPathCreateMutable();
    CGAffineTransform transform = CGAffineTransformMakeTranslation(rect.origin.x+patchOffset, rect.origin.y+patchOffset);
    float radians = (turns * M_PI) / 2;
    CGAffineTransform rotated = CGAffineTransformRotate(transform, radians);
    
    int v = patchVertices[0];
    float vx = ((v % PATCH_GRIDS) * patchScale) - patchOffset;
    float vy = ((v / PATCH_GRIDS) * patchScale) - patchOffset;
    CGPathMoveToPoint(path, &rotated, vx, vy);
    for (int j = 1; j < pathLen; j++) {
        v = patchVertices[j];
        vx = ((v % PATCH_GRIDS) * patchScale) - patchOffset;
        vy = ((v / PATCH_GRIDS) * patchScale) - patchOffset;
        CGPathAddLineToPoint(path, &rotated, vx, vy);
    }
    CGPathCloseSubpath(path);
    CGContextSetFillColorWithColor(gtx, fillColor);
    if (inverted) {
        CGContextSetFillColorWithColor(gtx, backColor);
    }
    CGContextAddPath(gtx, path);
    CGContextFillPath(gtx);
    CGPathRelease(path);
    
}

@end
