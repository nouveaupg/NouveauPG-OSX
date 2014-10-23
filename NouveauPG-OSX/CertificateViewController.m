//
//  CertificateViewController.m
//  NouveauPG-OSX
//
//  Created by John Hill on 10/23/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "CertificateViewController.h"

@interface CertificateViewController ()

@end

@implementation CertificateViewController

-(void)setUserId:(NSString *)userId {
    [m_userIdField setStringValue:userId];
}

-(void)setEmail:(NSString *)email {
    [m_emailField setStringValue:email];
}

-(void)setPublicKeyAlgo:(NSString *)publicKeyAlgo {
    if(publicKeyAlgo) {
      [m_publicKeyAlgoField setStringValue:publicKeyAlgo];
    }
}

-(void)setFingerprint: (NSString *)fingerprint {
    [m_fingerprintField setStringValue:fingerprint];
}

-(void)setPrimarySignature: (NSString *)signature {
    [m_primarySignatureField setStringValue:signature];
}
-(void)setSubkeySignature: (NSString *)signature {
    [m_subkeySignatureField setStringValue:signature];
}

- (void)viewDidLoad {
    //[super viewDidLoad];
    // Do view setup here.
}

@end
