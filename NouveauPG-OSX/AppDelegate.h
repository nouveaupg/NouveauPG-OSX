//
//  AppDelegate.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/10/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "OpenPGPMessage.h"
#import "OpenPGPPublicKey.h"
#import "CertificateViewController.h"
#import "Identities.h"
#import "Recipient.h"

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    IBOutlet NSOutlineView *m_outlineView;
    IBOutlet NSView *m_placeholderView;
    
    CertificateViewController *m_certificateViewController;
    
    NSArray *m_topLevelNodes;
    NSMutableDictionary *m_children;
    NSManagedObject *m_pendingObject;
    NSString *m_pendingItem;
    NSString *m_rootNode;
}

@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

@property (strong,nonatomic) NSArray *recipients;
@property (strong,nonatomic) NSArray *identities;

-(IBAction)saveAction:(id)sender;
-(IBAction)importFromClipboard:(id)sender;
-(IBAction)addAction:(id)sender;
-(IBAction)removeAction:(id)sender;
-(IBAction)lockIdentity:(id)sender;
-(IBAction)newIdentityPanel:(id)sender;
-(IBAction)importFromFile:(id)sender;

-(void)refreshCertificateViewController;

-(Identities *)identityForKeyId:(NSString *)keyId;
-(void)presentPasswordPrompt: (NSString *)identityKeyId;
-(bool)importRecipientFromCertificate:(OpenPGPMessage *)publicKeyCertificate;
-(void)composeMessageForPublicKey:(OpenPGPPublicKey *)publicKey UserID:(NSString *)userId;
-(void)presentPublicKeyCertificate:(NSString *)certificate UserID:(NSString *)userId;
-(void)presentPrivateKeyCertificate:(NSString *)keyId;
-(void)presentDecryptSheet:(NSString *)keyId;
-(Recipient *)recipientForKeyId:(NSString *)keyId;
-(bool)generateNewIdentity:(NSString *)userID keySize: (NSInteger)bits password:(NSString *)passwd;

-(void)setupCertificateSubview;

@end
