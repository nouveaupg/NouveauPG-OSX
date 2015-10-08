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

#define kConfirmationStateNone 0
#define kConfirmationStateDeleteItem 1
#define kConfirmationStateCompose 2
#define kConfirmationStateExport 3
#define kConfirmationImportNoSigs 4
#define kConfirmationImportInvalidSigs 5

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    IBOutlet NSOutlineView *m_outlineView;
    IBOutlet NSView *m_placeholderView;
    IBOutlet NSMenuItem *m_cloudSyncMenuItem;
    
    CertificateViewController *m_certificateViewController;
    
    OpenPGPPublicKey *m_pendingEncryptionKey;
    NSString *m_pendingEncryptionRecipient;
    
    NSString *m_pendingExportCertificate;
    NSString *m_pendingExportUserId;
    NSString *m_pendingImportCertificate;
    
    NSArray *m_topLevelNodes;
    NSMutableDictionary *m_children;
    NSManagedObject *m_pendingObject;
    NSString *m_pendingItem;
    NSString *m_rootNode;
    
    NSInteger m_confirmation;
    
    // Incoming keystore objects
    
    OpenPGPPublicKey *m_primaryKey;
    OpenPGPPublicKey *m_secondaryKey;
    NSString *m_userId;
    OpenPGPPacket *m_userIdSigPkt;
    OpenPGPPacket *m_subkeySigPkt;
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

-(OpenPGPPublicKey *)subkeyForPrimaryKeyId:(NSString *)primaryKeyId;
-(Identities *)identityForKeyId:(NSString *)keyId;
-(void)presentPasswordPrompt: (NSString *)identityKeyId;
-(bool)importRecipientFromCertificate:(OpenPGPMessage *)publicKeyCertificate override:(bool)skipValidCheck;
-(bool)importIdentityFromKeystore:(OpenPGPMessage *)keystore;
-(bool)encryptIdentityWithPassword: (NSString *)password;
-(bool)importEncryptedMessage:(OpenPGPMessage *)message;
-(void)composeMessageForPublicKey:(OpenPGPPublicKey *)publicKey UserID:(NSString *)userId;
-(void)presentPublicKeyCertificate:(NSString *)certificate UserID:(NSString *)userId;
-(void)presentPrivateKeyCertificate:(NSString *)keyId;
-(void)presentDecryptSheet:(NSString *)keyId;
-(Recipient *)recipientForKeyId:(NSString *)keyId;
-(bool)generateNewIdentity:(NSString *)userID keySize: (NSInteger)bits password:(NSString *)passwd;
-(bool)saveObjectToCloud: (NSManagedObject *)object;
-(void)startSyncFromCloud;
- (void)deleteCloudObject: (NSString *)keyId recordType:(NSString *)type;
-(void)reloadTimerFired: (id)sender;
-(IBAction)toggleCloudSync:(id)sender;

-(void)selectIdentityWithKeyId: (NSString *)keyId;
-(void)selectRecipientWithKeyId: (NSString *)keyId;

+(OpenPGPPublicKey *)validateEncryptedMessage:(OpenPGPMessage *)encryptedMessage;

-(void)setupCertificateSubview;

@end
