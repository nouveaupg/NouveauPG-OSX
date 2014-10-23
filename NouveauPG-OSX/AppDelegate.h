//
//  AppDelegate.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/10/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "OpenPGPMessage.h"
#import "CertificateViewController.h"

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    IBOutlet NSOutlineView *m_outlineView;
    IBOutlet NSView *m_placeholderView;
    
    CertificateViewController *m_certificateViewController;
    
    NSArray *m_topLevelNodes;
    NSMutableDictionary *m_children;
}

@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

@property (strong,nonatomic) NSArray *recipients;

- (IBAction)saveAction:(id)sender;
- (IBAction)importFromClipboard:(id)sender;
- (IBAction)addAction:(id)sender;
- (IBAction)removeAction:(id)sender;

-(bool)importRecipientFromCertificate:(OpenPGPMessage *)publicKeyCertificate;

@end
