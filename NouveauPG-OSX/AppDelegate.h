//
//  AppDelegate.h
//  NouveauPG-OSX
//
//  Created by John Hill on 9/10/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    IBOutlet NSOutlineView *m_outlineView;
    IBOutlet NSView *m_placeholderView;
    
    NSArray *m_topLevelNodes;
}

@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (void)setupNavigation;

- (IBAction)saveAction:(id)sender;
- (IBAction)importFromClipboard:(id)sender;
- (IBAction)addAction:(id)sender;
- (IBAction)removeAction:(id)sender;

@end
