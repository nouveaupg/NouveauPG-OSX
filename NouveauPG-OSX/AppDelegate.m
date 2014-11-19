//
//  AppDelegate.m
//  NouveauPG-OSX
//
//  Created by John Hill on 9/10/14.
//  Copyright (c) 2014 John Hill. All rights reserved.
//

#import "AppDelegate.h"
#import "OpenPGPMessage.h"
#import "OpenPGPPacket.h"
#import "UserIDPacket.h"
#import "OpenPGPPublicKey.h"
#import "OpenPGPSignature.h"
#import "Recipient.h"
#import "ComposeWindowController.h"
#import "NewIdentityPanel.h"
#import "IdenticonImage.h"
#import "Identities.h"
#import "PasswordWindow.h"

@implementation AppDelegate

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize managedObjectModel = _managedObjectModel;
@synthesize managedObjectContext = _managedObjectContext;

@synthesize recipients;
@synthesize identities;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    
    OpenSSL_add_all_algorithms();
    
    m_topLevelNodes = [NSArray arrayWithObjects:@"RECIPIENTS",@"MY IDENTITIES", nil];
    [m_outlineView reloadData];
    [m_outlineView sizeLastColumnToFit];
    [m_outlineView setFloatsGroupRows:NO];
    
    // NSTableViewRowSizeStyleDefault should be used, unless the user has picked an explicit size. In that case, it should be stored out and re-used.
    [m_outlineView setRowSizeStyle:NSTableViewRowSizeStyleDefault];
    
    m_children = [[NSMutableDictionary alloc]initWithCapacity:3];
    
    NSManagedObjectContext *ctx = [self managedObjectContext];
    NSFetchRequest *fetchRequest = [[NSFetchRequest alloc] init];
    NSEntityDescription *entity = [NSEntityDescription entityForName:@"Recipient"
                                              inManagedObjectContext:ctx];
    [fetchRequest setEntity:entity];
    
    NSError *error;
    self.recipients = [ctx executeFetchRequest:fetchRequest error:&error];
    NSLog(@"Loaded %lu recipients (public key certificates) from datastore.",(unsigned long)[self.recipients count]);
    
    for(Recipient *each in recipients) {
        OpenPGPMessage *cert = [[OpenPGPMessage alloc]initWithArmouredText:each.certificate];
        if ([cert validChecksum]) {
            for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:cert]) {
                if ([eachPacket packetTag] == 6) {
                    each.primary = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                }
                else if ([eachPacket packetTag] == 14) {
                    each.subkey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                }
                else if( [eachPacket packetTag] == 2 ) {
                    OpenPGPSignature *sig = [[OpenPGPSignature alloc]initWithPacket:eachPacket];
                    if ([sig signatureType] >= 0x10 && [sig signatureType] <= 0x13) {
                        each.userIdSig = sig;
                    }
                    else if([sig signatureType] == 0x18) {
                        each.subkeySig = sig;
                    }
                }
            }
        }
        else {
            NSLog(@"Invalid Public Key certificate for recipient: %@",each.name);
        }
    }
    
    if (error) {
        NSLog(@"NSError: %@",[error description]);
    }
    
    NSMutableArray *newArray = [[NSMutableArray alloc]init];
    for ( Recipient *eachRecipient in recipients ) {
        [newArray addObject:eachRecipient.keyId];
    }
    [m_children setObject:newArray forKey:@"RECIPIENTS"];
    
    fetchRequest = [[NSFetchRequest alloc] init];
    entity = [NSEntityDescription entityForName:@"Identities"
                                              inManagedObjectContext:ctx];
    [fetchRequest setEntity:entity];
    
    self.identities = [ctx executeFetchRequest:fetchRequest error:&error];
    NSLog(@"Loaded %lu identites from datastore.",(unsigned long)[self.identities count]);
    
    newArray = [[NSMutableArray alloc]init];
    for (Identities *each in identities) {
        [newArray addObject:each.keyId];
    }
    [m_children setObject:newArray forKey:@"MY IDENTITIES"];
}

// -------------------------------------------------------------------------------
//	applicationShouldTerminateAfterLastWindowClosed:sender
//
//	NSApplication delegate method placed here so the sample conveniently quits
//	after we close the window.
// -------------------------------------------------------------------------------
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)sender
{
	return YES;
}

// Returns the directory the application uses to store the Core Data store file. This code uses a directory named "com.nouveaupg.NouveauPG_OSX" in the user's Application Support directory.
- (NSURL *)applicationFilesDirectory
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *appSupportURL = [[fileManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] lastObject];
    return [appSupportURL URLByAppendingPathComponent:@"com.nouveaupg.NouveauPG_OSX"];
}

// Creates if necessary and returns the managed object model for the application.
- (NSManagedObjectModel *)managedObjectModel
{
    if (_managedObjectModel) {
        return _managedObjectModel;
    }
	
    NSURL *modelURL = [[NSBundle mainBundle] URLForResource:@"CoreDataModel" withExtension:@"momd"];
    _managedObjectModel = [[NSManagedObjectModel alloc] initWithContentsOfURL:modelURL];
    return _managedObjectModel;
}

// Returns the persistent store coordinator for the application. This implementation creates and return a coordinator, having added the store for the application to it. (The directory for the store is created, if necessary.)
- (NSPersistentStoreCoordinator *)persistentStoreCoordinator
{
    if (_persistentStoreCoordinator) {
        return _persistentStoreCoordinator;
    }
    
    NSManagedObjectModel *mom = [self managedObjectModel];
    if (!mom) {
        NSLog(@"%@:%@ No model to generate a store from", [self class], NSStringFromSelector(_cmd));
        return nil;
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *applicationFilesDirectory = [self applicationFilesDirectory];
    NSError *error = nil;
    
    NSDictionary *properties = [applicationFilesDirectory resourceValuesForKeys:@[NSURLIsDirectoryKey] error:&error];
    
    if (!properties) {
        BOOL ok = NO;
        if ([error code] == NSFileReadNoSuchFileError) {
            ok = [fileManager createDirectoryAtPath:[applicationFilesDirectory path] withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if (!ok) {
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    } else {
        if (![properties[NSURLIsDirectoryKey] boolValue]) {
            // Customize and localize this error.
            NSString *failureDescription = [NSString stringWithFormat:@"Expected a folder to store application data, found a file (%@).", [applicationFilesDirectory path]];
            
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setValue:failureDescription forKey:NSLocalizedDescriptionKey];
            error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:101 userInfo:dict];
            
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    }
    
    NSURL *url = [applicationFilesDirectory URLByAppendingPathComponent:@"CoreDataModel.storedata"];
    NSPersistentStoreCoordinator *coordinator = [[NSPersistentStoreCoordinator alloc] initWithManagedObjectModel:mom];
    if (![coordinator addPersistentStoreWithType:NSXMLStoreType configuration:nil URL:url options:nil error:&error]) {
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _persistentStoreCoordinator = coordinator;
    
    return _persistentStoreCoordinator;
}

// Returns the managed object context for the application (which is already bound to the persistent store coordinator for the application.) 
- (NSManagedObjectContext *)managedObjectContext
{
    if (_managedObjectContext) {
        return _managedObjectContext;
    }
    
    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:9999 userInfo:dict];
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _managedObjectContext = [[NSManagedObjectContext alloc] init];
    [_managedObjectContext setPersistentStoreCoordinator:coordinator];

    return _managedObjectContext;
}

// Returns the NSUndoManager for the application. In this case, the manager returned is that of the managed object context for the application.
- (NSUndoManager *)windowWillReturnUndoManager:(NSWindow *)window
{
    return [[self managedObjectContext] undoManager];
}

// Performs the save action for the application, which is to send the save: message to the application's managed object context. Any encountered errors are presented to the user.
- (IBAction)saveAction:(id)sender
{
    NSError *error = nil;
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing before saving", [self class], NSStringFromSelector(_cmd));
    }
    
    if (![[self managedObjectContext] save:&error]) {
        [[NSApplication sharedApplication] presentError:error];
    }
}

-(IBAction)newIdentityPanel:(id)sender {
    NewIdentityPanel *windowController = [[NewIdentityPanel alloc]initWithWindowNibName:@"NewIdentityPanel"];
    [windowController presentNewIdentityPanel:self.window];
}

-(IBAction)importFromFile:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    
    // display the panel
    [panel beginWithCompletionHandler:^(NSInteger result) {
        if (result == NSFileHandlingPanelOKButton) {
            
            // grab a reference to what has been selected
            NSURL *theDocument = [[panel URLs]objectAtIndex:0];
            
            // write our file name to a label
            NSString *theString = [NSString stringWithFormat:@"%@", theDocument];
            NSLog(@"%@",theString);
            
        }
    }];
}

-(void)composeMessageForPublicKey:(OpenPGPPublicKey *)publicKey UserID:(NSString *)userId {
    
    ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
    windowController.state = kComposePanelStateComposeMessage;
    [windowController presentComposePanel:self.window withPublicKey:publicKey UserId:userId];
}

-(void)presentPublicKeyCertificate:(NSString *)certificate UserID:(NSString *)userId {
    ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
    windowController.state = kComposePanelStateExportCertificate;
    [windowController presentPublicKeyCertPanel:self.window publicKeyCertificate:certificate UserId:userId];
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender
{
    // Save changes in the application's managed object context before the application terminates.
    
    if (!_managedObjectContext) {
        return NSTerminateNow;
    }
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing to terminate", [self class], NSStringFromSelector(_cmd));
        return NSTerminateCancel;
    }
    
    if (![[self managedObjectContext] hasChanges]) {
        return NSTerminateNow;
    }
    
    NSError *error = nil;
    if (![[self managedObjectContext] save:&error]) {

        // Customize this code block to include application-specific recovery steps.              
        BOOL result = [sender presentError:error];
        if (result) {
            return NSTerminateCancel;
        }

        NSString *question = NSLocalizedString(@"Could not save changes while quitting. Quit anyway?", @"Quit without saves error question message");
        NSString *info = NSLocalizedString(@"Quitting now will lose any changes you have made since the last successful save", @"Quit without saves error question info");
        NSString *quitButton = NSLocalizedString(@"Quit anyway", @"Quit anyway button title");
        NSString *cancelButton = NSLocalizedString(@"Cancel", @"Cancel button title");
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:question];
        [alert setInformativeText:info];
        [alert addButtonWithTitle:quitButton];
        [alert addButtonWithTitle:cancelButton];

        NSInteger answer = [alert runModal];
        
        if (answer == NSAlertAlternateReturn) {
            return NSTerminateCancel;
        }
    }

    return NSTerminateNow;
}

#pragma mark Data source

- (id)outlineView:(NSOutlineView *)outlineView child:(NSInteger)index ofItem:(id)item {
    if (item == nil) {
        return [m_topLevelNodes objectAtIndex:index];
    }
    else if( [item isEqualToString:@"RECIPIENTS"] ) {
        NSString *returnValue =  [[m_children objectForKey:item] objectAtIndex:index];
        return returnValue;
    }
    else if( [item isEqualToString:@"MY IDENTITIES"] ) {
        NSString *returnValue = [[m_children objectForKey:item] objectAtIndex:index];
        return returnValue;
    }
    return @"";
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item {
    if ([item isEqualToString:@"RECIPIENTS"]) {
        if ([recipients count] > 0) {
            return YES;
        }
    }
    else if ([item isEqualToString:@"MY IDENTITIES"]) {
        if ([identities count] > 0) {
            return YES;
        }
    }
    
    return NO;
}

- (NSInteger) outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item {
    if (item == nil) {
        return [m_topLevelNodes count];
    }
    else if([item isEqualToString:@"RECIPIENTS"]) {
        return [[m_children objectForKey:item] count];
    }
    else if ([item isEqualToString:@"MY IDENTITIES"]) {
        return [[m_children objectForKey:item] count];
    }
    return 0;
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isGroupItem:(id)item {
    return NO;
}

- (BOOL)outlineView:(NSOutlineView *)outlineView shouldShowOutlineCellForItem:(id)item {
    // As an example, hide the "outline disclosure button" for FAVORITES. This hides the "Show/Hide" button and disables the tracking area for that row.
    return YES;
}

- (NSView *)outlineView:(NSOutlineView *)outlineView viewForTableColumn:(NSTableColumn *)tableColumn item:(id)item {
    // For the groups, we just return a regular text view.
    if ([m_topLevelNodes containsObject:item]) {
        NSTableCellView *result = [outlineView makeViewWithIdentifier:@"HeaderCell" owner:self];
        // Uppercase the string value, but don't set anything else. NSOutlineView automatically applies attributes as necessary
        NSString *value = [item uppercaseString];
        [result.textField setStringValue:value];
        return result;
    }
    else if( [[m_children objectForKey:@"RECIPIENTS"] containsObject:item] ) {
        NSTableCellView *result = [outlineView makeViewWithIdentifier:@"DataCell" owner:self];
        
        
        NSString *keyId = nil;
        NSString *name = nil;
        for (Recipient *each in recipients) {
            if([each.keyId isEqualToString:item]) {
                keyId = [NSString stringWithString:each.keyId];
                name = [NSString stringWithString:each.name];
                break;
            }
        }
        
        [result.textField setStringValue:name];
        
        if (keyId) {
            NSInteger newIdenticonCode = 0;
            
            for (int i = 0; i < 8; i++) {
                unichar c = [keyId characterAtIndex:i];
                if ((int)c < 58) {
                    newIdenticonCode |=  ((int)c-48);
                }
                else {
                    newIdenticonCode |= ((int)c-55);
                }
                if (i < 7) {
                    newIdenticonCode <<= 4;
                }
            }
            
            IdenticonImage *identicon = [[IdenticonImage alloc]initWithIdenticonCode:newIdenticonCode];
            [result.imageView setImage:identicon];
            
            
        }
        
        
        
        return result;
    }
    else if( [[m_children objectForKey:@"MY IDENTITIES"] containsObject:item] ) {
        NSTableCellView *result = [outlineView makeViewWithIdentifier:@"DataCell" owner:self];
        
        
        NSString *keyId = nil;
        NSString *name = nil;
        for (Identities *each in identities) {
            if([each.keyId isEqualToString:item]) {
                name = [NSString stringWithString:each.name];
                keyId = [NSString stringWithString:each.keyId];
                break;
            }
        }
        
        [result.textField setStringValue:name];
        
        if (keyId) {
            NSInteger newIdenticonCode = 0;
            
            for (int i = 0; i < 8; i++) {
                unichar c = [keyId characterAtIndex:i];
                if ((int)c < 58) {
                    newIdenticonCode |=  ((int)c-48);
                }
                else {
                    newIdenticonCode |= ((int)c-55);
                }
                if (i < 7) {
                    newIdenticonCode <<= 4;
                }
            }
            
            IdenticonImage *identicon = [[IdenticonImage alloc]initWithIdenticonCode:newIdenticonCode];
            [result.imageView setImage:identicon];
            
            
        }
        
        
        
        return result;
    }
    return nil;
}

- (void)outlineViewSelectionDidChange:(NSNotification *)notification
{
    id selectedItem = [m_outlineView itemAtRow:[m_outlineView selectedRow]];
    id parent = [m_outlineView parentForItem:selectedItem];
    
    if ([parent isEqualToString:@"RECIPIENTS"]) {
        
        Recipient *selectedObject = nil;
        
        for (Recipient *each in recipients) {
            if ([[each keyId] isEqualToString:selectedItem]) {
                selectedObject = each;
            }
        }
        
        if (!m_certificateViewController) {
            [self setupCertificateSubview];
        }
        
        if ([selectedObject.subkey publicKeyType] == 1) {
            NSLog(@"Using subkey to encrypt... (KeyID: %@)",selectedObject.subkey.keyId);
            [m_certificateViewController setPublicKey:selectedObject.subkey];
        }
        else {
            NSLog(@"Could not use subkey because it is the wrong algo: %ld",(long)[selectedObject.subkey publicKeyType]);
            
            if ([selectedObject.primary publicKeyType] == 1) {
                NSLog(@"Using primary key to encrypt... (KeyID: %@)",selectedObject.primary.keyId);
                [m_certificateViewController setPublicKey:selectedObject.primary];
            }
            else {
                NSLog(@"Could not use primary key because it is the wrong algo: %ld",(long)[selectedObject.primary publicKeyType]);
                
                NSAlert *alert = [NSAlert alertWithMessageText:@"Public key problem" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"NouveauPG cannot encrypt messages for this key because it does not support this type of public key. NouveauPG only supports RSA encrypt/sign keys."];
                [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
            }
        }
        
        OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:selectedObject.certificate];
        
        OpenPGPSignature *userIdSig;
        OpenPGPSignature *subkeySig;
        OpenPGPPublicKey *primaryKey;
        OpenPGPPublicKey *subkey;
        UserIDPacket *userIdPkt;
        if ([message validChecksum]) {
            NSArray *packets = [OpenPGPPacket packetsFromMessage:message];
            for (OpenPGPPacket *each in packets ) {
                if ([each packetTag] == 6) {
                    primaryKey = [[OpenPGPPublicKey alloc]initWithPacket:each];
                }
                else if ([each packetTag] == 13) {
                    userIdPkt = [[UserIDPacket alloc]initWithPacket:each];
                }
                else if ([each packetTag] == 14) {
                    subkey = [[OpenPGPPublicKey alloc]initWithPacket:each];
                }
                else if([each packetTag] == 2) {
                    OpenPGPSignature *sig = [[OpenPGPSignature alloc]initWithPacket:each];
                    if (sig.signatureType >= 0x10 && sig.signatureType <= 0x13) {
                        userIdSig = sig;
                    }
                    else if (sig.signatureType == 0x18) {
                        subkeySig = sig;
                    }
                }
            }
        }
        
        if ([userIdSig validateWithPublicKey:primaryKey userId:[userIdPkt stringValue]]) {
            [m_certificateViewController setPrimarySignature:@"User ID signature verified."];
        }
        else {
            [m_certificateViewController setPrimarySignature:@"User ID not verified!"];
        }
        
        if (subkeySig) {
            if ([subkeySig validateSubkey:subkey withSigningKey:primaryKey]) {
                [m_certificateViewController setSubkeySignature:@"Subkey signature verified."];
            }
            else {
                [m_certificateViewController setSubkeySignature:@"Subkey not verified!"];
            }
        }
        else {
            [m_certificateViewController setSubkeySignature:nil];
        }
        
        
        [m_certificateViewController setUserId:selectedObject.name];
        [m_certificateViewController setPrivateCertificate:NO];
        [m_certificateViewController setPublicKeyAlgo:selectedObject.publicKeyAlgo];
        [m_certificateViewController setEmail:selectedObject.email];
        [m_certificateViewController setFingerprint:selectedObject.fingerprint];
        [m_certificateViewController setKeyId:selectedObject.keyId];
        m_certificateViewController.certificate = selectedObject.certificate;
        
        NSInteger newIdenticonCode = 0;
        
        NSString *keyId = selectedObject.keyId;
        for (int i = 0; i < 8; i++) {
            unichar c = [keyId characterAtIndex:i];
            if ((int)c < 58) {
                newIdenticonCode |=  ((int)c-48);
            }
            else {
                newIdenticonCode |= ((int)c-55);
            }
            if (i < 7) {
                newIdenticonCode <<= 4;
            }
        }
        [m_certificateViewController setIdenticon:newIdenticonCode];
    }
    else if([parent isEqualToString:@"MY IDENTITIES"]) {
        Identities *selectedObject = nil;
        
        for (Identities *each in identities) {
            if ([[each keyId] isEqualToString:selectedItem]) {
                selectedObject = each;
            }
        }
        
        if (selectedObject) {
            if (!m_certificateViewController) {
                [self setupCertificateSubview];
            }
        }
        
        OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:selectedObject.publicCertificate];
        
        OpenPGPSignature *userIdSig;
        OpenPGPSignature *subkeySig;
        OpenPGPPublicKey *primaryKey;
        OpenPGPPublicKey *subkey;
        UserIDPacket *userIdPkt;
        if ([message validChecksum]) {
            NSArray *packets = [OpenPGPPacket packetsFromMessage:message];
            for (OpenPGPPacket *each in packets ) {
                if ([each packetTag] == 6) {
                    primaryKey = [[OpenPGPPublicKey alloc]initWithPacket:each];
                }
                else if ([each packetTag] == 13) {
                    userIdPkt = [[UserIDPacket alloc]initWithPacket:each];
                }
                else if ([each packetTag] == 14) {
                    subkey = [[OpenPGPPublicKey alloc]initWithPacket:each];
                }
                else if([each packetTag] == 2) {
                    OpenPGPSignature *sig = [[OpenPGPSignature alloc]initWithPacket:each];
                    if (sig.signatureType >= 0x10 && sig.signatureType <= 0x13) {
                        userIdSig = sig;
                    }
                    else if (sig.signatureType == 0x18) {
                        subkeySig = sig;
                    }
                }
            }
        }
        
        NSString *publicKeyAlgo = [NSString stringWithFormat:@"%ld-bit RSA",(long)primaryKey.publicKeySize];
        
        [m_certificateViewController setUserId:selectedObject.name];
        [m_certificateViewController setPrivateCertificate:YES];
        [m_certificateViewController setPublicKeyAlgo:publicKeyAlgo];
        [m_certificateViewController setEmail:selectedObject.email];
        [m_certificateViewController setFingerprint:selectedObject.fingerprint];
        [m_certificateViewController setKeyId:selectedObject.keyId];
        m_certificateViewController.certificate = selectedObject.publicCertificate;
        
        NSInteger newIdenticonCode = 0;
        
        NSString *keyId = selectedObject.keyId;
        for (int i = 0; i < 8; i++) {
            unichar c = [keyId characterAtIndex:i];
            if ((int)c < 58) {
                newIdenticonCode |=  ((int)c-48);
            }
            else {
                newIdenticonCode |= ((int)c-55);
            }
            if (i < 7) {
                newIdenticonCode <<= 4;
            }
        }
        [m_certificateViewController setIdenticon:newIdenticonCode];
    }
    
    NSLog(@"Selection did change.");
}

-(void)setupCertificateSubview {
    if([[m_placeholderView subviews] firstObject] == nil) {
        CertificateViewController *viewController = [[CertificateViewController alloc]initWithNibName:@"CertificateView" bundle:[NSBundle mainBundle]];
        
        [m_placeholderView addSubview:viewController.view];
        
        [m_placeholderView addConstraint:[NSLayoutConstraint constraintWithItem:viewController.view
                                                                      attribute:NSLayoutAttributeLeading
                                                                      relatedBy:NSLayoutRelationEqual
                                                                         toItem:m_placeholderView
                                                                      attribute:NSLayoutAttributeLeft multiplier:1
                                                                       constant:0]];
        [m_placeholderView addConstraint:[NSLayoutConstraint constraintWithItem:viewController.view
                                                                      attribute:NSLayoutAttributeCenterX
                                                                      relatedBy:NSLayoutRelationEqual
                                                                         toItem:m_placeholderView
                                                                      attribute:NSLayoutAttributeCenterX multiplier:1
                                                                       constant:0]];
        //[m_placeholderView addConstraint:leftConstraint];
        
        m_certificateViewController = viewController;
    }

}

#pragma mark importing to Core Data

-(bool)importRecipientFromCertificate:(OpenPGPMessage *)publicKeyCertificate {
    NSLog(@"Importing Recipient from public key certificate.");
    
    if ([publicKeyCertificate validChecksum]) {
        NSString *armouredText = [publicKeyCertificate originalArmouredText];
        
        OpenPGPPublicKey *primaryKey;
        OpenPGPPublicKey *subkey;
        UserIDPacket *userIdPkt;
        
        OpenPGPSignature *userIdSig;
        OpenPGPSignature *subkeySig;
        
        NSArray *packets = [OpenPGPPacket packetsFromMessage:publicKeyCertificate];
        for ( OpenPGPPacket *eachPacket in packets ) {
            if ([eachPacket packetTag] == 6) {
                primaryKey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
            }
            else if( [eachPacket packetTag] == 13 ) {
                userIdPkt = [[UserIDPacket alloc]initWithPacket:eachPacket];
            }
            else if( [eachPacket packetTag] == 14 ) {
                subkey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
            }
            else if ( [eachPacket packetTag] == 2 ) {
                OpenPGPSignature *signature = [[OpenPGPSignature alloc]initWithPacket:eachPacket];
                if (signature.signatureType == 0x18) {
                    subkeySig = signature;
                }
                else if (signature.signatureType == 0x13 ) {
                    userIdSig = signature;
                }
            }
        }
        
        bool validSig = [userIdSig validateWithPublicKey:primaryKey userId:[userIdPkt stringValue]];
        
        //[subkeySig validateSubkey:subkey withSigningKey:primaryKey];
        
        unsigned char *fingerprint = [primaryKey fingerprintBytes];
        unsigned int d1,d2,d3,d4,d5;
        d1 = fingerprint[0] << 24 | fingerprint[1] << 16 | fingerprint[2] << 8 | fingerprint[3];
        d2 = fingerprint[4] << 24 | fingerprint[5] << 16 | fingerprint[6] << 8 | fingerprint[7];
        d3 = fingerprint[8] << 24 | fingerprint[9] << 16 | fingerprint[10] << 8 | fingerprint[11];
        d4 = fingerprint[12] << 24 | fingerprint[13] << 16 | fingerprint[14] << 8 | fingerprint[15];
        d5 = fingerprint[16] << 24 | fingerprint[17] << 16 | fingerprint[18] << 8 | fingerprint[19];
        
        NSManagedObjectContext *ctx = [self managedObjectContext];
        Recipient *newRecipient = [NSEntityDescription insertNewObjectForEntityForName:@"Recipient" inManagedObjectContext:ctx];
        newRecipient.userId = [userIdPkt stringValue];
        newRecipient.certificate = armouredText;
        newRecipient.keyId = [[primaryKey keyId] uppercaseString];
        newRecipient.added = [NSDate date];
        newRecipient.fingerprint = [[NSString stringWithFormat:@"%08x%08x%08x%08x%08x",d1,d2,d3,d4,d5] uppercaseString];
        newRecipient.primary = primaryKey;
        newRecipient.subkey = subkey;
        
        
        NSRange firstBracket = [[userIdPkt stringValue] rangeOfString:@"<"];
        if (firstBracket.location != NSNotFound) {
            NSString *nameOnly = [[userIdPkt stringValue]substringToIndex:firstBracket.location];
            NSRange secondBracket =[[userIdPkt stringValue] rangeOfString:@">"];
            NSUInteger len = secondBracket.location - firstBracket.location - 1;
            NSString *emailOnly = [[userIdPkt stringValue]substringWithRange:NSMakeRange(firstBracket.location+1, len)];
            
            newRecipient.name = nameOnly;
            newRecipient.email = emailOnly;
        }
        else {
            // If the UserID doesn't conform to RFC 2822, we don't attempt to pull out the e-mail address
            newRecipient.name = [userIdPkt stringValue];
        }

        if (validSig) {
            [self saveAction:self];
        }
        else {
            NSLog(@"Did not add - invalid signature.!");
        }
        
        
        NSMutableArray *editable = [[NSMutableArray alloc]initWithArray:recipients];
        [editable addObject:newRecipient];
        recipients = [[NSArray alloc]initWithArray:editable];
        
        return true;
    }
    else {
        NSLog(@"Invalid OpenPGP message/checksum failed.");
    }
    
    return false;
}

-(void)presentPrivateKeyCertificate:(NSString *)keyId {
    Identities *selectedIdentity = nil;
    for (Identities *each in identities ) {
        NSLog(@"%@",each.keyId);
        if ([each.keyId isEqualToString:keyId]) {
            selectedIdentity = each;
        }
    }
    
    if (selectedIdentity) {
        ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
        windowController.state = kComposePanelStateExportKeystore;
        [windowController presentPrivateKeyCertPanel:self.window certificate:selectedIdentity.privateKeystore UserId:selectedIdentity.name];
    }
    else {
        NSLog(@"Key ID: %@ not found.",keyId);
    }
}

-(void)presentDecryptSheet:(NSString *)keyId {
    Identities *selectedIdentity = nil;
    for (Identities *each in identities ) {
        NSLog(@"%@",each.keyId);
        if ([each.keyId isEqualToString:keyId]) {
            selectedIdentity = each;
        }
    }
    
    if (selectedIdentity) {
        ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
        windowController.state = kComposePanelStateEncryptMessage;
        [windowController presentDecryptPanel:self.window keyId:selectedIdentity.keyId userId:selectedIdentity.name];
    }
    else {
        NSLog(@"Key ID: %@ not found.",keyId);
    }
}

-(bool)generateNewIdentity:(NSString *)userID keySize: (NSInteger)bits password:(NSString *)passwd {
    OpenPGPPublicKey *primaryKey = [[OpenPGPPublicKey alloc]initWithKeyLength:bits isSubkey:NO];
    OpenPGPPublicKey *subkey = [[OpenPGPPublicKey alloc]initWithKeyLength:bits isSubkey:YES];
    OpenPGPPacket *userIdPkt = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:[userID UTF8String] length:[userID length]] tag:13 oldFormat:NO];
    
    OpenPGPPacket *userIdSigPkt = [OpenPGPSignature signUserId:userID withPublicKey:primaryKey];
    OpenPGPPacket *subkeySigPkt = [OpenPGPSignature signSubkey:subkey withPrivateKey:primaryKey];
    
    NSMutableArray *packets = [[NSMutableArray alloc]initWithCapacity:5];
    [packets addObject:[primaryKey exportPublicKey]];
    [packets addObject:userIdPkt];
    [packets addObject:userIdSigPkt];
    [packets addObject:[subkey exportPublicKey]];
    [packets addObject:subkeySigPkt];
    
    NSString *publicKeyCertificate = [OpenPGPMessage armouredMessageFromPacketChain:packets type:kPGPPublicCertificate];
    [packets removeAllObjects];
    
    [packets addObject:[primaryKey exportPrivateKey:passwd]];
    [packets addObject:userIdPkt];
    [packets addObject:userIdSigPkt];
    [packets addObject:[subkey exportPrivateKey:passwd]];
    [packets addObject:subkeySigPkt];
    
    NSString *privateKeystore = [OpenPGPMessage armouredMessageFromPacketChain:packets type:kPGPPrivateCertificate];
    
    NSManagedObjectContext *ctx = [self managedObjectContext];
    Identities *newIdentity = [NSEntityDescription insertNewObjectForEntityForName:@"Identities" inManagedObjectContext:ctx];
    newIdentity.keyId = [[primaryKey keyId] uppercaseString];
    newIdentity.created = [NSDate date];
    newIdentity.publicCertificate = publicKeyCertificate;
    newIdentity.privateKeystore = privateKeystore;
    
    unsigned char *fingerprint = [primaryKey fingerprintBytes];
    unsigned int d1,d2,d3,d4,d5;
    d1 = fingerprint[0] << 24 | fingerprint[1] << 16 | fingerprint[2] << 8 | fingerprint[3];
    d2 = fingerprint[4] << 24 | fingerprint[5] << 16 | fingerprint[6] << 8 | fingerprint[7];
    d3 = fingerprint[8] << 24 | fingerprint[9] << 16 | fingerprint[10] << 8 | fingerprint[11];
    d4 = fingerprint[12] << 24 | fingerprint[13] << 16 | fingerprint[14] << 8 | fingerprint[15];
    d5 = fingerprint[16] << 24 | fingerprint[17] << 16 | fingerprint[18] << 8 | fingerprint[19];
    
    newIdentity.fingerprint = [[NSString stringWithFormat:@"%08x%08x%08x%08x%08x",d1,d2,d3,d4,d5] uppercaseString];
    
    NSRange firstBracket = [userID rangeOfString:@"<"];
    if (firstBracket.location != NSNotFound) {
        NSString *nameOnly = [userID substringToIndex:firstBracket.location];
        NSRange secondBracket =[userID rangeOfString:@">"];
        NSUInteger len = secondBracket.location - firstBracket.location - 1;
        NSString *emailOnly = [userID substringWithRange:NSMakeRange(firstBracket.location+1, len)];
        
        newIdentity.name = nameOnly;
        newIdentity.email = emailOnly;
    }
    else {
        // If the UserID doesn't conform to RFC 2822, we don't attempt to pull out the e-mail address
        newIdentity.name = userID;
    }
    
    NSMutableArray *editable = [[NSMutableArray alloc]initWithArray:identities];
    [editable addObject:newIdentity];
    identities = [[NSArray alloc]initWithArray:editable];
    
    NSError *error;
    
    [ctx save:&error];
    if (error) {
        NSLog(@"Core Data Error: %@",[error description]);
        
        return false;
    }
    
    return true;
}

#pragma mark UI actions

- (IBAction)importFromClipboard:(id)sender {
    NSString *clipboardText = [[NSPasteboard generalPasteboard] stringForType:@"public.utf8-plain-text"];
    
    OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:clipboardText];
    
    if ([message validChecksum]) {
        NSLog(@"OpenPGP message found on clipboard.");
        NSArray *packets = [OpenPGPPacket packetsFromMessage:message];
        for ( OpenPGPPacket *eachPacket in packets ) {
            if ([eachPacket packetTag] == 6 ) {
                OpenPGPPublicKey *publicKey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                NSString *keyId = [publicKey keyId];
                bool bFound = false;
                for (Recipient *each in recipients) {
                    if ([[keyId uppercaseString] isEqualToString:each.keyId]) {
                        NSLog(@"%@",each.keyId);
                        bFound = true;
                        break;
                    }
                }
                
                if (!bFound) {
                    if([self importRecipientFromCertificate:message]) {
                        NSMutableArray *newArray = [[NSMutableArray alloc]initWithCapacity:[recipients count]];
                        for (Recipient *each in recipients) {
                            [newArray addObject:[[NSString alloc]initWithString:each.name]];
                        }
                        [m_children setObject:newArray forKey:@"RECIPIENTS"];
                        [m_outlineView reloadData];
                    }
                    else {
                        NSAlert *alert = [NSAlert alertWithMessageText:@"Couldn't add certificate" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Unspecified error occured when importing public key certificate. Public key certificate invalid or incompatible with NouveauPG."];
                        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
                    }
                    
                }
                else {
                    NSAlert *alert = [NSAlert alertWithMessageText:@"Already exists" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"An identity with the primary Key ID: %@ already exists.",keyId];
                    [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
                }
                
                
                break;
            }
            
            NSLog(@"Packet tag: %ld",(long)[eachPacket packetTag]);
            NSLog(@"Packet length: %lu",(unsigned long)[[eachPacket packetData] length]);
        }
    }
    else {
        NSAlert *alert = [NSAlert alertWithMessageText:@"No input" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"No valid OpenPGP message was found on the clipboard."];
        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
    }
}

- (IBAction)addAction:(id)sender {
    
}

- (IBAction)removeAction:(id)sender {
    id selectedItem = [m_outlineView itemAtRow:[m_outlineView selectedRow]];
    id parent = [m_outlineView parentForItem:selectedItem];
    
    if (selectedItem) {
        if ([parent isEqualToString:@"RECIPIENTS"]) {
            
            Recipient *selectedObject = nil;
            
            for (Recipient *each in recipients) {
                if ([[each name] isEqualToString:selectedItem]) {
                    selectedObject = each;
                }
            }
            
            if (selectedObject) {
                NSMutableArray *mutable = [[NSMutableArray alloc]initWithArray:recipients];
                [mutable removeObject:selectedObject];
                recipients = [[NSArray alloc]initWithArray:mutable];
                [m_outlineView reloadData];
                
                [self.managedObjectContext deleteObject:selectedObject];
                
                NSAlert *confirm = [NSAlert alertWithMessageText:@"Delete recipient?" defaultButton:@"Delete" alternateButton:@"Cancel" otherButton:nil informativeTextWithFormat:@"Are you sure you want to delete the selected recipient?"];
                
                [confirm beginSheetModalForWindow:self.window modalDelegate:self didEndSelector:@selector(alertDidEnd:returnCode:contextInfo:) contextInfo:nil];
            }
        }
    }
    else {
        NSAlert *alert = [NSAlert alertWithMessageText:@"No item selected" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"You must select a Recipient or Identity to delete."];
        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
    }
}

- (void)alertDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo {
    NSError *error;
    if (returnCode == 1) {
        [self.managedObjectContext save:&error];
    }
    else {
        [self.managedObjectContext reset];
    }
}

@end
