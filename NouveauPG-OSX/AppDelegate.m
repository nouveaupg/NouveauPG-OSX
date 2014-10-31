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

@implementation AppDelegate

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize managedObjectModel = _managedObjectModel;
@synthesize managedObjectContext = _managedObjectContext;

@synthesize recipients;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    
    OpenSSL_add_all_algorithms();
    
    m_topLevelNodes = [NSArray arrayWithObjects:@"RECIPIENTS",@"IDENTITIES",@"MESSAGES", nil];
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
        [newArray addObject:eachRecipient.name];
    }
    [m_children setObject:newArray forKey:@"RECIPIENTS"];
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

-(void)composeMessageForPublicKey:(OpenPGPPublicKey *)publicKey {
    
    ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
    [windowController presentComposePanel:self.window withPublicKey:publicKey];
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
    return @"";
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item {
    if ([item isEqualToString:@"RECIPIENTS"]) {
        if ([recipients count] > 0) {
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
        [result.textField setStringValue:item];
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
            if ([[each name] isEqualToString:selectedItem]) {
                selectedObject = each;
            }
        }
        
        if([[m_placeholderView subviews] firstObject] == nil) {
            CertificateViewController *viewController = [[CertificateViewController alloc]initWithNibName:@"CertificateView" bundle:[NSBundle mainBundle]];
            
            [m_placeholderView addSubview:viewController.view];
            
            m_certificateViewController = viewController;
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
                [alert beginSheetModalForWindow:self.window completionHandler:nil];
            }
        }
        
        NSDateFormatter *formatter = [[NSDateFormatter alloc]initWithDateFormat:@"%Y-%m-%d %H:%M:%S" allowNaturalLanguage:NO];
        
        NSString *userIdDate =[formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:selectedObject.userIdSig.signatureCreated]];
        
        NSString *subkeyDate =[formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:selectedObject.subkeySig.signatureCreated]];
        
        
        
        
        [m_certificateViewController setPrimarySignature:[NSString stringWithFormat:@"User ID signed: %@",userIdDate]];
        [m_certificateViewController setSubkeySignature:[NSString stringWithFormat:@"Subkey signed: %@",subkeyDate]];
        [m_certificateViewController setUserId:selectedObject.name];
        [m_certificateViewController setPublicKeyAlgo:selectedObject.publicKeyAlgo];
        [m_certificateViewController setEmail:selectedObject.email];
        [m_certificateViewController setFingerprint:selectedObject.fingerprint];
        
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
        
        // TODO: check certificate for errors before importing...
        bool validSig = [userIdSig validateWithPublicKey:primaryKey userId:[userIdPkt stringValue]]
        && [subkeySig validateSubkey:subkey withSigningKey:primaryKey];
        
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

#pragma mark UI actions

- (IBAction)importFromClipboard:(id)sender {
    NSString *clipboardText = [[NSPasteboard generalPasteboard] stringForType:@"public.utf8-plain-text"];
    
    OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:clipboardText];
    
    if ([message validChecksum]) {
        NSLog(@"OpenPGP message found on clipboard.");
        NSArray *packets = [OpenPGPPacket packetsFromMessage:message];
        for ( OpenPGPPacket *eachPacket in packets ) {
            if ([eachPacket packetTag] == 6 ) {
                if([self importRecipientFromCertificate:message]) {
                    NSMutableArray *newArray = [[NSMutableArray alloc]initWithCapacity:[recipients count]];
                    for (Recipient *each in recipients) {
                        [newArray addObject:[[NSString alloc]initWithString:each.name]];
                    }
                    [m_children setObject:newArray forKey:@"RECIPIENTS"];
                }
                break;
            }
            
            NSLog(@"Packet tag: %ld",(long)[eachPacket packetTag]);
            NSLog(@"Packet length: %lu",(unsigned long)[[eachPacket packetData] length]);
        }
    }
    else {
        NSLog(@"Error: No valid OpenPGP message found on clipboard.");
    }
}

- (IBAction)addAction:(id)sender {
    
}

- (IBAction)removeAction:(id)sender {
    
}

@end
