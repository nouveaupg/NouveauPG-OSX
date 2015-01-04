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
#import "ComposeWindowController.h"
#import "NewIdentityPanel.h"
#import "IdenticonImage.h"
#import "PasswordWindow.h"

@implementation AppDelegate

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize managedObjectModel = _managedObjectModel;
@synthesize managedObjectContext = _managedObjectContext;

#define kMessageTypeEncrypted 1
#define kMessageTypeCertificate 2
#define kMessageTypeKeystore 3

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
    
    for(Identities *each in identities) {
        OpenPGPMessage *cert = [[OpenPGPMessage alloc]initWithArmouredText:each.privateKeystore];
        if ([cert validChecksum]) {
            for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:cert]) {
                if ([eachPacket packetTag] == 5) {
                    each.primaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
                }
                else if ([eachPacket packetTag] == 7) {
                    each.secondaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
                }
            }
        }
        else {
            NSLog(@"Invalid Public Key certificate for recipient: %@",each.name);
        }
    }

    
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

#pragma mark Modal panels

-(void)presentPrivateKeyCertificate:(NSString *)keyId {
    Identities *selectedIdentity = nil;
    for (Identities *each in identities ) {
        NSLog(@"%@",each.keyId);
        if ([each.keyId isEqualToString:keyId]) {
            selectedIdentity = each;
            break;
        }
    }
    
    if (selectedIdentity) {
        if ([selectedIdentity.primaryKey isEncrypted]) {
            [self presentPasswordPrompt:selectedIdentity.keyId];
            return;
        }
        
        OpenPGPMessage *publicCertMessage = [[OpenPGPMessage alloc]initWithArmouredText:selectedIdentity.publicCertificate];
        OpenPGPSignature *sig;
        OpenPGPPacket *primarySigPacket;
        OpenPGPPacket *secondarySigPacket;
        OpenPGPPacket *userIdPacket;
        
        NSString *unencryptedKeystore = nil;
        
        if ([publicCertMessage validChecksum]) {
            for (OpenPGPPacket *each in [OpenPGPPacket packetsFromMessage:publicCertMessage]) {
                if ([each packetTag] == 13) {
                    userIdPacket = [[OpenPGPPacket alloc]initWithData:[each packetData]];
                }
                else if( [each packetTag] == 2 ) {
                    sig = [[OpenPGPSignature alloc]initWithPacket:each];
                    if (sig.signatureType >= 0x10 &&
                        sig.signatureType <= 0x13) {
                        primarySigPacket = [[OpenPGPPacket alloc]initWithData:[each packetData]];;
                    }
                    else if(sig.signatureType == 0x18) {
                        secondarySigPacket = [[OpenPGPPacket alloc]initWithData:[each packetData]];
                    }
                }
            }
            
            NSMutableArray *packets = [[NSMutableArray alloc]initWithCapacity:5];
            [packets addObject:[selectedIdentity.primaryKey exportPrivateKeyUnencrypted]];
            [packets addObject:primarySigPacket];
            [packets addObject:userIdPacket];
            [packets addObject:[selectedIdentity.secondaryKey exportPrivateKeyUnencrypted]];
            [packets addObject:secondarySigPacket];
            
            unencryptedKeystore = [OpenPGPMessage armouredMessageFromPacketChain:packets type:kPGPPrivateCertificate];
        }
        else {
            NSAlert *alert = [NSAlert alertWithMessageText:@"Error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Could not read public certificate (invalid OpenPGP message)"];
            [alert runModal];
            return;
        }
        
        if (unencryptedKeystore) {
            ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
            windowController.state = kComposePanelStateExportKeystore;
            [windowController presentPrivateKeyCertPanel:self.window certificate:unencryptedKeystore UserId:selectedIdentity.name];
        }
        else {
            NSAlert *alert = [NSAlert alertWithMessageText:@"Error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Could not export unencrypted keystore."];
            [alert runModal];
        }
        
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
            break;
        }
    }
    
    if (selectedIdentity) {
        
        if ([selectedIdentity.primaryKey isEncrypted]) {
            [self presentPasswordPrompt:selectedIdentity.keyId];
            return;
        }
        ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
        windowController.state = kComposePanelStateDecryptMessage;
        [windowController presentDecryptPanel:self.window keyId:selectedIdentity.keyId userId:selectedIdentity.name];
    }
    else {
        NSLog(@"Key ID: %@ not found.",keyId);
    }
}


-(IBAction)newIdentityPanel:(id)sender {
    NewIdentityPanel *windowController = [[NewIdentityPanel alloc]initWithWindowNibName:@"NewIdentityPanel"];
    [windowController presentNewIdentityPanel:self.window];
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

-(void)presentPasswordPrompt: (NSString *)identityKeyId {
    Identities *selectedIdentity;
    for ( Identities *each in identities ) {
        if ([each.keyId isEqualToString:identityKeyId]) {
            selectedIdentity = each;
            break;
        }
    }
    NSString *prompt = [NSString stringWithFormat:@"Enter password to unlock identity (%@)",selectedIdentity.name];
    
    PasswordWindow *windowController = [[PasswordWindow alloc]initWithWindowNibName:@"PasswordWindow"];
    [windowController presentPasswordPrompt:prompt privateKey:selectedIdentity.primaryKey window:self.window];
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
                break;
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
                [m_certificateViewController setPublicKey:subkey];
            }
            else {
                [m_certificateViewController setSubkeySignature:@"Subkey not verified!"];
                [m_certificateViewController setPublicKey:primaryKey];
            }
        }
        else {
            [m_certificateViewController setPublicKey:primaryKey];
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
        
        
        [m_certificateViewController setUserId:selectedObject.name];
        [m_certificateViewController setPrivateCertificate:YES];
        [m_certificateViewController setEmail:selectedObject.email];
        [m_certificateViewController setFingerprint:selectedObject.fingerprint];
        [m_certificateViewController setKeyId:selectedObject.keyId];
        
        [m_certificateViewController setPublicKey:subkey];
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
    else {
        [m_certificateViewController.view removeFromSuperview];
        m_certificateViewController = nil;
    }
    [self refreshCertificateViewController];
    
    NSLog(@"Selection did change.");
}

#pragma mark Helper methods

+(OpenPGPPublicKey *)validateEncryptedMessage:(OpenPGPMessage *)encryptedMessage {
    if ([encryptedMessage validChecksum]) {
        for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:encryptedMessage]) {
            if ([eachPacket packetTag] == 1) {
                unsigned char *ptr = (unsigned char *)[[eachPacket packetData] bytes];
                NSUInteger packetLen = [[eachPacket packetData] length];
                if (packetLen > 13) {
                    if (ptr[3] != 3) {
                        NSLog(@"Wrong version for Public-Key Encrypted Session Packet. Expected 3, actual %d",ptr[3]);
                        return nil;
                    }
                    if (ptr[12] != 1) {
                        NSLog(@"Unsupported public key type.");
                        return nil;
                    }
                    NSString *keyId = [NSString stringWithFormat:@"%02x%02x%02x%02x",ptr[8],ptr[9],ptr[10],ptr[11]];
                    AppDelegate *app = [[NSApplication sharedApplication]delegate];
                    
                    OpenPGPPublicKey *found = nil;
                    for (Identities *each in app.identities) {
                        if ([[keyId uppercaseString] isEqualToString:[each.keyId uppercaseString]]) {
                            NSLog(@"Primary key found: %@",keyId);
                            found = each.primaryKey;
                            break;
                        }
                        else if([[keyId uppercaseString] isEqualToString:[each.secondaryKey.keyId uppercaseString]]) {
                            NSLog(@"Subkey found: %@", keyId);
                            found = each.secondaryKey;
                            break;
                        }
                    }
                    if (!found) {
                        NSLog(@"Key ID: %@ not found in keychain",keyId);
                    }
                    return found;
                }
            }
        }
    }
    else {
        NSLog(@"No valid OpenPGP message found.");
    }

    
    return nil;
}

-(void)refreshCertificateViewController {
    id selectedItem = [m_outlineView itemAtRow:[m_outlineView selectedRow]];
    id parent = [m_outlineView parentForItem:selectedItem];
    
    if ([parent isEqualToString:@"RECIPIENTS"]) {
        [m_certificateViewController setPrivateCertificate:NO];
        
        Recipient *selectedRecipient = [self recipientForKeyId:selectedItem];
        OpenPGPPublicKey *primaryKey;
        OpenPGPSignature *primarySig;
        OpenPGPSignature *secondarySig;
        if (selectedRecipient) {
            OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:selectedRecipient.certificate];
            for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:message]) {
                if ([eachPacket packetTag] == 2) {
                    OpenPGPSignature *sig = [[OpenPGPSignature alloc]initWithPacket:eachPacket];
                    if (sig.signatureType == 0x18) {
                        secondarySig = sig;
                    }
                    else if(sig.signatureType >= 0x10 && sig.signatureType <= 0x13) {
                        primarySig = sig;
                    }
                }
                else if ([eachPacket packetTag] == 6) {
                    primaryKey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                }
            }
            
            [m_certificateViewController setValidSince:[primarySig dateSigned] until:[primarySig dateExpires]];
            
            if (secondarySig) {
                [m_certificateViewController setSubkeyKeyId:[primaryKey.keyId uppercaseString] signed:[primarySig dateSigned]];
            }
            else {
                [m_certificateViewController setSubkeyKeyId:nil signed:0];
            }
            
            NSString *publicKeyAlgo = [NSString stringWithFormat:@"%ld-bit RSA",(long)selectedRecipient.primary.publicKeySize];
            [m_certificateViewController setPublicKeyAlgo:publicKeyAlgo];
        }
    }
    else if ([parent isEqualToString:@"MY IDENTITIES"]) {
        Identities *selectedIdentity = [self identityForKeyId:selectedItem];
        if (selectedIdentity) {
            NSString *publicKeyAlgo = [NSString stringWithFormat:@"%ld-bit RSA",(long)selectedIdentity.primaryKey.publicKeySize];
            [m_certificateViewController setPublicKeyAlgo:publicKeyAlgo];
            [m_certificateViewController setSubkeyKeyId:nil signed:0];
            
            if ([selectedIdentity.primaryKey isEncrypted]) {
                [m_certificateViewController setIdentityLocked:YES];
            }
            else {
                [m_certificateViewController setIdentityLocked:NO];
            }
        }
        else {
            // TODO: hide certificate
        }
    }
}

-(Recipient *)recipientForKeyId:(NSString *)keyId {
    Recipient *recipient = nil;
    
    for (Recipient *each in recipients) {
        if ([[[each keyId] uppercaseString] isEqualToString:[keyId uppercaseString]]) {
            recipient = each;
            break;
        }
    }
    
    return recipient;
}

-(Identities *)identityForKeyId:(NSString *)keyId {
    Identities *identity = nil;
    
    for (Identities *each in identities) {
        if ([[[each keyId] uppercaseString] isEqualToString:[keyId uppercaseString]]) {
            identity = each;
            break;
        }
    }
    
    return identity;
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
    newIdentity.keyId = [[NSString alloc] initWithString:[[primaryKey keyId] uppercaseString]];
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
    
    newIdentity.primaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:[primaryKey exportPrivateKey:passwd]];
    newIdentity.secondaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:[subkey exportPrivateKey:passwd]];
    
    NSMutableArray *editable = [[NSMutableArray alloc]initWithArray:identities];
    [editable addObject:newIdentity];
    identities = [[NSArray alloc]initWithArray:editable];
    
    NSError *error;
    
    [ctx save:&error];
    if (error) {
        NSLog(@"Core Data Error: %@",[error description]);
        
        return false;
    }
    else {
        NSMutableArray *newArray = [[NSMutableArray alloc]initWithCapacity:[identities count]];
        for( Identities *each in identities ) {
            if (each.keyId) {
                [newArray addObject:[[NSString alloc]initWithString:each.keyId]];
            }
        }
        [m_children setObject:newArray forKey:@"MY IDENTITIES"];
        [m_outlineView reloadData];
    }
    
    return true;
}

-(void)setupCertificateSubview {
    if([[m_placeholderView subviews] firstObject] == nil) {
        CertificateViewController *viewController = [[CertificateViewController alloc]initWithNibName:@"CertificateView" bundle:[NSBundle mainBundle]];
        
        [m_placeholderView addSubview:viewController.view];
        /*
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
         */
        //[m_placeholderView addConstraint:leftConstraint];
        
        m_certificateViewController = viewController;
    }

}

#pragma mark importing to Core Data

-(bool)encryptIdentityWithPassword: (NSString *)password {
    NSMutableArray *packets = [[NSMutableArray alloc]initWithCapacity:5];
    
    NSManagedObjectContext *ctx = [self managedObjectContext];
    Identities *newIdentity = [NSEntityDescription insertNewObjectForEntityForName:@"Identities" inManagedObjectContext:ctx];
    
    [packets addObject:[m_primaryKey exportPublicKey]];
    OpenPGPPacket *userIdPkt = [[OpenPGPPacket alloc]initWithPacketBody:[NSData dataWithBytes:[m_userId UTF8String] length:[m_userId length]] tag:13 oldFormat:NO];
    [packets addObject:userIdPkt];
    
    OpenPGPPacket *userIdSig = m_userIdSigPkt;
    if (!userIdPkt) {
        userIdPkt = [OpenPGPSignature signUserId:m_userId withPublicKey:m_primaryKey];
    }
    [packets addObject:userIdPkt];

    if (m_secondaryKey) {
        [packets addObject:[m_secondaryKey exportPublicKey]];
        
        OpenPGPPacket *subkeySig = m_subkeySigPkt;
        if (!subkeySig) {
            subkeySig = [OpenPGPSignature signSubkey:m_secondaryKey withPrivateKey:m_primaryKey];
        }
        [packets addObject:subkeySig];
    }
    
    NSString *publicCertificate = [OpenPGPMessage armouredMessageFromPacketChain:packets type:kMessageTypeCertificate];
    
    newIdentity.publicCertificate = publicCertificate;
    
    [packets setObject:[m_primaryKey exportPrivateKey:password] atIndexedSubscript:0];
    [packets setObject:[m_secondaryKey exportPrivateKey:password] atIndexedSubscript:3];
    
    NSString *privateKeystore = [OpenPGPMessage armouredMessageFromPacketChain:packets type:kMessageTypeKeystore];
    
    newIdentity.privateKeystore = privateKeystore;
    unsigned char *fingerprint = [m_primaryKey fingerprintBytes];
    unsigned int d1,d2,d3,d4,d5;
    d1 = fingerprint[0] << 24 | fingerprint[1] << 16 | fingerprint[2] << 8 | fingerprint[3];
    d2 = fingerprint[4] << 24 | fingerprint[5] << 16 | fingerprint[6] << 8 | fingerprint[7];
    d3 = fingerprint[8] << 24 | fingerprint[9] << 16 | fingerprint[10] << 8 | fingerprint[11];
    d4 = fingerprint[12] << 24 | fingerprint[13] << 16 | fingerprint[14] << 8 | fingerprint[15];
    d5 = fingerprint[16] << 24 | fingerprint[17] << 16 | fingerprint[18] << 8 | fingerprint[19];
    newIdentity.fingerprint = [[NSString stringWithFormat:@"%08x%08x%08x%08x%08x",d1,d2,d3,d4,d5] uppercaseString];
    newIdentity.keyId = [m_primaryKey keyId];
    newIdentity.created = [NSDate date];
    
    NSRange firstBracket = [m_userId rangeOfString:@"<"];
    if (firstBracket.location != NSNotFound) {
        NSString *nameOnly = [m_userId substringToIndex:firstBracket.location];
        NSRange secondBracket =[m_userId rangeOfString:@">"];
        NSUInteger len = secondBracket.location - firstBracket.location - 1;
        NSString *emailOnly = [m_userId substringWithRange:NSMakeRange(firstBracket.location+1, len)];
        
        newIdentity.name = nameOnly;
        newIdentity.email = emailOnly;
    }
    else {
        // If the UserID doesn't conform to RFC 2822, we don't attempt to pull out the e-mail address
        newIdentity.name = m_userId;
    }
    
    [self saveAction:self];
    
    NSMutableArray *editable = [[NSMutableArray alloc]initWithArray:identities];
    [editable addObject:newIdentity];
    identities = editable;
    
    return true;
}

-(OpenPGPPublicKey *)subkeyForPrimaryKeyId:(NSString *)primaryKeyId {
    for (Identities *each in identities) {
        if ([each.keyId isEqualToString:primaryKeyId]) {
            return each.secondaryKey;
        }
    }
    
    return nil;
}

-(bool)importIdentityFromKeystore:(OpenPGPMessage *)keystore {
    m_primaryKey = m_secondaryKey = nil;
    m_userId = nil;
    m_userIdSigPkt = m_subkeySigPkt = nil;
    
    for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:keystore]) {
        if ([eachPacket packetTag] == 5) {
             m_primaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
        }
        else if([eachPacket packetTag] == 7) {
            m_secondaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
        }
        else if([eachPacket packetTag] == 13) {
            UserIDPacket *userIdPkt = [[UserIDPacket alloc]initWithPacket:eachPacket];
            m_userId = [[NSString alloc]initWithString:[userIdPkt stringValue]];
        }
        else if([eachPacket packetTag] == 2) {
            OpenPGPSignature *sig = [[OpenPGPSignature alloc]initWithPacket:eachPacket];
            if (sig.signatureType == 0x13) {
                m_userIdSigPkt = [[OpenPGPPacket alloc]initWithData:[eachPacket packetData]];
            }
            else if(sig.signatureType == 0x18) {
                m_subkeySigPkt = [[OpenPGPPacket alloc]initWithData:[eachPacket packetData]];
            }
        }
    }
    
    if (m_primaryKey && m_userId) {
        // check to see if we already have this KeyID in the identities keychain
        bool found = false;
        for(Identities *eachIdentity in identities) {
            if ([[eachIdentity.keyId uppercaseString] isEqualToString:[m_primaryKey.keyId uppercaseString]]) {
                found = true;
                break;
            }
        }
        
        if (found) {
            NSAlert *alert = [NSAlert alertWithMessageText:@"Can't import identity" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"An identity with the KeyId %@ already exists in the Identities keychain. Delete it before importing this identity.",[m_primaryKey.keyId uppercaseString]];
            [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
        }
        else {
            // prompt for password
            PasswordWindow *windowController = [[PasswordWindow alloc]initWithWindowNibName:@"PasswordWindow"];
            NSString *prompt = [NSString stringWithFormat:@"Importing identity \"%@\": enter a password to protect from unauthorized use.",m_userId];
            [windowController presentChangePasswordPrompt:prompt privateKey:m_primaryKey window:self.window];
            
            return true;
        }
    }
    
    return false;
}

-(bool)importEncryptedMessage:(OpenPGPMessage *)message {
    return false;
}


-(IBAction)importFromFile:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    
    // display the panel
    [panel beginWithCompletionHandler:^(NSInteger result) {
        if (result == NSFileHandlingPanelOKButton) {
            NSError *error;
            // grab a reference to what has been selected
            NSURL *theDocument = [[panel URLs]objectAtIndex:0];
            
            // write our file name to NSLog
            NSString *theString = [NSString stringWithFormat:@"%@", theDocument];
            NSLog(@"%@",theString);
            
            NSString *importData = [NSString stringWithContentsOfURL:theDocument encoding:NSUTF8StringEncoding error:&error];
            
            if (importData && !error) {
                OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:importData];
                // validate OpenPGPMessage
                if ([message validChecksum]) {
                    NSInteger messageType = 0;
                    
                    OpenPGPPublicKey *primaryKey;
                    OpenPGPPublicKey *subkey;
                    OpenPGPSignature *primarySig;
                    OpenPGPSignature *subkeySig;
                    UserIDPacket *userIdPkt;
                    
                    for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:message]) {
                        if ([eachPacket packetTag] == 6) {
                            messageType = 1;
                            
                            primaryKey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                            break;
                        }
                        else if([eachPacket packetTag] == 5) {
                            messageType = 2;
                            
                            primaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
                            break;
                        }
                        else if([eachPacket packetTag] == 1 ) {
                            messageType = 3;
                            break;
                        }
                    }
                    
                    NSAlert *alert;
                    
                    if (messageType == 1) {
                        if([self importRecipientFromCertificate:message]) {
                            NSMutableArray *newArray = [[NSMutableArray alloc]initWithCapacity:20];
                            for (Recipient *each in recipients) {
                                [newArray addObject:each.keyId];
                            }
                            [m_children setObject:newArray forKey:@"RECIPIENTS"];
                            [m_outlineView reloadData];
                        }
                    }
                    else {
                        alert = [NSAlert alertWithMessageText:@"Error importing file" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"A valid OpenPGP was not found in the selected file."];
                        [alert runModal];
                    }
                }
                else {
                    NSAlert *alert = [NSAlert alertWithMessageText:@"Error importing file" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Selected file did not contain a valid OpenPGP message."];
                    [alert runModal];
                }
            }
            else {
                NSAlert *alert = [NSAlert alertWithMessageText:@"Error importing file" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"%@",[error description]];
                [alert runModal];
            }
            
        }
    }];
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




#pragma mark IBActions

- (IBAction)importFromClipboard:(id)sender {
    NSString *clipboardText = [[NSPasteboard generalPasteboard] stringForType:@"public.utf8-plain-text"];
    
    OpenPGPMessage *message = [[OpenPGPMessage alloc]initWithArmouredText:clipboardText];
    
    int messageType = 0;
    
    if ([message validChecksum]) {
        NSLog(@"OpenPGP message found on clipboard.");
        NSArray *packets = [OpenPGPPacket packetsFromMessage:message];
        for ( OpenPGPPacket *eachPacket in packets ) {
            if ([eachPacket packetTag] == 6 ) {
                messageType = kMessageTypeCertificate;
                OpenPGPPublicKey *publicKey = [[OpenPGPPublicKey alloc]initWithPacket:eachPacket];
                NSString *keyId = [publicKey keyId];
                bool bFound = false;
                for (Recipient *each in recipients) {
                    if ([[keyId uppercaseString] isEqualToString:[each.keyId uppercaseString]]) {
                        NSLog(@"%@",each.keyId);
                        bFound = true;
                        break;
                    }
                }
                
                if (!bFound) {
                    if([self importRecipientFromCertificate:message]) {
                        NSMutableArray *newArray = [[NSMutableArray alloc]initWithCapacity:[recipients count]];
                        for (Recipient *each in recipients) {
                            if (each.keyId) {
                                [newArray addObject:[[NSString alloc]initWithString:each.keyId]];
                            }
                            
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
            else if( [eachPacket packetTag] == 1 ) {
                OpenPGPPublicKey *keyUsed = [AppDelegate validateEncryptedMessage:message];
                if (keyUsed) {
                    Identities *usedIdentity = nil;
                    for (Identities *eachIdentity in identities) {
                        if ([[eachIdentity.primaryKey keyId]isEqualToString:keyUsed.keyId] || [[eachIdentity.secondaryKey keyId] isEqualToString:keyUsed.keyId]) {
                            usedIdentity = eachIdentity;
                            break;
                        }
                    }
                    for (NSString *eachKeyId in [m_children objectForKey:@"MY IDENTITIES"]) {
                        if ([eachKeyId isEqualToString:usedIdentity.keyId]) {
                            NSInteger row = [m_outlineView rowForItem:eachKeyId];
                            [m_outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:false];
                            
                            break;
                        }
                    }
                    
                    if([keyUsed isEncrypted]) {
                        NSAlert *alert = [NSAlert alertWithMessageText:@"Identity locked" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The identity used to decrypt this message is locked. Unlock the identity and try importing the message again."];
                        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
                    }
                    else {
                        // present decrypted message
                        ComposeWindowController *windowController = [[ComposeWindowController alloc]initWithWindowNibName:@"ComposePanel"];
                        windowController.state = kComposePanelStateDecryptMessage;
                        
                        [windowController presentDecryptedMessage:self.window owner:usedIdentity.keyId encryptedMessage:clipboardText];
                        
                    }
                }
                else {
                    NSAlert *alert = [NSAlert alertWithMessageText:@"Can't decrypt message" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The secret key needed to decrypt the OpenPGP message on the clipboard was not found in the Identities keychain."];
                    [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
                }
                break;
            }
            else if( [eachPacket packetTag] == 5 ) {
                [self importIdentityFromKeystore:message];
                
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

- (IBAction)lockIdentity:(id)sender {
    // note this is not wired, the action is bubbled up from CertificateViewController
    id selectedItem = [m_outlineView itemAtRow:[m_outlineView selectedRow]];
    id parent = [m_outlineView parentForItem:selectedItem];
    
    if (selectedItem) {
        if ([parent isEqualToString:@"MY IDENTITIES"]) {
            Identities *selectedObject = [self identityForKeyId:selectedItem];
            
            OpenPGPMessage *keystoreMessage = [[OpenPGPMessage alloc]initWithArmouredText:selectedObject.privateKeystore];
            for (OpenPGPPacket *eachPacket in [OpenPGPPacket packetsFromMessage:keystoreMessage] ) {
                if( [eachPacket packetTag] == 5 ) {
                    selectedObject.primaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
                }
                else if( [eachPacket packetTag] == 7 ) {
                    selectedObject.secondaryKey = [[OpenPGPPublicKey alloc]initWithEncryptedPacket:eachPacket];
                }
            }
            
            [m_certificateViewController setIdentityLocked:YES];
        }
    }
}

- (IBAction)removeAction:(id)sender {
    id selectedItem = [m_outlineView itemAtRow:[m_outlineView selectedRow]];
    id parent = [m_outlineView parentForItem:selectedItem];
    
    if (selectedItem) {
        if ([parent isEqualToString:@"RECIPIENTS"]) {
            
            Recipient *selectedObject = nil;
            
            for (Recipient *each in recipients) {
                if ([[each keyId] isEqualToString:selectedItem]) {
                    selectedObject = each;
                    break;
                }
            }
            
            if (selectedObject) {
                m_pendingObject = selectedObject;
                m_pendingItem = [[NSString alloc]initWithString:selectedItem];
                m_rootNode = [[NSString alloc]initWithString:parent];
                [self.managedObjectContext deleteObject:selectedObject];
                
                NSAlert *confirm = [NSAlert alertWithMessageText:@"Delete recipient?" defaultButton:@"Delete" alternateButton:@"Cancel" otherButton:nil informativeTextWithFormat:@"Are you sure you want to delete the selected recipient?"];
                
                [confirm beginSheetModalForWindow:self.window modalDelegate:self didEndSelector:@selector(alertDidEnd:returnCode:contextInfo:) contextInfo:nil];
            }
        }
        else if( [parent isEqualToString:@"MY IDENTITIES"]) {
            Identities *selectedObject = [self identityForKeyId:selectedItem];
            
            if (selectedObject) {
                m_pendingObject = selectedObject;
                m_pendingItem = [[NSString alloc]initWithString:selectedItem];
                m_rootNode = [[NSString alloc]initWithString:parent];
                
                NSAlert *confirm = [NSAlert alertWithMessageText:@"Delete recipient?" defaultButton:@"Delete" alternateButton:@"Cancel" otherButton:nil informativeTextWithFormat:@"Are you sure you want to delete the selected recipient %@?",selectedObject.name];
                
                [self.managedObjectContext deleteObject:selectedObject];
                
                [confirm beginSheetModalForWindow:self.window modalDelegate:self didEndSelector:@selector(alertDidEnd:returnCode:contextInfo:) contextInfo:nil];
            }
        }
    }
    else {
        NSAlert *alert = [NSAlert alertWithMessageText:@"No item selected" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"You must select a Recipient or Identity to delete."];
        [alert beginSheetModalForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:nil];
    }
}

#pragma mark Alert delegate

- (void)alertDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo {
    NSError *error;
    if (returnCode == 1) {
        [self.managedObjectContext save:&error];
        
        if( [m_rootNode isEqualToString:@"RECIPIENTS"] ) {
            NSMutableArray *mutable = [[NSMutableArray alloc]initWithArray:recipients];
            [mutable removeObject:m_pendingObject];
            recipients = [[NSArray alloc]initWithArray:mutable];
        }
        else if( [m_rootNode isEqualToString:@"MY IDENTITIES"] ) {
            NSMutableArray *mutable = [[NSMutableArray alloc]initWithArray:identities];
            [mutable removeObject:m_pendingObject];
            identities = [[NSArray alloc]initWithArray:mutable];
        }
        
        NSMutableArray *treeArray = [[NSMutableArray alloc]initWithCapacity:10];
        for (NSString *each in [m_children objectForKey:m_rootNode] ) {
            if (![each isEqualToString:m_pendingItem]) {
                [treeArray addObject:[[NSString alloc]initWithString:each]];
            }
        }
        [m_children setObject:treeArray forKey:m_rootNode];
        
        [m_outlineView reloadData];
        
        [m_certificateViewController.view removeFromSuperview];
        m_certificateViewController = nil;
    }
    else {
        m_pendingItem = nil;
        m_pendingObject = nil;
        m_rootNode = nil;
        
        [self.managedObjectContext reset];
    }
}

@end
