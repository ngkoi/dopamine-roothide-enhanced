#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#import <substrate.h>
#include <roothide.h>
#include <pthread.h>
#include "common.h"

#ifndef DEBUG
#define NSLog(...) ((void)0)
#endif

extern void xpc_connection_get_audit_token(xpc_connection_t connection, audit_token_t *token);

#define PROC_PIDPATHINFO_MAXSIZE        (4*MAXPATHLEN)

pid_t __thread gCurrentClientPid = 0;

// Fast C-string path prefix check: replaces slow regex recompilation (^(/private)?/var/(\w+)/Library/Preferences/)
static inline BOOL isPreferencesPath(const char *path)
{
	if (!path) return NO;
	const char *p = path;
	if (strncmp(p, "/private", 8) == 0) p += 8;
	if (strncmp(p, "/var/", 5) != 0) return NO;
	p += 5;
	const char *slash = strchr(p, '/');
	if (!slash || slash == p) return NO;
	if (strncmp(slash, "/Library/Preferences/", 21) != 0) return NO;
	return YES;
}

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if (!plistPath) return NO;
	if (!isPreferencesPath(plistPath.fileSystemRepresentation)) return NO;

	NSString *plistName = plistPath.lastPathComponent;
	NSString *identifier = [plistName hasSuffix:@".plist"] ? plistName.stringByDeletingPathExtension : plistName;
	if (is_apple_internal_identifier(identifier.UTF8String))
		return YES;

	if ([plistName hasPrefix:@"com.apple."]
	  || [plistName hasPrefix:@"group.com.apple."]
	  || [plistName hasPrefix:@"systemgroup.com.apple."])
		return NO;

	static NSSet *additionalSystemPlistNames = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		additionalSystemPlistNames = [[NSSet alloc] initWithObjects:
			@".GlobalPreferences.plist",
			@".GlobalPreferences_m.plist",
			@"bluetoothaudiod.plist",
			@"NetworkInterfaces.plist",
			@"OSThermalStatus.plist",
			@"preferences.plist",
			@"osanalyticshelper.plist",
			@"UserEventAgent.plist",
			@"wifid.plist",
			@"dprivacyd.plist",
			@"silhouette.plist",
			@"nfcd.plist",
			@"kNPProgressTrackerDomain.plist",
			@"siriknowledged.plist",
			@"UITextInputContextIdentifiers.plist",
			@"mobile_storage_proxy.plist",
			@"splashboardd.plist",
			@"mobile_installation_proxy.plist",
			@"languageassetd.plist",
			@"ptpcamerad.plist",
			@"com.google.gmp.measurement.monitor.plist",
			@"com.google.gmp.measurement.plist",
			nil
		];
	});

	return ![additionalSystemPlistNames containsObject:plistName];
}

BOOL (*orig_CFPrefsGetPathForTriplet)(CFStringRef, CFStringRef, BOOL, CFStringRef, UInt8*);
BOOL new_CFPrefsGetPathForTriplet(CFStringRef identifier, CFStringRef user, BOOL byHost, CFStringRef container, UInt8 *buffer)
{
	BOOL orig = orig_CFPrefsGetPathForTriplet(identifier, user, byHost, container, buffer);

	NSLog(@"CFPrefsGetPathForTriplet identifier=%@ user=%@ byHost=%d container=%@ ret=%d : %s", identifier, user, byHost, container, orig, orig?(char*)buffer:"");

	if (orig && buffer)
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);

		if (needsRedirection) {
			if (gCurrentClientPid > 0 && cached_blacklist_check_pid(gCurrentClientPid) == true) {
				NSLog(@"CFPrefsGetPathForTriplet deny redirection for process (%d) %s", gCurrentClientPid, proc_get_path(gCurrentClientPid,NULL));
				needsRedirection = NO;
			}
		}
		
		if (needsRedirection) {
			NSLog(@"Plist redirected to jbroot:%@", origPath);
			const char* newpath = jbroot(origPath.UTF8String);
			if (strlen(newpath) < 1024) {
				strcpy((char*)buffer, newpath);
				NSLog(@"CFPrefsGetPathForTriplet redirect to %s", buffer);
			}
			else {
				return NO;
			}
		}
	}

	return orig;
}

void* (*orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__)(id self, xpc_object_t message, xpc_connection_t connection, void* replyHandler);
void* (*LEGACY_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__)(id self, SEL selector, xpc_object_t message, xpc_connection_t connection, void* replyHandler);
void* DISPATCH_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(id self, xpc_object_t message, xpc_connection_t connection, void* replyHandler)
{
	if (@available(iOS 17.0, *)) {
		return orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(self, message, connection, replyHandler);
	} else {
		return LEGACY_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(self, nil, message, connection, replyHandler);
	}
}
void* new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(id self, xpc_object_t message, xpc_connection_t connection, void* replyHandler)
{
	audit_token_t token = {0};
	xpc_connection_get_audit_token(connection, &token);
	pid_t clientPid = audit_token_to_pid(token);

	NSLog(@"CFPrefsDaemon: handleMessage %p/%d pid=%d proc=%s", message, xpc_get_type(message)==XPC_TYPE_DICTIONARY, clientPid, proc_get_path(clientPid,NULL));

	gCurrentClientPid = clientPid;

	return DISPATCH_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(self, message, connection, replyHandler);
}
void* LEGACY_new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(id self, SEL selector, xpc_object_t message, xpc_connection_t connection, void* replyHandler)
{
	return new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__(self, message, connection, replyHandler);
}

void cfprefsdInit(void)
{
	NSLog(@"cfprefsdInit..");

	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");

	void* CFPrefsGetPathForTriplet_ptr = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet");
	if (CFPrefsGetPathForTriplet_ptr)
	{
		MSHookFunction(CFPrefsGetPathForTriplet_ptr, (void *)&new_CFPrefsGetPathForTriplet, (void **)&orig_CFPrefsGetPathForTriplet);
		NSLog(@"hook __CFPrefsGetPathForTriplet %p => %p : %p", CFPrefsGetPathForTriplet_ptr, new_CFPrefsGetPathForTriplet, orig_CFPrefsGetPathForTriplet);
	}

	void* __CFPrefsDaemon_handleMessage_fromPeer_replyHandler__ = MSFindSymbol(coreFoundationImage, "-[CFPrefsDaemon handleMessage:fromPeer:replyHandler:]");
	if (__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__)
	{
		if (@available(iOS 17.0, *)) {
			MSHookFunction(__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, (void *)new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, (void **)&orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__);
			NSLog(@"hook __CFPrefsDaemon_handleMessage_fromPeer_replyHandler__ %p => %p : %p", __CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__);
		} else {
			MSHookFunction(__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, (void *)LEGACY_new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, (void **)&LEGACY_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__);
			NSLog(@"hook __CFPrefsDaemon_handleMessage_fromPeer_replyHandler__ %p => %p : %p", __CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, LEGACY_new__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__, LEGACY_orig__CFPrefsDaemon_handleMessage_fromPeer_replyHandler__);
		}
	}

	%init();
}
