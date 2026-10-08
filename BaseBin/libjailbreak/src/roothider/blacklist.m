#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <pthread.h>

#include "../libjailbreak.h"
#include "common.h"

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

NSString *getAppBundlePathFromSpawnPath(const char *path) {
    if (!path) return nil;

    // Fast rejection: if path doesn't start with /var/ or /private/var/, skip expensive realpath()
    if (strncmp(path, "/var/", 5) != 0 && strncmp(path, "/private/var/", 13) != 0)
        return nil;

    char abspath[PATH_MAX];
    if (!realpath(path, abspath)) return nil;

    if (strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1) != 0)
        return nil;

    char *p1 = abspath + sizeof(APP_PATH_PREFIX) - 1;
    char *p2 = strchr(p1, '/');
    if (!p2) return nil;

    //is normal app or jailbroken app/daemon?
    if ((p2 - p1) != (sizeof(NULL_UUID) - 1))
        return nil;

    char *p = strstr(p2, ".app/");
    if (!p) return nil;

    p[sizeof(".app/") - 1] = '\0';

    return [NSString stringWithUTF8String:abspath];
}

// In-memory cache for app identifiers to eliminate reading Info.plist on every check
static NSCache *s_appIdentifierCache = nil;
static dispatch_once_t s_appIdentifierOnce;

// get main bundle identifier of app for (PlugIns's) executable path
NSString *getAppIdentifierFromPath(const char *path) {
    if (!path) return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;

    dispatch_once(&s_appIdentifierOnce, ^{
        s_appIdentifierCache = [[NSCache alloc] init];
        [s_appIdentifierCache setCountLimit:256];
    });

    NSString *cachedIdentifier = [s_appIdentifierCache objectForKey:bundlePath];
    if (cachedIdentifier) {
        return cachedIdentifier;
    }

    NSDictionary *appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (!appInfo) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (identifier) {
        [s_appIdentifierCache setObject:identifier forKey:bundlePath];
    }

    return identifier;
}

NSSet* builtinApps()
{
    static NSSet* apps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        JBLogDebug("Initializing builtin apps set");
        apps = [NSSet setWithObjects:@"com.opa334.Dopamine-roothide", nil];
        NSString* customBundleId = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.AppIdentifier") encoding:NSUTF8StringEncoding error:nil];
        if(customBundleId && customBundleId.length > 0) {
            JBLogDebug("Added custom bundle identifier to builtin apps: %s", customBundleId.UTF8String);
            apps = [apps setByAddingObject:customBundleId];
        }
    });
    return apps;
}

// In-memory cache for RootHideConfig.plist with mtime check to eliminate disk I/O
static NSDictionary *s_cachedRoothideConfig = nil;
static time_t s_cachedRoothideConfigMtime = 0;
static pthread_mutex_t s_roothideConfigLock = PTHREAD_MUTEX_INITIALIZER;

static NSDictionary *getCachedRoothideConfig(void)
{
    NSString *configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    const char *cpath = configFilePath.fileSystemRepresentation;

    struct stat st;
    if (stat(cpath, &st) != 0) {
        return nil;
    }

    pthread_mutex_lock(&s_roothideConfigLock);
    if (s_cachedRoothideConfig && s_cachedRoothideConfigMtime == st.st_mtime) {
        NSDictionary *result = s_cachedRoothideConfig;
        pthread_mutex_unlock(&s_roothideConfigLock);
        return result;
    }

    NSDictionary *loaded = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    s_cachedRoothideConfig = loaded;
    s_cachedRoothideConfigMtime = st.st_mtime;
    pthread_mutex_unlock(&s_roothideConfigLock);

    return loaded;
}

bool isBlacklistedApp(const char* identifier)
{
    if(!identifier) return false;

    if([builtinApps() containsObject:@(identifier)]) return false;

    NSDictionary* roothideConfig = getCachedRoothideConfig();
    if(!roothideConfig) return false;

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) return false;

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) return false;

    return blacklisted.boolValue;
}

bool isBlacklistedPath(const char* path)
{
    if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

