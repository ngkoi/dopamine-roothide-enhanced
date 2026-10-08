
#include <stdbool.h>
#include <sys/types.h>

#ifndef DEBUG
#ifndef NSLog
#define NSLog(...) ((void)0)
#endif
#endif

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>

bool isJailbreakBundlePath(const char* path);
bool cached_blacklist_check_pid(pid_t pid);

