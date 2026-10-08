#import <Foundation/Foundation.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <roothide.h>
#include <sys/mount.h>
#include "common.h"

#define PID_CACHE_SIZE 128
static struct {
	pid_t pid;
	int pidversion;
	bool is_blacklisted;
} g_shared_pid_cache[PID_CACHE_SIZE];
static pthread_mutex_t g_shared_pid_cache_lock = PTHREAD_MUTEX_INITIALIZER;

bool cached_blacklist_check_pid(pid_t pid)
{
	// Fast path: system daemons and calling process are never blacklisted
	if (pid <= 100 || pid == getpid()) return false;
	int pidversion = proc_get_pidversion(pid);
	if (pidversion <= 0) return jbclient_blacklist_check_pid(pid);

	size_t idx = (size_t)pid % PID_CACHE_SIZE;
	pthread_mutex_lock(&g_shared_pid_cache_lock);
	if (g_shared_pid_cache[idx].pid == pid && g_shared_pid_cache[idx].pidversion == pidversion) {
		bool cached = g_shared_pid_cache[idx].is_blacklisted;
		pthread_mutex_unlock(&g_shared_pid_cache_lock);
		return cached;
	}
	pthread_mutex_unlock(&g_shared_pid_cache_lock);

	bool blacklisted = jbclient_blacklist_check_pid(pid);

	pthread_mutex_lock(&g_shared_pid_cache_lock);
	g_shared_pid_cache[idx].pid = pid;
	g_shared_pid_cache[idx].pidversion = pidversion;
	g_shared_pid_cache[idx].is_blacklisted = blacklisted;
	pthread_mutex_unlock(&g_shared_pid_cache_lock);

	return blacklisted;
}

bool isJailbreakBundlePath(const char* path)
{
	if (!path) return false;

	// Fast Path 1: System and rootfs bundles are never jailbreak bundles
	if (strncmp(path, "/System/", 8) == 0 ||
	    strncmp(path, "/Applications/", 14) == 0 ||
	    strncmp(path, "/usr/", 5) == 0 ||
	    strncmp(path, "/Library/", 9) == 0 ||
	    strncmp(path, "/private/var/db/", 16) == 0) {
		return false;
	}

	// Fast Path 2: Explicitly located inside jbroot
	const char* jb = jbroot("/");
	if (jb && jb[0] && strncmp(path, jb, strlen(jb)) == 0) {
		return true;
	}

	// Fast Path 3: App Store / installed user apps
	if (isRemovableBundlePath(path))
	{
		if (!hasTrollstoreMarker(path)) {
			// Normal App Store app bundle
			return false;
		}
		return true;
	}

	struct statfs fs;
	if (statfs(path, &fs) != 0)
	{
		// Path does not exist, may be a jailbreak bundle
		return true;
	}

	if (strcmp(fs.f_mntonname, "/") == 0) {
		return false;
	}

	return true;
}

