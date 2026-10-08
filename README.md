# dopahide-enhanced

an optimized fork of dopamine roothide for ios 15.0 - 16.7.x (arm64 & arm64e).

roothide offers great app stealth and jailbreak detection bypass, but can cause ui lag, micro-stutters, and battery drain due to repeated hooking and ipc overhead.

dopahide-enhanced eliminates the performance penalty while keeping 100% of roothide's stealth and tweak compatibility.

## changes

- in-memory trustcache caching to remove repeated xpc lookups on library loads
- fast paths for system libraries and app store apps to bypass hooking overhead
- optimized cfprefsd hooking (removed regex overhead, bypasses apple domains)
- cached blacklist and bundle queries for faster app launch times
- direct kernel csflags patching on process spawn
- stripped heavy debug logging in release binaries

## building

use github actions:
1. fork this repo
2. go to the actions tab and run the build workflow
3. download the .ipa or .tipa from artifacts

to build locally on macos:
```bash
make
```

## credits

- opa334 (dopamine)
- roothidedev (roothide)
- évelyne (ellekit)
- ngkoi (dopahide-enhanced)
