#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <sys/mount.h>

//Don't try to patch/hook me, it's a Kids's trick!

void detect_rootlessJB()
{
    if(access("/var/JB", F_OK)==0) {
        NSLog(@"rootless JB found!");
    }
    
    if(access("/var/containers/Bundle/dylib", F_OK)==0) {
        NSLog(@"xina JB found!");
    }
}

void detect_kernBypass()
{
    if(access("/private/var/MobileSoftwareUpdate/mnt1/System", F_OK)==0)
    {
        NSLog(@"kernBypass installed!");
    }
}

void detect_chroot()
{
    struct statfs s={0};
    statfs("/", &s);
    if(strcmp("/", s.f_mntonname)!=0) {
        NSLog(@"chroot found! %s", s.f_mntonname);
    }
}

void detect_mount_fs()
{
    struct statfs * ss=NULL;
    int n = getmntinfo(&ss, 0);
    for(int i=0; i<n; i++) {
        //printf("mount %s %s : %s\n", ss[i].f_fstypename, ss[i].f_mntonname, ss[i].f_mntfromname);
        
        if(strcmp("/", ss[i].f_mntonname)!=0 && strstr(ss[i].f_mntfromname, "@")!=NULL) {
            NSLog(@"unexcept snap mount! %s => %s", ss[i].f_mntfromname, ss[i].f_mntonname);
        }
        
        for(int j=0; j<i; j++) {
            if(strcmp(ss[i].f_mntfromname, ss[j].f_mntfromname)==0) {
                NSLog(@"double mount: %s", ss[i].f_mntfromname);
            }
        }
    }
}

void detect_bootstraps()
{
    if(access("/var/log/apt", F_OK)==0) {
        NSLog(@"apt log found!");
    }
    
    if(access("/var/log/dpkg", F_OK)==0) {
        NSLog(@"dpkg log found!");
    }
    
    if(access("/var/lib/dpkg", F_OK)==0) {
        NSLog(@"dpkg found!");
    }
    
    if(access("/var/lib/apt", F_OK)==0) {
        NSLog(@"apt found!");
    }
    
    if(access("/var/lib/cydia", F_OK)==0) {
        NSLog(@"cydia found!");
    }
    
    if(access("/var/lib/undecimus", F_OK)==0) {
        NSLog(@"unc0ver found!");
    }
}

void detect_trollStoredFilza()
{
    if(access("/var/lib/filza", F_OK)==0) {
        NSLog(@"trollStoredFilza found!");
    }
    
    if(access("/var/mobile/Library/Filza", F_OK)==0) {
        NSLog(@"trollStoredFilza found!");
    }
}

kern_return_t bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

static mach_port_t connect_mach_service(const char *name) {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = bootstrap_look_up(bootstrap_port, (char *)name, &port);
  return port;
}

void detect_jailbreakd()
{
    if(connect_mach_service("cy:com.saurik.substrated")) {
        NSLog(@"substrated found!");
    }
    
    if(connect_mach_service("org.coolstar.jailbreakd")) {
        NSLog(@"coolstar jb found!");
    }
}

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
void detect_proc_flags()
{
    uint32_t flags = 0;
    csops(getpid(), 0, &flags, 0);
    //NSLog(@"csops=%08X", flags); //22003305/lldb32003004=>3600700D, 22003305/lldb32003005
    
    if(flags & 0x00000004) {
        NSLog(@"get-task-allow found!");
    }
    if(flags & 0x04000000) {
        NSLog(@"unexcept platform binary!");
    }
    if(flags & 0x00000008) {
        NSLog(@"unexcept installer!");
    }
    if(flags & 0x00004000) {
        NSLog(@"unexcept entitlements!");
    }
}


//#import "AppDelegate.h"
int main(int argc, char * argv[])
{
    NSLog(@"Don't try to patch/hook me, it's a Kids's trick!");
    
    detect_rootlessJB();
    detect_kernBypass();
    detect_chroot();
    detect_mount_fs();
    detect_bootstraps();
    detect_trollStoredFilza();
    detect_jailbreakd();
    detect_proc_flags();
    
    
//    NSString * appDelegateClassName;
//    @autoreleasepool {
//        // Setup code that might create autoreleased objects goes here.
//        appDelegateClassName = NSStringFromClass([AppDelegate class]);
//    }
//    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
//    
}
