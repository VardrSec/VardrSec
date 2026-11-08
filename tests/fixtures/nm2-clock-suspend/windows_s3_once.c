/* PRIVATE SOURCE PROPOSAL ONLY. Not compiled or approved for execution.
 * Existing MinGW types; documented newer APIs are resolved by exact names.
 * One existing-token privilege, one absolute UTC timer, one sleep request.
 * Existing HYBRIDSLEEP AC/DC=1 is preserved; this does not assert hybrid absence.
 * A returning observation is NOT NM-2 acceptance or proof of the wake source.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define __USE_MINGW_ANSI_STDIO 1
#include <windows.h>
#include <powrprof.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Microsoft win32metadata15fc870a, winnt.h:12060; SDK blob9cff0d5c. */
#ifndef SE_PRIVILEGE_REMOVED
#define SE_PRIVILEGE_REMOVED 0x00000004L
#endif

typedef struct { ULONGLONG utc_before, utc_after, biased, unbiased; } SAMPLE;
/* Named fields only. ABI calculation is recorded against the pinned primary SDK. */
typedef char capability_abi[(sizeof(SYSTEM_POWER_CAPABILITIES)==76 &&
    sizeof(SYSTEM_POWER_STATE)==4 && sizeof(BATTERY_REPORTING_SCALE)==8)?1:-1];
typedef DWORD (WINAPI *GET_SCHEME)(HKEY,GUID **);
typedef DWORD (WINAPI *READ_INDEX)(HKEY,const GUID *,const GUID *,const GUID *,LPDWORD);
typedef VOID (WINAPI *TICK_CLOCK)(ULONGLONG *);
typedef VOID (WINAPI *UTC_CLOCK)(LPFILETIME);
typedef BOOLEAN (WINAPI *GET_CAPS)(PSYSTEM_POWER_CAPABILITIES);
typedef BOOLEAN (WINAPI *SUSPEND)(BOOLEAN,BOOLEAN,BOOLEAN);
static GET_SCHEME p_scheme; static READ_INDEX p_ac,p_dc;
static TICK_CLOCK p_biased,p_unbiased; static UTC_CLOCK p_utc;
static GET_CAPS p_caps; static SUSPEND p_suspend; static HMODULE power_module;
static BOOL resolve_system(void) {
    WCHAR path[MAX_PATH]; UINT n=GetSystemDirectoryW(path,MAX_PATH);
    HMODULE kernel=GetModuleHandleW(L"kernel32.dll");
    if (!kernel || !n || n>=MAX_PATH-sizeof(L"\\powrprof.dll")/sizeof(WCHAR)) return FALSE;
    memcpy(path+n,L"\\powrprof.dll",sizeof(L"\\powrprof.dll"));
    power_module=LoadLibraryExW(path,NULL,0x00000800); /* LOAD_LIBRARY_SEARCH_SYSTEM32 */
    if (!power_module) return FALSE;
    p_scheme=(GET_SCHEME)GetProcAddress(power_module,"PowerGetActiveScheme");
    p_ac=(READ_INDEX)GetProcAddress(power_module,"PowerReadACValueIndex");
    p_dc=(READ_INDEX)GetProcAddress(power_module,"PowerReadDCValueIndex");
    p_caps=(GET_CAPS)GetProcAddress(power_module,"GetPwrCapabilities");
    p_suspend=(SUSPEND)GetProcAddress(power_module,"SetSuspendState");
    p_biased=(TICK_CLOCK)GetProcAddress(kernel,"QueryInterruptTimePrecise");
    p_unbiased=(TICK_CLOCK)GetProcAddress(kernel,"QueryUnbiasedInterruptTimePrecise");
    p_utc=(UTC_CLOCK)GetProcAddress(kernel,"GetSystemTimePreciseAsFileTime");
    return p_scheme && p_ac && p_dc && p_caps && p_suspend && p_biased && p_unbiased && p_utc;
}
static const GUID sleep_group = {0x238c9fa8,0x0aad,0x41ed,{0x83,0xf4,0x97,0xbe,0x24,0x2c,0x8f,0x20}};
static const GUID rtc_wake = {0xbd3b718a,0x0680,0x4d9d,{0x8a,0xb2,0xe1,0xd2,0xb4,0xac,0x80,0x6d}};
static const GUID hybrid = {0x94ac6d29,0x73ce,0x41a6,{0x80,0x9f,0x63,0x63,0xba,0x21,0xb4,0x7e}};

static ULONGLONG utc_now(void) {
    FILETIME t; ULARGE_INTEGER n;
    p_utc(&t); n.LowPart=t.dwLowDateTime; n.HighPart=t.dwHighDateTime;
    return n.QuadPart;
}
static SAMPLE sample(void) {
    SAMPLE s; s.utc_before=utc_now();
    p_biased(&s.biased); p_unbiased(&s.unbiased);
    s.utc_after=utc_now(); return s;
}
static BOOL policy(const GUID *original) {
    GUID *active=NULL; DWORD a,b; BOOL ok=FALSE;
    if (p_scheme(NULL,&active)!=ERROR_SUCCESS || !active) return FALSE;
    if (original && memcmp(original,active,sizeof(GUID))) goto done;
    if (p_ac(NULL,active,&sleep_group,&rtc_wake,&a) || a!=1) goto done;
    if (p_dc(NULL,active,&sleep_group,&rtc_wake,&b) || b!=1) goto done;
    if (p_ac(NULL,active,&sleep_group,&hybrid,&a) || a!=1) goto done;
    if (p_dc(NULL,active,&sleep_group,&hybrid,&b) || b!=1) goto done;
    ok=TRUE;
done:
    if (LocalFree(active)!=NULL) ok=FALSE;
    return ok;
}
static BOOL has_privilege(HANDLE token,LUID wanted) {
    union {TOKEN_PRIVILEGES alignment; BYTE bytes[16384];} storage;
    DWORD length=0; TOKEN_PRIVILEGES *all=(TOKEN_PRIVILEGES *)storage.bytes;
    if (!GetTokenInformation(token,TokenPrivileges,storage.bytes,sizeof(storage.bytes),&length)) return FALSE;
    if (length<offsetof(TOKEN_PRIVILEGES,Privileges) || length>sizeof(storage.bytes) ||
        all->PrivilegeCount>(length-offsetof(TOKEN_PRIVILEGES,Privileges))/sizeof(LUID_AND_ATTRIBUTES)) return FALSE;
    for (DWORD i=0;i<all->PrivilegeCount;i++) {
        LUID_AND_ATTRIBUTES p=all->Privileges[i];
        if (p.Luid.LowPart==wanted.LowPart && p.Luid.HighPart==wanted.HighPart)
            return (p.Attributes&SE_PRIVILEGE_REMOVED)==0;
    }
    return FALSE;
}
static void print_sample(const SAMPLE *s) {
    printf("{\"utc_before\":%llu,\"utc_after\":%llu,\"biased\":%llu,\"unbiased\":%llu}",
        (unsigned long long)s->utc_before,(unsigned long long)s->utc_after,
        (unsigned long long)s->biased,(unsigned long long)s->unbiased);
}
int main(int argc,char **argv) {
    if (argc!=3 || strcmp(argv[1],"--execute") || strcmp(argv[2],"C09-Windows-S3-once-20-v1")) {
        puts("{\"status\":\"prepared_only\"}"); return 2;
    }
    HANDLE token=NULL,timer=NULL; GUID *scheme=NULL,original;
    TOKEN_PRIVILEGES requested={0},previous={0}; DWORD previous_bytes=0,error=0;
    SYSTEM_POWER_CAPABILITIES caps={0}; LARGE_INTEGER due;
    SAMPLE before={0},after={0}; BOOL changed=FALSE,armed=FALSE,cleanup_failed=FALSE;
    BOOL returned=FALSE,signaled=FALSE; const char *stage="system_exports";
    if (!resolve_system()) goto done;
    stage="preconditions";
    /* S3 is the selected standby model; existing hybrid policy is not bypassed. */
    if (!p_caps(&caps) || !caps.SystemS3 ||
        caps.RtcWake<PowerSystemSleeping3 || caps.RtcWake>PowerSystemHibernate || !policy(NULL)) goto done;
    if (p_scheme(NULL,&scheme)!=ERROR_SUCCESS || !scheme) goto done;
    original=*scheme; if (LocalFree(scheme)!=NULL) {scheme=NULL;goto done;} scheme=NULL;
    stage="privilege";
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token) ||
        !LookupPrivilegeValueW(NULL,L"SeShutdownPrivilege",&requested.Privileges[0].Luid) ||
        !has_privilege(token,requested.Privileges[0].Luid)) goto done;
    requested.PrivilegeCount=1; requested.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token,FALSE,&requested,sizeof(previous),&previous,&previous_bytes)) goto done;
    error=GetLastError(); changed=previous.PrivilegeCount!=0;
    if (error!=ERROR_SUCCESS || previous.PrivilegeCount>1) goto done;
    stage="timer";
    timer=CreateWaitableTimerW(NULL,TRUE,NULL); if (!timer) goto done;
    ULONGLONG now=utc_now(); if (now>0x7fffffffffffffffULL-200000000ULL) goto done;
    due.QuadPart=(LONGLONG)(now+200000000ULL);
    SetLastError(ERROR_SUCCESS);
    armed=SetWaitableTimer(timer,&due,0,NULL,NULL,TRUE); error=GetLastError();
    if (!armed || error!=ERROR_SUCCESS) goto done; /* Includes success+ERROR_NOT_SUPPORTED. */
    if (!policy(&original) || WaitForSingleObject(timer,0)!=WAIT_TIMEOUT) goto done;
    before=sample();
    if (before.utc_before<now || before.utc_after>(ULONGLONG)due.QuadPart-190000000ULL ||
        before.utc_after<before.utc_before || before.utc_after-before.utc_before>500000ULL) goto done;
    stage="suspend";
    SetLastError(ERROR_SUCCESS);
    returned=p_suspend(FALSE,FALSE,FALSE); error=returned?ERROR_SUCCESS:GetLastError();
    after=sample(); signaled=WaitForSingleObject(timer,0)==WAIT_OBJECT_0;
    stage=returned?(policy(&original)?"returned_unqualified":"policy_after"):"suspend";
done:
    if (!error && strcmp(stage,"returned_unqualified")) error=GetLastError();
    if (timer && armed && !CancelWaitableTimer(timer)) cleanup_failed=TRUE;
    if (timer && !CloseHandle(timer)) cleanup_failed=TRUE;
    if (changed) {
        SetLastError(ERROR_SUCCESS);
        BOOL restored=AdjustTokenPrivileges(token,FALSE,&previous,0,NULL,NULL);
        if (!restored || GetLastError()!=ERROR_SUCCESS) cleanup_failed=TRUE;
    }
    if (token && !CloseHandle(token)) cleanup_failed=TRUE;
    if (scheme && LocalFree(scheme)!=NULL) cleanup_failed=TRUE;
    if (power_module && !FreeLibrary(power_module)) cleanup_failed=TRUE;
    printf("{\"schema\":\"vardr.nm2-c09-windows-observation/1\",\"stage\":\"%s\","
        "\"return_error\":%lu,\"returned\":%s,\"timer_signaled\":%s,\"cleanup_failed\":%s,"
        "\"due_filetime\":%llu,\"before\":",stage,(unsigned long)error,
        returned?"true":"false",signaled?"true":"false",cleanup_failed?"true":"false",
        (unsigned long long)(armed?due.QuadPart:0));
    print_sample(&before); printf(",\"after\":"); print_sample(&after); puts("}");
    return returned && !cleanup_failed && !strcmp(stage,"returned_unqualified") ? 0 : 1;
}
