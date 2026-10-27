#include "collect.h"

#include <windows.h>
#include <softpub.h>
#include <mscat.h>
#include <wintrust.h>

#include <cstdio>
#include <cwchar>
#include <map>
#include <string>

namespace procrib {

namespace {

const LONG kStatusLengthMismatch = static_cast<LONG>(0xC0000004);
const LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005);
const LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023);
const HWND kNoWindow = reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);
const ULONG kSystemProcessInformation = 5;
const ULONG kProcessCommandLineInformation = 60;

struct UString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

// Layout of SYSTEM_PROCESS_INFORMATION up to PrivatePageCount.
struct SysProcInfo {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UString ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
};

typedef LONG(NTAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

std::string utf8(const wchar_t* w, int len) {
    if (len <= 0) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, &s[0], n, nullptr, nullptr);
    return s;
}

std::string utf8(const std::wstring& w) { return utf8(w.data(), static_cast<int>(w.size())); }

std::string hex(DWORD v) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%08lx", v);
    return b;
}

std::wstring query_image_path(HANDLE h) {
    std::wstring buf(32768, L'\0');
    DWORD n = static_cast<DWORD>(buf.size());
    if (!QueryFullProcessImageNameW(h, 0, &buf[0], &n)) return L"";
    buf.resize(n);
    return buf;
}

std::string query_cmdline(HANDLE h, NtQueryInformationProcessFn fn) {
    if (!fn) return "";
    std::string buf(1024, '\0');
    for (int tries = 0; tries < 4; tries++) {
        ULONG need = 0;
        LONG st = fn(h, kProcessCommandLineInformation, &buf[0], static_cast<ULONG>(buf.size()), &need);
        if (st >= 0) {
            auto* us = reinterpret_cast<UString*>(&buf[0]);
            return utf8(us->Buffer, us->Length / 2);
        }
        if (st != kStatusLengthMismatch && st != kStatusBufferOverflow && st != kStatusBufferTooSmall)
            return "";
        buf.assign(need > buf.size() ? need : buf.size() * 2, '\0');
    }
    return "";
}

std::string verify_catalog(const wchar_t* path, HANDLE file) {
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext(&admin, nullptr, 0)) return "";
    std::string result;
    DWORD hlen = 0;
    CryptCATAdminCalcHashFromFileHandle(file, &hlen, nullptr, 0);
    std::basic_string<BYTE> hash(hlen, 0);
    if (hlen && CryptCATAdminCalcHashFromFileHandle(file, &hlen, &hash[0], 0)) {
        HCATINFO cat = CryptCATAdminEnumCatalogFromHash(admin, &hash[0], hlen, 0, nullptr);
        if (cat) {
            CATALOG_INFO ci = {sizeof ci};
            if (CryptCATCatalogInfoFromContext(cat, &ci, 0)) {
                std::wstring tag;
                for (DWORD i = 0; i < hlen; i++) {
                    wchar_t b[3];
                    swprintf(b, 3, L"%02X", hash[i]);
                    tag += b;
                }
                WINTRUST_CATALOG_INFO wc = {};
                wc.cbStruct = sizeof wc;
                wc.pcwszCatalogFilePath = ci.wszCatalogFile;
                wc.pcwszMemberTag = tag.c_str();
                wc.pcwszMemberFilePath = path;
                wc.hMemberFile = file;
                wc.pbCalculatedFileHash = &hash[0];
                wc.cbCalculatedFileHash = hlen;
                WINTRUST_DATA wd = {};
                wd.cbStruct = sizeof wd;
                wd.dwUIChoice = WTD_UI_NONE;
                wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wd.pCatalog = &wc;
                wd.dwStateAction = WTD_STATEACTION_VERIFY;
                wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
                GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                LONG st = WinVerifyTrust(kNoWindow, &action, &wd);
                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(kNoWindow, &action, &wd);
                result = st == 0 ? "signed (catalog)" : "invalid " + hex(static_cast<DWORD>(st));
            }
            CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        }
    }
    CryptCATAdminReleaseContext(admin, 0);
    return result;
}

std::string check_signature(const std::wstring& path) {
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(kNoWindow, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(kNoWindow, &action, &wd);

    if (st == 0) return "signed";
    if (static_cast<DWORD>(st) == static_cast<DWORD>(TRUST_E_NOSIGNATURE) ||
        static_cast<DWORD>(st) == static_cast<DWORD>(TRUST_E_PROVIDER_UNKNOWN) ||
        static_cast<DWORD>(st) == static_cast<DWORD>(TRUST_E_SUBJECT_FORM_UNKNOWN)) {
        HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            std::string c = verify_catalog(path.c_str(), f);
            CloseHandle(f);
            if (!c.empty()) return c;
        }
        return "unsigned";
    }
    return "invalid " + hex(static_cast<DWORD>(st));
}

}  // namespace

std::vector<Proc> collect(const CollectOpts& o) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto query_sys = reinterpret_cast<NtQuerySystemInformationFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtQuerySystemInformation")));
    auto query_proc = reinterpret_cast<NtQueryInformationProcessFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtQueryInformationProcess")));
    std::vector<Proc> out;
    if (!query_sys) return out;

    std::string buf(1 << 20, '\0');
    for (;;) {
        ULONG need = 0;
        LONG st = query_sys(kSystemProcessInformation, &buf[0], static_cast<ULONG>(buf.size()), &need);
        if (st >= 0) break;
        if (st != kStatusLengthMismatch) return out;
        buf.assign(need + (64 << 10), '\0');  // list can grow between the two calls
    }

    std::map<std::wstring, std::string> sig_cache;
    const char* p = buf.data();
    for (;;) {
        auto* e = reinterpret_cast<const SysProcInfo*>(p);
        Proc pr;
        pr.pid = static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(e->UniqueProcessId));
        pr.ppid = static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(e->InheritedFromUniqueProcessId));
        pr.start = static_cast<uint64_t>(e->CreateTime.QuadPart);
        pr.threads = e->NumberOfThreads;
        pr.working_set = e->WorkingSetSize;
        pr.private_bytes = e->PrivatePageCount;
        pr.cpu_time = static_cast<uint64_t>(e->UserTime.QuadPart + e->KernelTime.QuadPart);
        pr.name = utf8(e->ImageName.Buffer, e->ImageName.Length / 2);
        if (pr.pid == 0) pr.name = "System Idle Process";
        if (pr.name.empty()) pr.name = "?";

        if (pr.pid == 0 || pr.pid == 4) {
            pr.access = Access::Kernel;
        } else {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pr.pid);
            if (!h) {
                pr.access = GetLastError() == ERROR_ACCESS_DENIED ? Access::Denied : Access::Gone;
            } else {
                std::wstring path = query_image_path(h);
                pr.path = utf8(path);
                pr.cmdline = query_cmdline(h, query_proc);
                DWORD code = 0;
                if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE) pr.access = Access::Gone;
                CloseHandle(h);
                if (o.signatures && !path.empty() && pr.access != Access::Gone) {
                    auto it = sig_cache.find(path);
                    if (it == sig_cache.end()) it = sig_cache.emplace(path, check_signature(path)).first;
                    pr.sig = it->second;
                }
            }
        }
        out.push_back(std::move(pr));
        if (!e->NextEntryOffset) break;
        p += e->NextEntryOffset;
    }
    return out;
}

void CpuTracker::update(std::vector<Proc>& procs) {
    auto now = std::chrono::steady_clock::now();
    double wall = std::chrono::duration<double>(now - prev_time_).count() * 1e7;  // 100ns units
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    double cores = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;

    std::unordered_map<uint32_t, Sample> cur;
    for (Proc& p : procs) {
        auto it = prev_.find(p.pid);
        if (have_prev_ && wall > 0 && it != prev_.end() && it->second.start == p.start &&
            p.cpu_time >= it->second.cpu) {
            p.cpu_pct = (p.cpu_time - it->second.cpu) / wall / cores * 100.0;
        }
        cur[p.pid] = {p.start, p.cpu_time};
    }
    prev_.swap(cur);
    prev_time_ = now;
    have_prev_ = true;
}

}  // namespace procrib
