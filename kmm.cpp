// Build: cl /EHsc /W4 kmm.cpp /link Psapi.lib
// run as admin

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#define STATUS_MORE_ENTRIES     ((NTSTATUS)0x00000105L)
#define STATUS_NO_MORE_ENTRIES  ((NTSTATUS)0x8000001AL)

#define DIRECTORY_QUERY    (0x0001)
#define DIRECTORY_TRAVERSE (0x0002)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);       \
    (p)->RootDirectory = r;                        \
    (p)->Attributes = a;                           \
    (p)->ObjectName = n;                           \
    (p)->SecurityDescriptor = s;                   \
    (p)->SecurityQualityOfService = NULL;          \
}

// NtQuerySystemInformation
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(DWORD, PVOID, ULONG, PULONG);

// NtOpenDirectoryObject / NtQueryDirectoryObject
typedef NTSTATUS(NTAPI* NtOpenDirectoryObject_t)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* NtQueryDirectoryObject_t)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
    );

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

// SYSTEM_MODULE_INFORMATION
#pragma pack(push,1)
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT Id;
    USHORT Rank;
    USHORT w018;
    USHORT NameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
#pragma pack(pop)

struct KernelModuleInfo {
    PVOID base;
    ULONG size;
    std::string name;
    std::string path;

    KernelModuleInfo() : base(nullptr), size(0), name(""), path("") {}
};

bool IsUserAnAdminLocal()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// enum drivers via psapi
void list_via_psapi(std::vector<LPVOID>& bases)
{
    std::cout << "EnumDeviceDrivers (Psapi)\n";

    std::vector<LPVOID> drivers(1024);
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers.data(), (DWORD)(drivers.size() * sizeof(LPVOID)), &cbNeeded)) {
        std::cerr << "EnumDeviceDrivers failed: " << GetLastError() << "\n";
        return;
    }

    size_t count = cbNeeded / sizeof(LPVOID);
    drivers.resize(count);

    for (size_t i = 0; i < count; ++i) {
        CHAR name[MAX_PATH] = { 0 };
        CHAR path[MAX_PATH] = { 0 };

        if (GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name))) {
            GetDeviceDriverFileNameA(drivers[i], path, sizeof(path));
            printf("Base: %p  Name: %-30s Path: %s\n", drivers[i], name, path);
            bases.push_back(drivers[i]);
        }
    }
    std::cout << "Found " << count << " drivers (via Psapi)\n\n";
}

// enum drivers via ntquery
void list_via_ntdll(const std::vector<LPVOID>& psapiBases)
{
    std::cout << "NtQuerySystemInformation(SystemModuleInformation)\n";

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { std::cerr << "Failed to get ntdll\n"; return; }

    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) { std::cerr << "NtQuerySystemInformation not found\n"; return; }

    ULONG size = 0;
    NTSTATUS st = NtQuerySystemInformation(11 /*SystemModuleInformation*/, nullptr, 0, &size);
    if (size == 0) { std::cerr << "NtQuerySystemInformation returned 0 size\n"; return; }

    std::vector<BYTE> buffer(size);
    st = NtQuerySystemInformation(11, buffer.data(), size, &size);
    if (st != 0) { std::cerr << "NtQuerySystemInformation failed (NTSTATUS=" << std::hex << st << ")\n"; return; }

    PSYSTEM_MODULE_INFORMATION p = (PSYSTEM_MODULE_INFORMATION)buffer.data();
    ULONG cnt = p->ModulesCount;
    for (ULONG i = 0; i < cnt; ++i) {
        auto& e = p->Modules[i];

        std::string fullPath(e.ImageName);
        std::string fileName = fullPath.substr(fullPath.find_last_of("\\/") + 1);

        printf("Base: %p  Size: 0x%08X  Name: %-30s Path: %s\n",
            e.ImageBase, e.ImageSize, fileName.c_str(), e.ImageName);

        bool suspicious = false;

        if (std::find(psapiBases.begin(), psapiBases.end(), e.ImageBase) == psapiBases.end()) {
            suspicious = true;
            std::cout << "  [!] Module base not seen in PSAPI list\n";
        }

        if (fileName.empty() || fullPath.empty()) {
            suspicious = true;
            std::cout << "  [!] Empty name/path detected\n";
        }

        if (fullPath.rfind("\\SystemRoot", 0) != 0 && fullPath.rfind("\\??\\", 0) != 0) {
            suspicious = true;
            std::cout << "  [!] Path does not start with expected prefix\n";
        }

        if (suspicious) {
            std::cout << "  [!] Suspicious module at " << e.ImageBase << "\n";
        }
    }
    std::cout << "Found " << cnt << " modules (via NtQuerySystemInformation)\n\n";
}

// enum device objects
void list_driver_objects()
{
    std::cout << "NtOpenDirectoryObject(/Driver)\n";

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { std::cerr << "Failed to load ntdll\n"; return; }

    auto NtOpenDirectoryObject = (NtOpenDirectoryObject_t)GetProcAddress(ntdll, "NtOpenDirectoryObject");
    auto NtQueryDirectoryObject = (NtQueryDirectoryObject_t)GetProcAddress(ntdll, "NtQueryDirectoryObject");

    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject) {
        std::cerr << "NtOpenDirectoryObject/NtQueryDirectoryObject not found\n"; return;
    }

    UNICODE_STRING dirName;
    WCHAR dirBuffer[] = L"\\Driver";
    dirName.Buffer = dirBuffer;
    dirName.Length = (USHORT)(wcslen(dirBuffer) * sizeof(WCHAR));
    dirName.MaximumLength = dirName.Length;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = nullptr;
    NTSTATUS status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (status != STATUS_SUCCESS) { std::cerr << "NtOpenDirectoryObject failed: 0x" << std::hex << status << "\n"; return; }

    ULONG context = 0;
    BYTE buffer[4096];
    ULONG retLen = 0;

    while (true) {
        status = NtQueryDirectoryObject(hDir, buffer, sizeof(buffer), TRUE, FALSE, &context, &retLen);

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            std::cerr << "NtQueryDirectoryObject failed: 0x" << std::hex << status << "\n"; break;
        }

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        std::wstring name(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
        std::wstring type(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
        std::wcout << L"Driver Object: " << name << L" (Type: " << type << L")\n";
    }

    CloseHandle(hDir);
    std::cout << "Finished enumerating /Driver directory objects\n\n";
}

// main
int main()
{
    std::cout << "Usermode Driver Scanner\n";

    if (!IsUserAnAdminLocal()) {
        std::cerr << "Warning: not running as admin. some entries may be hidden.\n";
    }

    std::vector<LPVOID> psapiBases;
    list_via_psapi(psapiBases);
    list_via_ntdll(psapiBases);
    list_driver_objects();

    std::cout << "\nDone.\n";
    std::cin.get();

    return 0;
}
