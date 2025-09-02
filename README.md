# Kernel Driver Scanner
C++ Usermode Windows Driver Scanner To Enumerate Loaded Kernel Modules And Driver Objects, Flagging, Suspicious or manually mapped drivers.

## Features
- Enumerates drivers via **PSAPI (`EnumDeviceDrivers`)**
- Enumerates drivers via **`NtQuerySystemInformation(SystemModuleInformation)`**
- Enumerates `/Driver` directory objects via **`NtOpenDirectoryObject` / `NtQueryDirectoryObject`**
- Highlights suspicious modules that do not appear in standard driver lists or have abnormal paths.

## Limitations

- Cannot reliably detect stealth **manual-mapped drivers** that leave no usermode artifacts.
- Full detection of hidden drivers requires kernel access.


## Build
Visual Studio, create **Console App (C++)** project, create or upload kmm.cpp and link against psapi.lib, build and run as admin.

Suspicious modules will be highlighted in the console if they do not match expected criteria.
