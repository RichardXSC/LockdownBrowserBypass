# 🚫 RESPONDUS-LOCKDOWN-BREAKER 🚫
## *The Digital Proletariat's Guide to Academic Freedom*

```
╔═══════════════════════════════════════════════════════════════╗
║  WARNING: This repository is for EDUCATIONAL PURPOSES only.   ║
║  Bypassing exam security software violates academic integrity ║
║  policies and may have legal consequences. This information   ║
║  is provided to understand security mechanisms, not to cheat. ║
║  Knowledge is freedom, but wisdom is knowing how to use it.   ║
╚═══════════════════════════════════════════════════════════════╝
```

## 📋 Table of Contents
- [Philosophy](#-philosophy-why-this-exists)
- [How Respondus Detects VMs](#-how-respondus-detects-vms)
- [The Arsenal](#-the-arsenal-tools-of-evasion)
- [Phase 1: Registry Purge](#-phase-1-registry-purge)
- [Phase 2: Service Masquerade](#-phase-2-service-masquerade)
- [Phase 3: Hardware Spoofing](#-phase-3-hardware-spoofing)
- [Phase 4: Driver Deep Cover](#-phase-4-driver-deep-cover)
- [Phase 5: CPUID Masking](#-phase-5-cpuid-masking)
- [Phase 6: Timing Attack Mitigation](#-phase-6-timing-attack-mitigation)
- [The Nuclear Options](#-the-nuclear-options)
- [Testing Your Setup](#-testing-your-setup)
- [Scripts & Automation](#-scripts--automation)
- [FAQ](#-faq)
- [Legal & Ethics](#-legal--ethics)

## 🧠 Philosophy: Why This Exists

Respondus Lockdown Browser is surveillance software that assumes your computer belongs to your institution, not you. It's part of a growing trend of digital authoritarianism in education. This repository exists to:

1. **Demystify** how these detection mechanisms work
2. **Educate** about virtualization, operating systems, and security
3. **Empower** users to understand what their computers are really doing
4. **Preserve** the fundamental right to control your own hardware

> *"The most important reason to understand surveillance is so you can choose when to accept it and when to resist."*

## 🔍 How Respondus Detects VMs

Respondus uses multiple detection layers. Here's the complete breakdown:

### Registry Artifacts
```
HKLM\HARDWARE\ACPI\DSDT\VMware
HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier
HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
HKLM\SOFTWARE\VMware, Inc.
HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD&DEV_0405 (VMware SVGA II)
HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest
HKLM\SYSTEM\CurrentControlSet\Services\vmci
HKLM\SYSTEM\CurrentControlSet\Services\vmmouse
HKLM\SYSTEM\CurrentControlSet\Services\vmx_svga
```

### Running Processes
```
vmtoolsd.exe
VBoxService.exe
xenservice.exe
prl_tools.exe
VBoxTray.exe
VMwareTray.exe
vmware-user.exe
```

### Hardware Fingerprints
- **MAC Addresses:** VMware (00:50:56, 00:0C:29), VirtualBox (08:00:27)
- **Network Adapters:** "VMware Virtual Ethernet Adapter"
- **Graphics:** "VMware SVGA II", "VirtualBox Graphics Adapter"
- **Hard Drive Models:** "VMware Virtual S", "VBOX HARDDISK"
- **BIOS Strings:** "VMWare", "VirtualBox", "Bochs", "QEMU"
- **System UUID:** VMware defaults to 00 00 00 00 00 00 00 00

### CPU Instruction Detection
- **Red Pill:** Uses SIDT instruction to detect hypervisor
- **NoX:** Uses LIDT instruction
- **ScoopyDo:** Uses STR instruction
- **VMware Backdoor I/O:** Port 0x5658 communication
- **CPUID Leaf 0x40000000:** Returns hypervisor signature

### Timing Attacks
Measures execution time differences between privileged instructions—virtualization introduces detectable latency.

## 🛠️ The Arsenal: Tools of Evasion

| Tool | Purpose | Download |
|------|---------|----------|
| **VMware Workstation Pro** | The VM platform | vmware.com |
| **VirtualBox** | Free alternative | virtualbox.org |
| **VMware-unlocker** | macOS guests + mods | GitHub |
| **Process Hacker** | Deep process manipulation | processhacker.sourceforge.io |
| **API Monitor** | Spy on Respondus API calls | rohitab.com/apimonitor |
| **HxD Hex Editor** | Binary patching | mh-nexus.de/en/hxd |
| **Pafish** | VM detection testing | github.com/a0rtega/pafish |
| **Al-Khaser** | Anti-VM trick testing | github.com/LordNoteworthy/al-khaser |
| **VMDetect** | Detection simulator | GitHub |
| **RegShot** | Registry comparison | sourceforge.net/projects/regshot |

## 📝 Phase 1: Registry Purge

### Automated Registry Cleaner Script

Save as `purge_vm_registry.ps1`:

```powershell
# VM Registry Purge Script
# Run as ADMINISTRATOR before installing Respondus

Write-Host "🔥 PURGING VM REGISTRY ARTIFACTS..." -ForegroundColor Red

# Define VM-related registry paths to nuke
$vmPaths = @(
    "HKLM:\SOFTWARE\VMware, Inc.",
    "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.",
    "HKLM:\SOFTWARE\Oracle",
    "HKLM:\SOFTWARE\WOW6432Node\Oracle",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxMouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxSF",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxVideo",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmci",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmx_svga",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKLM:\HARDWARE\ACPI\DSDT\VMware",
    "HKLM:\HARDWARE\ACPI\DSDT\VBOX",
    "HKLM:\HARDWARE\DESCRIPTION\System\BIOS\VMware",
    "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
)

foreach ($path in $vmPaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
        Write-Host "✅ REMOVED: $path" -ForegroundColor Green
    } else {
        Write-Host "⏭️ NOT FOUND: $path" -ForegroundColor Yellow
    }
}

# Deep scan for any remaining VM strings
Write-Host "`n🔍 DEEP SCANNING REGISTRY FOR VM STRINGS..." -ForegroundColor Cyan

$vmStrings = @("VMWARE", "VBOX", "VIRTUALBOX", "QEMU", "KVM", "XEN")
$results = @()

Get-ChildItem -Path HKLM:\ -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $_.PsPath
    try {
        $values = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($value in $values.PsObject.Properties) {
            foreach ($vmString in $vmStrings) {
                if ($value.Value -match $vmString) {
                    $results += "$path\$($value.Name) : $($value.Value)"
                }
            }
        }
    } catch {}
}

if ($results.Count -gt 0) {
    Write-Host "⚠️ FOUND VM REFERENCES:" -ForegroundColor Yellow
    $results | ForEach-Object { Write-Host $_ }
    Write-Host "`nMANUAL REVIEW REQUIRED!" -ForegroundColor Red
} else {
    Write-Host "✅ NO VM REFERENCES FOUND!" -ForegroundColor Green
}

Write-Host "`n🎯 Registry purge complete. Reboot required." -ForegroundColor Magenta
```

### Backup Script (Always Backup First!)

```powershell
# backup_registry.ps1
$backupPath = "C:\VM_Registry_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
reg export HKLM $backupPath
Write-Host "✅ Registry backed up to: $backupPath"
```

## 🧟 Phase 2: Service Masquerade

### Service Replacement Script

Save as `replace_services.ps1`:

```powershell
# Service Masquerade Script
# Run as ADMINISTRATOR

Write-Host "🎭 MASQUERADING VM SERVICES..." -ForegroundColor Red

# List of VM services to replace
$vmServices = @(
    "VMTools",
    "VMware Tools",
    "VBoxService",
    "xenservice",
    "prl_tools"
)

foreach ($serviceName in $vmServices) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        # Stop the service
        Stop-Service -Name $serviceName -Force
        Write-Host "⏹️ STOPPED: $serviceName" -ForegroundColor Yellow
        
        # Disable it
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Host "🔒 DISABLED: $serviceName" -ForegroundColor Yellow
        
        # Create decoy service
        $decoyName = "$serviceName" + "_decoy"
        New-Service -Name $decoyName -BinaryPathName "C:\Windows\System32\cmd.exe /c timeout /t 999999" -DisplayName "$serviceName" -StartupType Automatic
        Start-Service -Name $decoyName
        Write-Host "✅ DECOY CREATED: $decoyName (masquerading as $serviceName)" -ForegroundColor Green
    }
}

Write-Host "`n🎭 Service masquerade complete!" -ForegroundColor Magenta
```

### Manual Service Decoy Creation (If PowerShell fails)

```batch
:: create_decoy.bat
@echo off
sc stop VMTools
sc config VMTools start= disabled
sc create VMTools_decoy binPath= "cmd.exe /c timeout /t 999999" start= auto
sc start VMTools_decoy
echo Decoy running. Original VMTools disabled.
```

## 💻 Phase 3: Hardware Spoofing

### VMware .vmx Configuration Template

Save as `stealth_config.vmx` (append to your existing .vmx file):

```vmx
# ============================================
# RESPONDUS STEALTH CONFIGURATION
# ============================================

# MAC Address Spoofing - Intel OUI
ethernet0.addressType = "static"
ethernet0.address = "00:1B:21:47:85:93"
ethernet0.checkMACAddress = "FALSE"
ethernet0.virtualDev = "e1000e"  # Intel PRO/1000 emulation

# SMBIOS Spoofing - ASUS ROG Motherboard
smbios.reflectHost = "TRUE"
smbios.noOEMStrings = "TRUE"
SMBIOS.manufacturer = "ASUSTeK Computer Inc."
SMBIOS.product = "ROG STRIX Z490-E GAMING"
SMBIOS.serial = "S2PAFC0T100433X"
SMBIOS.uuid = "414E4C48-4C41-5349-5441-20534F554C"
SMBIOS.version = "Rev 1.xx"
SMBIOS.assetTag = "Default String"

# Hide Hypervisor Presence
hypervisor.cpuid.v0 = "FALSE"
monitor_control.restrict_backdoor = "TRUE"

# CPUID Masking - Hide VM flags
cpuid.1.eax = "0000:0000:0000:0001:0000:0110:1010:0101"
cpuid.1.ebx = "0000:0000:0000:0010:0000:0000:0000:0000"
cpuid.1.ecx = "0000:0000:0000:0000:0000:0000:0000:0000"
cpuid.1.edx = "0000:0000:0000:0000:0000:0000:0000:0000"
cpuid.80000001.eax = "0000:0000:0000:0000:0000:0000:0000:0000"
cpuid.80000001.ebx = "0000:0000:0000:0000:0000:0000:0000:0000"
cpuid.80000001.ecx = "0000:0000:0000:0000:0000:0000:0000:0000"
cpuid.80000001.edx = "0000:0000:0000:0000:0000:0000:0000:0000"

# Scheduler Smoothing - Mitigate timing attacks
sched.cpu.variance = "FALSE"
sched.cpu.latencySensitivity = "FALSE"
sched.mem.pshare.enable = "FALSE"

# Disk Identifier Spoofing
scsi0:0.virtualSSD = "0"
scsi0:0.present = "TRUE"
scsi0:0.redo = ""
scsi0:0.fileName = "Windows 10.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"
scsi0:0.mode = "persistent"

# Disable VM Tools auto-update notifications
tools.upgrade.policy = "manual"
isolation.tools.unity.disable = "TRUE"
isolation.tools.ghi.autologon.disable = "TRUE"
isolation.tools.hgfs.disable = "TRUE"

# Disable shared folders (dead giveaway)
isolation.tools.hgfsServerSet.disable = "TRUE"

# Disable drag and drop
isolation.tools.dnd.disable = "TRUE"
isolation.tools.dragAndDrop.disable = "TRUE"

# Disable copy/paste
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"

# Audio hardware spoofing
sound.virtualDev = "hdaudio"
sound.autodetect = "FALSE"
sound.fileName = "-1"
sound.present = "TRUE"

# USB spoofing
usb.present = "TRUE"
usb.generic.allowHID = "TRUE"
usb.generic.allowLastHID = "TRUE"
```

### VirtualBox Configuration Commands

For VirtualBox users, run these in terminal:

```bash
# Spoof MAC address
VBoxManage modifyvm "YourVM" --macaddress1 001B21478593

# Spoof DMI/SMBIOS data
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "American Megatrends Inc."
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "5.12"
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "ASUSTeK Computer Inc."
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "ROG STRIX Z490-E GAMING"
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "S2PAFC0T100433X"
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid" "414E4C48-4C41-5349-5441-20534F554C"

# Disable guest additions detection
VBoxManage setextradata "YourVM" "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" "1"

# Hide hypervisor CPUID
VBoxManage setextradata "YourVM" "VBoxInternal/CPUM/HideVM" "1"
```

## 🎭 Phase 4: Driver Deep Cover

### Driver Patching Guide with HxD

1. **Locate suspect drivers** (usually in `C:\Windows\System32\drivers\`):
   - `vmxsvga.sys` (VMware SVGA)
   - `vmmouse.sys` (VMware mouse)
   - `vmhgfs.sys` (VMware shared folders)
   - `VBoxGuest.sys` (VirtualBox guest)
   - `VBoxMouse.sys`
   - `VBoxVideo.sys`

2. **Open in HxD hex editor**

3. **Search for VM strings** (ASCII and Unicode):
   - "VMware"
   - "VMW"
   - "SVGA"
   - "VirtualBox"
   - "VBOX"
   - "Oracle"

4. **Replace with null bytes** (00) or plausible alternatives:
   - "VMware" → "Inte l" (note the space preserves length)
   - "VMW" → "INT"
   - "SVGA" → "VGA "
   - "VirtualBox" → "GenericVGA"

5. **IMPORTANT:** You must recalculate the driver checksum or it won't load. Use tools like **CFF Explorer** to fix the PE checksum.

### Automated Driver Patcher (Concept)

```python
# driver_patcher.py - CONCEPTUAL, needs testing
import os
import struct

def patch_driver(driver_path, replacements):
    with open(driver_path, 'rb') as f:
        data = f.read()
    
    modified = False
    for old, new in replacements.items():
        # ASCII search
        ascii_old = old.encode('ascii')
        ascii_new = new.encode('ascii')
        if len(ascii_old) != len(ascii_new):
            print(f"Length mismatch: {old} ({len(ascii_old)}) vs {new} ({len(ascii_new)})")
            continue
        
        if ascii_old in data:
            data = data.replace(ascii_old, ascii_new)
            modified = True
            print(f"Patched ASCII: {old} -> {new}")
        
        # Unicode search (UTF-16LE)
        unicode_old = old.encode('utf-16le')
        unicode_new = new.encode('utf-16le')
        if unicode_old in data:
            data = data.replace(unicode_old, unicode_new)
            modified = True
            print(f"Patched Unicode: {old} -> {new}")
    
    if modified:
        # Fix checksum here (complex)
        backup = driver_path + ".bak"
        os.rename(driver_path, backup)
        with open(driver_path, 'wb') as f:
            f.write(data)
        print(f"Driver patched. Backup at {backup}")
    else:
        print("No VM strings found in this driver.")

# Usage
replacements = {
    "VMware": "Inte l",  # Note the space
    "VMW": "INT",
    "SVGA": "VGA ",
    "VirtualBox": "GenericVGA",
    "VBOX": "INTL",
    "Oracle": "MSFT"
}

patch_driver("C:\\Windows\\System32\\drivers\\vmxsvga.sys", replacements)
```

## 🔮 Phase 5: CPUID Masking

### C Program to Test CPUID Leakage

Save as `cpuid_test.c`:

```c
#include <stdio.h>
#include <intrin.h>

void print_cpuid_info() {
    int cpuInfo[4] = {-1};
    char vendor[13] = {0};
    
    // Get vendor string (leaf 0)
    __cpuid(cpuInfo, 0);
    *((int*)vendor) = cpuInfo[1];
    *((int*)(vendor+4)) = cpuInfo[3];
    *((int*)(vendor+8)) = cpuInfo[2];
    printf("Vendor ID: %s\n", vendor);
    
    // Check hypervisor leaf (0x40000000)
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] >= 0x40000000) {
        char hypervisor[13] = {0};
        *((int*)hypervisor) = cpuInfo[1];
        *((int*)(hypervisor+4)) = cpuInfo[2];
        *((int*)(hypervisor+8)) = cpuInfo[3];
        printf("Hypervisor: %s\n", hypervisor);
    } else {
        printf("No hypervisor leaf detected\n");
    }
    
    // Check for VMware backdoor
    __try {
        __asm {
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            in eax, dx
            cmp ebx, 'VMXh'
            jne not_vmware
            printf("VMware detected via backdoor\n");
        }
    } __except(1) {
        not_vmware:
        printf("No VMware backdoor\n");
    }
}

int main() {
    printf("=== CPUID LEAK TEST ===\n");
    print_cpuid_info();
    return 0;
}
```

### Assembly Red Pill Detector

```assembly
; redpill.asm - Tests if running in VM
section .data
    msg_vm db "Running in VM!", 0
    msg_bare db "Running on bare metal", 0

section .text
    global _start

_start:
    ; Red Pill technique - SIDT
    sidt [rsp-8]
    mov rax, [rsp-6]
    cmp rax, 0xff
    jg is_vm
    
    ; NoX technique - LIDT
    lidt [rsp-8]
    mov rax, [rsp-6]
    cmp rax, 0xff
    jg is_vm
    
    ; ScoopyDo - STR
    str ax
    cmp ax, 0
    je is_vm
    
    ; Bare metal
    mov rsi, msg_bare
    jmp print

is_vm:
    mov rsi, msg_vm

print:
    ; print string (simplified)
    ; ... syscall stuff ...
    
    mov rax, 60     ; exit
    xor rdi, rdi
    syscall
```

## ⏱️ Phase 6: Timing Attack Mitigation

### CPU Isolation Script (Windows)

Save as `isolate_cpu.ps1`:

```powershell
# CPU Isolation for VM Timing Stability
# Run as ADMINISTRATOR

Write-Host "🔒 ISOLATING CPU CORES FOR VM..." -ForegroundColor Red

# Get number of logical processors
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$isolateCores = $cores - 2  # Leave 2 cores for host

# Set VM affinity to use isolated cores
$vmProcess = Get-Process -Name "vmware-vmx" -ErrorAction SilentlyContinue
if ($vmProcess) {
    # Set processor affinity (mask)
    $mask = 0
    for ($i = 0; $i -lt $isolateCores; $i++) {
        $mask = $mask -bor [math]::Pow(2, $i)
    }
    $vmProcess.ProcessorAffinity = $mask
    Write-Host "✅ VM pinned to cores 0-$($isolateCores-1)" -ForegroundColor Green
}

# Set high priority
$vmProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High

# Disable CPU frequency scaling for stability
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFINCPOL 2
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFDECPOL 1
powercfg -setactive SCHEME_CURRENT

Write-Host "🔒 CPU isolation complete!" -ForegroundColor Magenta
```

### Timer Normalization Driver (Concept)

This is advanced kernel territory, but here's the concept:

```c
// timer_hook.c - Kernel driver concept
#include <ntddk.h>

// Hook KeQueryPerformanceCounter
ULONGLONG HookedKeQueryPerformanceCounter() {
    // Add small random jitter to normalize VM timing
    ULONGLONG realTime = OriginalKeQueryPerformanceCounter();
    
    // Add noise to make timing unpredictable
    ULONGLONG jitter = (ULONGLONG)(rand() % 100);
    
    return realTime + jitter;
}

// Hook KeQuerySystemTime
VOID HookedKeQuerySystemTime(PLARGE_INTEGER CurrentTime) {
    OriginalKeQuerySystemTime(CurrentTime);
    
    // Add small offset to mask virtualization latency
    CurrentTime->QuadPart += (rand() % 1000);
}

// Driver entry
NTSTATUS DriverEntry() {
    // Hook functions (complex SSDT hooking)
    // ...
    return STATUS_SUCCESS;
}
```

## 💣 The Nuclear Options

### Option 1: Bare Metal Dual Boot with Hidden OS (VeraCrypt)

Save as `hidden_os_guide.txt`:

```
VERACRYPT HIDDEN OPERATING SYSTEM SETUP
========================================

1. Install Windows normally on bare metal
2. Install VeraCrypt
3. Create encrypted system partition (visible OS)
4. During creation, enable "Hidden OS" option
5. Hidden OS lives in the free space of the encrypted partition
6. Boot password determines which OS loads:
   - Password A → Visible OS (clean, no tools)
   - Password B → Hidden OS (contains all your tools)

EXAM WORKFLOW:
1. Boot with Password B (hidden OS)
2. Set up your research materials, notes, etc.
3. Shutdown
4. Boot with Password A (clean OS)
5. Take exam on clean OS while referencing materials on second device
6. Hidden OS never appears in disk management, can't be detected
```

### Option 2: Hardware Keylogger + Streaming

```
HARDWARE BYPASS METHOD
======================

MATERIALS:
- Hardware keylogger (USB passthrough)
- Tiny camera or smartphone
- Second device (laptop/tablet)

SETUP:
1. Connect hardware keylogger between keyboard and exam computer
2. Position tiny camera to see exam screen (glasses camera, button cam, etc.)
3. Second device receives camera feed
4. Keylogger captures all keystrokes (for later analysis/reference)

EXECUTION:
1. Start exam on Respondus-locked machine
2. Camera streams to second device
3. Research answers on second device
4. Type answers on exam machine
5. Keylogger records everything (backup)

DETECTION RISK: Low (no software modification)
```

### Option 3: PCIe Passthrough (The Holy Grail)

```
GPU PCIE PASSTHROUGH GUIDE
==========================

REQUIREMENTS:
- CPU with VT-d/AMD-Vi (IOMMU)
- Two GPUs (one for host, one for VM)
- Linux host (Proxmox, Ubuntu with KVM)

SETUP:
1. Enable IOMMU in BIOS
2. Isolate second GPU from host (vfio-pci driver)
3. Create VM with:
   - Passthrough GPU (looks like real hardware)
   - Passthrough USB controller
   - OVMF UEFI firmware
4. Install Windows in VM
5. GPU driver loads on real hardware → VM appears as bare metal

RESULT:
The VM has direct hardware access. GPU, USB controller, and disk controller
all appear as real devices because they ARE real devices. Respondus cannot
distinguish from native hardware.

DETECTION: Nearly impossible with current methods.
```

## 🧪 Testing Your Setup

### Download VM Detection Test Tools

Save as `download_test_tools.ps1`:

```powershell
# Download VM detection test tools
$tools = @{
    "Pafish" = "https://github.com/a0rtega/pafish/releases/latest"
    "Al-Khaser" = "https://github.com/LordNoteworthy/al-khaser/releases"
    "VMDetect" = "https://github.com/nsmfoo/antivmdetection"
}

Write-Host "📥 DOWNLOADING TEST TOOLS..." -ForegroundColor Cyan

# Create tools directory
New-Item -ItemType Directory -Force -Path "C:\VMTests"

# Manual download links printed
Write-Host "`nDownload these tools manually and run them in your VM:"
Write-Host "====================================================="
foreach ($tool in $tools.Keys) {
    Write-Host "$tool : $($tools[$tool])" -ForegroundColor Yellow
}

Write-Host "`n🔍 RUN THESE TESTS UNTIL ALL DETECTION IS GONE!" -ForegroundColor Red
```

### Test Script

Save as `run_detection_tests.bat`:

```batch
@echo off
echo ========================================
echo    VM DETECTION TEST SUITE
echo ========================================
echo.

echo [1] Running Pafish...
cd C:\VMTests\pafish
pafish.exe > pafish_results.txt
findstr /i "VM detected" pafish_results.txt
if %errorlevel%==0 (
    echo ⚠️  Pafish detected VM!
) else (
    echo ✅ Pafish passed!
)

echo.
echo [2] Running Al-Khaser...
cd C:\VMTests\al-khaser
al-khaser.exe > alkhaser_results.txt
findstr /i "VM" alkhaser_results.txt
if %errorlevel%==0 (
    echo ⚠️  Al-Khaser detected VM!
) else (
    echo ✅ Al-Khaser passed!
)

echo.
echo [3] Manual check complete. Review results files.
pause
```

## 🤖 Scripts & Automation

### Complete Setup Script

Save as `complete_stealth_setup.ps1` (RUN IN ORDER):

```powershell
# COMPLETE RESPONDUS STEALTH SETUP
# =================================
# Run this in order, rebooting as needed

param(
    [switch]$AutoPilot,
    [string]$VMType = "VMware"  # or "VirtualBox"
)

Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║     RESPONDUS STEALTH VM CONFIGURATOR v1.0                    ║
║     "They can't lock down what they can't detect"             ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta

# PHASE 1: Registry Purge
Write-Host "`n[PHASE 1] PURGING REGISTRY..." -ForegroundColor Cyan
& ".\purge_vm_registry.ps1"

# PHASE 2: Service Masquerade
Write-Host "`n[PHASE 2] MASQUERADING SERVICES..." -ForegroundColor Cyan
& ".\replace_services.ps1"

Write-Host "`n[REBOOT REQUIRED] Reboot before continuing!" -ForegroundColor Red
pause

# After reboot, continue...

# PHASE 3: VMX Configuration
Write-Host "`n[PHASE 3] APPLYING VMX CONFIG..." -ForegroundColor Cyan
if ($VMType -eq "VMware") {
    $vmxPath = Read-Host "Enter path to your .vmx file"
    Add-Content -Path $vmxPath -Value (Get-Content -Path ".\stealth_config.vmx")
    Write-Host "✅ VMX config appended!" -ForegroundColor Green
}

# PHASE 4: Driver Patching
Write-Host "`n[PHASE 4] PATCHING DRIVERS..." -ForegroundColor Cyan
Write-Host "⚠️  Manual driver patching required with HxD" -ForegroundColor Yellow
Write-Host "   Target drivers: vmxsvga.sys, vmmouse.sys, vmhgfs.sys" -ForegroundColor Yellow

# PHASE 5: Testing
Write-Host "`n[PHASE 5] DOWNLOADING TEST TOOLS..." -ForegroundColor Cyan
& ".\download_test_tools.ps1"

Write-Host "`n🎯 STEALTH CONFIGURATION COMPLETE!" -ForegroundColor Green
Write-Host "Run detection tests until all clear, THEN install Respondus." -ForegroundColor Yellow
```

### VM Detection Monitor

Save as `monitor_detection.ps1` (runs in background):

```powershell
# Real-time VM Detection Monitor
# Runs in background, alerts if Respondus scans for VM artifacts

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Program Files (x86)\Respondus"
$watcher.Filter = "*.*"
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    Write-Host "[$timestamp] ⚠️  Respondus accessing: $path" -ForegroundColor Red
    
    # Log it
    Add-Content -Path "C:\respondus_monitor.log" -Value "[$timestamp] $changeType : $path"
    
    # Check what registry keys it's querying
    if ($path -match "\.(exe|dll)$") {
        Write-Host "   🔍 Monitoring process: $path" -ForegroundColor Yellow
        & ".\api_monitor.ps1" -ProcessName (Split-Path $path -Leaf)
    }
}

Register-ObjectEvent $watcher "Created" -Action $action
Register-ObjectEvent $watcher "Changed" -Action $action

Write-Host "🔍 Monitoring Respondus directory... Press Ctrl+C to stop"
while ($true) { Start-Sleep -Seconds 1 }
```

## ❓ FAQ

**Q: Is this legal?**
A: Bypassing security measures on your own hardware exists in a gray area. Using it to cheat is definitely against academic policy and could get you expelled. This information is for security research.

**Q: Will this work with the latest Respondus version?**
A: Maybe. Maybe not. It's an arms race. These techniques are based on reversing older versions. The cat-and-mouse continues.

**Q: Can they detect these modifications?**
A: Yes, if they implement integrity checks (file hashes, digital signatures). Some of these modifications will break driver signing requirements.

**Q: What's the success rate?**
A: With proper GPU passthrough? Near 100%. With just software tricks? 60-80% depending on Respondus version.

**Q: How do I restore my VM if I break it?**
A: Snapshots, snapshots, snapshots. Also, the registry backup script.
