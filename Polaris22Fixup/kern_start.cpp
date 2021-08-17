//
//  kern_start.cpp
//  Polaris22Fixup
//
//  Copyright © 2020 osy86. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>

#define MODULE_SHORT "p22"

#pragma mark - Patches

static const int kEllesmereDeviceId = 0x67DF;

static const uint8_t kAmdBronzeMtlAddrLibGetBaseArrayModeReturnOriginal[] = {
    0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x43, 0xc1, 0xeb,
};

static const uint8_t kAmdBronzeMtlAddrLibGetBaseArrayModeReturnPatched[] = {
    0xb8, 0x02, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xeb,
};

static_assert(sizeof(kAmdBronzeMtlAddrLibGetBaseArrayModeReturnOriginal) == sizeof(kAmdBronzeMtlAddrLibGetBaseArrayModeReturnPatched), "patch size invalid");

static const uint8_t kPECI_IsEarlySAMUInitEnabledOriginal[] = {
    0xbe, 0x60, 0x01, 0x00, 0x00, 0xff, 0x90, 0xb8, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x83, 0xf8, 0x01, 0x0f, 0x94, 0xc1, 0x89, 0xc8, 0x5d, 0xc3,
 };

static const uint8_t kPECI_IsEarlySAMUInitEnabledPatched[] = {
    0xbe, 0x60, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc9, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x89, 0xc8, 0x5d, 0xc3,
};

static constexpr size_t kPECI_IsEarlySAMUInitEnabledOriginalSize = sizeof(kPECI_IsEarlySAMUInitEnabledOriginal);

static_assert(kPECI_IsEarlySAMUInitEnabledOriginalSize == sizeof(kPECI_IsEarlySAMUInitEnabledPatched), "patch size invalid");

static const char *kAmdRadeonX4000HwLibsPath[] { "/System/Library/Extensions/AMDRadeonX4000HWServices.kext/Contents/PlugIns/AMDRadeonX4000HWLibs.kext/Contents/MacOS/AMDRadeonX4000HWLibs" };

static const char *kAmdRadeonX4000Path[] { "/System/Library/Extensions/AMDRadeonX4000.kext/Contents/MacOS/AMDRadeonX4000" };

enum {
    kAmdRadeonX4000=0,
    kAmdRadeonX4000HwLibs,
};

static KernelPatcher::KextInfo kAMDHWLibsInfo[] = {
    [kAmdRadeonX4000] = { "com.apple.kext.AMDRadeonX4000", kAmdRadeonX4000Path, arrsize(kAmdRadeonX4000Path), {true}, {}, KernelPatcher::KextInfo::Unloaded },
    [kAmdRadeonX4000HwLibs] = { "com.apple.kext.AMDRadeonX4000HWLibs", kAmdRadeonX4000HwLibsPath, arrsize(kAmdRadeonX4000HwLibsPath), {true}, {}, KernelPatcher::KextInfo::Unloaded },
};

static mach_vm_address_t orig_cs_validate {};
static mach_vm_address_t orig_IsEarlySAMUInitEnabled {};
static mach_vm_address_t orig_getHardwareInfo {};

#pragma mark - Kernel patching code

template <size_t findSize, size_t replaceSize>
static inline void searchAndPatch(const void *haystack, size_t haystackSize, const char *path, const uint8_t (&needle)[findSize], const uint8_t (&patch)[replaceSize]) {
   if (UNLIKELY(KernelPatcher::findAndReplace(const_cast<void *>(haystack), haystackSize, needle, findSize, patch, replaceSize)))
       DBGLOG(MODULE_SHORT, "found function to patch at %s!", path);
}

#pragma mark - Patched functions

// For Big Sur +
static void patched_cs_validate_page(vnode_t vp, memory_object_t pager, memory_object_offset_t page_offset, const void *data, int *validated_p, int *tainted_p, int *nx_p) {
    char path[PATH_MAX];
    int pathlen = PATH_MAX;
    FunctionCast(patched_cs_validate_page, orig_cs_validate)(vp, pager, page_offset, data, validated_p, tainted_p, nx_p);
    if (vn_getpath(vp, path, &pathlen) == 0 && UserPatcher::matchSharedCachePath(path)) {
        searchAndPatch(data, PAGE_SIZE, path, kAmdBronzeMtlAddrLibGetBaseArrayModeReturnOriginal, kAmdBronzeMtlAddrLibGetBaseArrayModeReturnPatched);
    }
}

static int patched_IsEarlySAMUInitEnabled(void *ctx) {
    DBGLOG(MODULE_SHORT, "PECI_IsEarlySAMUInitEnabled: return 0");
    return 0;
}

static int patched_getHardwareInfo(void *obj, uint16_t *hwInfo) {
    int ret = FunctionCast(patched_getHardwareInfo, orig_getHardwareInfo)(obj, hwInfo);
    DBGLOG(MODULE_SHORT, "AMDRadeonX4000_AMDAccelDevice::getHardwareInfo: return 0x%08X");
    if (ret == 0) {
        SYSLOG(MODULE_SHORT, "getHardwareInfo: deviceId = 0x%x", *hwInfo);
        *hwInfo = kEllesmereDeviceId;
    }
    return ret;
}

#pragma mark - Patches on start/stop

static void pluginStart() {
    
    DBGLOG(MODULE_SHORT, "start");
    lilu.onPatcherLoadForce([](void *user, KernelPatcher &patcher) {
        KernelPatcher::RouteRequest csRoute =
        KernelPatcher::RouteRequest("_cs_validate_page", patched_cs_validate_page, orig_cs_validate) ;
        if (!patcher.routeMultipleLong(KernelPatcher::KernelID, &csRoute, 1))
            SYSLOG(MODULE_SHORT, "failed to route cs validation pages");
    });

    lilu.onKextLoad(kAMDHWLibsInfo, arrsize(kAMDHWLibsInfo), [](void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size){
        DBGLOG(MODULE_SHORT, "processing AMDRadeonX4000HWLibs");
        for (size_t i = 0; i < arrsize(kAMDHWLibsInfo); i++) {
            if (i == kAmdRadeonX4000 && kAMDHWLibsInfo[i].loadIndex == index) {
                KernelPatcher::RouteRequest amd_requests[] {
                    KernelPatcher::RouteRequest("__ZN29AMDRadeonX4000_AMDAccelDevice15getHardwareInfoEP24_sAMD_GET_HW_INFO_VALUES", patched_getHardwareInfo, orig_getHardwareInfo),
                };
                if (!patcher.routeMultiple(index, amd_requests, address, size, true, true)) {
                    SYSLOG(MODULE_SHORT, "failed to patch getHardwareInfo");
                }
            } else if (i == kAmdRadeonX4000HwLibs && kAMDHWLibsInfo[i].loadIndex == index) {
                //BigSur
                if (getKernelVersion() <= KernelVersion::BigSur) {
                    KernelPatcher::RouteRequest amd_requests[] {
                        KernelPatcher::RouteRequest("_PECI_IsEarlySAMUInitEnabled", patched_IsEarlySAMUInitEnabled, orig_IsEarlySAMUInitEnabled),
                    };
                    if (!patcher.routeMultiple(index, amd_requests, address, size, true, true))
                        SYSLOG(MODULE_SHORT, "failed to patch PECI_IsEarlySAMUInitEnabled");
                }
                //Monterey
                else {
                    KernelPatcher::LookupPatch patch = {&kAMDHWLibsInfo[kAmdRadeonX4000HwLibs], kPECI_IsEarlySAMUInitEnabledOriginal, kPECI_IsEarlySAMUInitEnabledPatched, sizeof(kPECI_IsEarlySAMUInitEnabledOriginal), 1};
                    patcher.applyLookupPatch(&patch);
                    if (patcher.getError() != KernelPatcher::Error::NoError) {
                        SYSLOG(MODULE_SHORT, "failed to binary patch PECI_IsEarlySAMUInitEnabled");
                        patcher.clearError();
                    }
                }
            }
        }
    });
}

// Boot args.
static const char *bootargOff[] {
    "-polaris22off"
};
static const char *bootargDebug[] {
    "-polaris22dbg"
};
static const char *bootargBeta[] {
    "-polaris22beta"
};

// Plugin configuration.
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    bootargOff,
    arrsize(bootargOff),
    bootargDebug,
    arrsize(bootargDebug),
    bootargBeta,
    arrsize(bootargBeta),
    KernelVersion::BigSur,
    KernelVersion::Monterey,
    pluginStart
};
