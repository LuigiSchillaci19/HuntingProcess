#include <windows.h>
#include <Wbemidl.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h> 
#include <iostream>
#include <string>

#define MAX_SUSPICIOUS 256
#define MAX_PATH 1000
#define SUSPICIOUS_PROCESSES_COUNT 2



typedef struct {
	TCHAR processName[MAX_PATH]; 
	DWORD processID;               
	DWORD threadCount;             
	DWORD parentProcessID;        
} ProcessInfo;

typedef struct {
	TCHAR processName[MAX_PATH];  
	DWORD processID;               
	DWORD threadCount;             
	DWORD parentProcessID;         
	TCHAR CommandLine[MAX_PATH]; 
} SuspiciousProcess;

const TCHAR* suspiciousProcesses[] = {
	_T("cmd.exe"),
	_T("powershell.exe")
};

void SaveProcessInfo(PROCESSENTRY32 pe32, ProcessInfo* pe);

void FindParents(DWORD processCount, ProcessInfo* pInfo);

void PrintSuspiciousCommandLinesByPID(DWORD* suspiciousPIDs, DWORD count);

DWORD IsSuspiciousProcess(ProcessInfo* process, DWORD processCount, DWORD* suspiciousPIDs);

std::wstring GetProcCommandLine(DWORD pid);

int main()
{
	while (1) {
	DWORD dwFlags = TH32CS_SNAPPROCESS;
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap;
	ProcessInfo* processInfo = {};
	DWORD processCount = 0;
	DWORD processSuspciousCount = 0;
	if ((hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
		printf("Error: %lu\n", GetLastError());
	}
	else {
		printf("Snapshot create successfull!\n");
	}

	processInfo = (ProcessInfo*)malloc(1000 * sizeof(ProcessInfo));
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("ErrorA: %lu\n", GetLastError());
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		_tprintf(TEXT("\n\n====================================================="));
		_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		_tprintf(TEXT("\n-------------------------------------------------------"));
		_tprintf(TEXT("\n  Process ID        = %d"), pe32.th32ProcessID);
		_tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
		_tprintf(TEXT("\n  Parent process ID = %d\n"), pe32.th32ParentProcessID);
		SaveProcessInfo(pe32, &processInfo[processCount]);
		processCount++;
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	FindParents(processCount, processInfo);

	DWORD* suspiciousPIDs = (DWORD*)malloc(processCount * sizeof(DWORD));
	DWORD suspiciousCount = IsSuspiciousProcess(processInfo, processCount, suspiciousPIDs);

	if (suspiciousCount > 0) {
		printf("Suspicious processes found: %u\n", suspiciousCount);
		for (DWORD i = 0; i < suspiciousCount; i++) {
			printf("Suspicious processes PID: %u\n", suspiciousPIDs[i]); 
		}
	}
	else {
		printf("No suspicious processes found.\n");
	}

	free(suspiciousPIDs);
	free(processInfo);
	Sleep(5000);
	continue;
}
	return 0;
}

bool isLegitParent(const wchar_t* child, const wchar_t* parent) {
	// ⚪ Relazioni standard legittime
	if (_wcsicmp(child, L"System") == 0 && (_wcsicmp(parent, L"[System Process]") == 0 || _wcsicmp(parent, L"") == 0)) return true;
	if (_wcsicmp(child, L"Registry") == 0 && _wcsicmp(parent, L"System") == 0) return true;
	if (_wcsicmp(child, L"smss.exe") == 0 && _wcsicmp(parent, L"System") == 0) return true;
	if (_wcsicmp(child, L"wininit.exe") == 0 && (_wcsicmp(parent, L"smss.exe") == 0 || _wcsicmp(parent, L"svchost.exe") == 0)) return true;
	if (_wcsicmp(child, L"csrss.exe") == 0 && (_wcsicmp(parent, L"wininit.exe") == 0 || _wcsicmp(parent, L"svchost.exe") == 0)) return true;
	if (_wcsicmp(child, L"services.exe") == 0 && _wcsicmp(parent, L"wininit.exe") == 0) return true;
	if (_wcsicmp(child, L"lsass.exe") == 0 && (_wcsicmp(parent, L"services.exe") == 0 || _wcsicmp(parent, L"wininit.exe") == 0)) return true;
	if (_wcsicmp(child, L"fontdrvhost.exe") == 0 && (_wcsicmp(parent, L"wininit.exe") == 0 || _wcsicmp(parent, L"winlogon.exe") == 0)) return true;
	if (_wcsicmp(child, L"svchost.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"dwm.exe") == 0 && _wcsicmp(parent, L"winlogon.exe") == 0) return true;
	if (_wcsicmp(child, L"upfc.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"spoolsv.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"vmtoolsd.exe") == 0 && (_wcsicmp(parent, L"services.exe") == 0 || _wcsicmp(parent, L"explorer.exe") == 0)) return true;
	if (_wcsicmp(child, L"vm3dservice.exe") == 0 && (_wcsicmp(parent, L"services.exe") == 0 || _wcsicmp(parent, L"vm3dservice.exe") == 0)) return true;
	if (_wcsicmp(child, L"VGAuthService.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"MsMpEng.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"MpDefenderCoreService.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"dllhost.exe") == 0 && (_wcsicmp(parent, L"services.exe") == 0 || _wcsicmp(parent, L"svchost.exe") == 0)) return true;
	if (_wcsicmp(child, L"msdtc.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"SearchIndexer.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"SearchProtocolHost.exe") == 0 && _wcsicmp(parent, L"SearchIndexer.exe") == 0) return true;
	if (_wcsicmp(child, L"ctfmon.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"SearchFilterHost.exe") == 0 && _wcsicmp(parent, L"SearchIndexer.exe") == 0) return true;
	if (_wcsicmp(child, L"VSSVC.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"MicrosoftEdgeUpdate.exe") == 0 && (_wcsicmp(parent, L"MicrosoftEdgeUpdate.exe") == 0 || _wcsicmp(parent, L"svchost.exe") == 0)) return true;
	if (_wcsicmp(child, L"sppsvc.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"AggregatorHost.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"SppExtComObj.Exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"sihost.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"taskhostw.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"SearchApp.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"audiodg.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"SecurityHealthSystray.exe") == 0 && _wcsicmp(parent, L"explorer.exe") == 0) return true;
	if (_wcsicmp(child, L"SecurityHealthService.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"ZoomIt64.exe") == 0 && _wcsicmp(parent, L"explorer.exe") == 0) return true;
	if (_wcsicmp(child, L"HuntingProcess.exe") == 0 && _wcsicmp(parent, L"explorer.exe") == 0) return true;
	if (_wcsicmp(child, L"MpCmdRun.exe") == 0 && _wcsicmp(parent, L"MsMpEng.exe") == 0) return true;
	if (_wcsicmp(child, L"internet_detector.exe") == 0 && (_wcsicmp(parent, L"svchost.exe") == 0 || _wcsicmp(parent, L"internet_detector.exe") == 0)) return true;
	if (_wcsicmp(child, L"RuntimeBroker.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"WmiApSrv.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"NisSrv.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"StartMenuExperienceHost.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"ShellExperienceHost.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"UserOOBEBroker.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"smartscreen.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"TiWorker.exe") == 0 && _wcsicmp(parent, L"svchost.exe") == 0) return true;
	if (_wcsicmp(child, L"TrustedInstaller.exe") == 0 && _wcsicmp(parent, L"services.exe") == 0) return true;
	if (_wcsicmp(child, L"msedgewebview2.exe") == 0 && (_wcsicmp(parent, L"SearchApp.exe") == 0 || _wcsicmp(parent, L"msedgewebview2.exe") == 0)) return true;

	return false;
}
void SaveProcessInfo(PROCESSENTRY32 pe32, ProcessInfo* pInfo)
{
	wcscpy_s(pInfo->processName, pe32.szExeFile);
	pInfo->processID = pe32.th32ProcessID;
	pInfo->threadCount = pe32.cntThreads;
	pInfo->parentProcessID = pe32.th32ParentProcessID;
}


//Suspicious father
void FindParents(DWORD processCount, ProcessInfo* pInfo)
{
	DWORD Suspecious = 0;
	TCHAR father[MAX_PATH] = {};
	TCHAR child[MAX_PATH] = {};
	if (pInfo == NULL) {
		printf("Error: null pointer.\n");
		return;
	}

	if (processCount == 0) {
		printf("Error : no process to analyze.\n");
		return;
	}

	for (DWORD i = 0; i < processCount; i++) {
		if (pInfo[i].processID == 0) {
			continue;
		}
		for (DWORD j = 0; j < processCount; j++) {
			if (i != j && pInfo[i].parentProcessID == pInfo[j].processID) {
				_tprintf(TEXT("Process %s (PID: %d) is a child of %s (PID: %d)\n"),
					pInfo[i].processName, pInfo[i].processID,
					pInfo[j].processName, pInfo[j].processID);
				if (!isLegitParent(pInfo[i].processName, pInfo[j].processName)) {
					_tprintf(TEXT("[!] Sospetto: %s ha padre %s non standard\n"),
						pInfo[i].processName, pInfo[j].processName);
						Suspecious++;
				}
			}
		}
	}
	printf("\nSuspicious processes found with suspicious father: %d\n", Suspecious);
}


DWORD IsSuspiciousProcess(ProcessInfo* process, DWORD processCount, DWORD* suspiciousPIDs) {
	DWORD n = 0;
	for (DWORD i = 0; i < processCount; i++) {
		for (DWORD j = 0; j < SUSPICIOUS_PROCESSES_COUNT; j++) {
			if (_tcscmp(process[i].processName, suspiciousProcesses[j]) == 0) {
				if (n < MAX_SUSPICIOUS) {
					suspiciousPIDs[n] = process[i].processID;
				}
				n++;
			}
		}
	}
	return n;  
}




