# APC Injection Techniques (Local & Remote)

This repository demonstrates **APC (Asynchronous Procedure Call) injection**, using the Windows API function `QueueUserAPC` to execute Calculator obfuscated payload in either the **local** or a **remote** process/thread.

# Disclaimer 
For educational and research purposes only. Do not use this for unauthorized access or malicious activity.

---

## Description

**APC Injection** is a stealthy code injection technique where a function (typically payload) is queued for execution in the context of a target thread. When that thread enters an alertable/suspended state, the payload is executed.

This repo contains:
-  **Local APC Injection**: Injects the Payload into the current process using `QueueUserAPC`.
-  **Remote APC Injection**: Injects the Payload into another process (RuntimeBroker.exe) by creating a thread and queueing an APC call.

---

## 1-Techniques Overview

### 1 : Local APC Injection
1. create a thread that runs the alertableFunction to make it in alertable state .
  -> the thread can be created in suspended state but you need to resume it after calling `QueueUserAPC` using `ResumeThread` winAPI so you can execute the payload

2. inject the payload to the address space memory after deobfuscating it
3. pass alerted thread's handle and deobfuscated payload address to the `QueueUserAPC` win API function 

### 2 : Remote APC Injection (Early-Bird APC Injection)
1. Open target process in Debugged State 
  -> you can create a suspended process using `CREATE_SUSPENDED` flage and you need to resume it so you can execute the payload.

2. inject the payload to the address space memory of the target process after deobfuscating it 
3. pass the debugged thread's handle and the deobfuscated payload to`QueueUserAPC`WINAPI.
4. Stop the debugging of the remote process using `DebugActiveProcessStop` which resumes its threads and executes the payload.

## Getting Started
1. Clone the repository:

    ```bash
    git clone https://github.com/Zanebilal/APC-Injection-Techniques 
    ```
 2. open the desired file.c in Microsoft Visual Studio and run it   

 ## Further reading
  - [microsoft docs]([https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc))
- [Malware Development for Ethical Hackers book](https://www.abebooks.co.uk/9781801810173/Malware-Development-Ethical-Hackers-Learn-1801810176/plp)
- [MalDev Academy Course](https://maldevacademy.com/)
