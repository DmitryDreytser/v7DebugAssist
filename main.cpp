#include "main.h"
#define ULONG_PTR    DWORD
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (DWORD)(addValue))
#define IS_INTRESOURCE(_r) ((((ULONG_PTR)(_r)) >> 16) == 0)

HRESULT WriteProtectedMemory(LPVOID pDest, LPCVOID pSrc, DWORD dwSize);
HRESULT ApiHijackImports(HMODULE hModule, LPSTR szVictim, LPSTR szEntry, LPVOID pHijacker, LPVOID *ppOrig);

HMODULE hSeven = NULL;
LPVOID pOldHandler = NULL;

// a sample exported function
BOOL DLL_EXPORT APIENTRY SetForegroundWindow_(HWND hWnd)
{
    DWORD dwTimeout;

    SystemParametersInfo(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, &dwTimeout, 0);
    SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, 0, 0);
    HWND hActiveWin = ::GetForegroundWindow();
    int iMyTID   = GetCurrentThreadId();
    int iCurrTID = GetWindowThreadProcessId(hActiveWin,0);
    AttachThreadInput(iMyTID, iCurrTID, TRUE);
    ::SetForegroundWindow(hWnd);
    SetFocus(hWnd);
    hActiveWin = ::GetForegroundWindow();
    if(hActiveWin != hWnd)
    {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
        ::SetActiveWindow(hActiveWin);
        ::SwitchToThisWindow(hWnd, TRUE);
        hActiveWin = ::GetForegroundWindow();
        if(hActiveWin != hWnd)
        {
            hActiveWin = ::GetForegroundWindow();
            if(hActiveWin != hWnd)
            {
                ::SetActiveWindow(hActiveWin);
                ::ShowWindow(hWnd, SW_MINIMIZE);
                ::ShowWindow(hWnd, SW_MAXIMIZE);
                ::SetForegroundWindow(hWnd);
                ::SendMessage(hWnd, WM_ACTIVATE, WA_CLICKACTIVE, (long)hActiveWin);
            }
        }
        SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    }
    SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, (LPVOID)dwTimeout, 0);
    ::SendMessage(hWnd, WM_ACTIVATE, WA_CLICKACTIVE, (long)hActiveWin);
    AttachThreadInput(iMyTID, iCurrTID, FALSE);
    return TRUE;

}
BOOL Hijacked = FALSE;

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if(!Hijacked)
        {
            HMODULE hModule = ::GetModuleHandle("seven.dll");

            if(!hModule)
                hModule = ::GetModuleHandle("tracer.dll");

            ApiHijackImports(hModule, "User32.dll", "SetForegroundWindow", SetForegroundWindow_, &pOldHandler);
            Hijacked = TRUE;
        }
        break;

    case DLL_PROCESS_DETACH:
        /*if(Hijacked)
        {
            ApiHijackImports(::GetModuleHandle("seven.dll"), "User32.dll", "SetForegroundWindow", pOldHandler, &pOldHandler);
            Hijacked = FALSE;
        }*/
        // detach from process
        break;

    case DLL_THREAD_ATTACH:
        // attach to thread
        break;

    case DLL_THREAD_DETACH:
        // detach from thread
        break;
    }
    return TRUE; // succesful
}

HRESULT ApiHijackImports(
    HMODULE hModule,
    LPSTR szVictim,
    LPSTR szEntry,
    LPVOID pHijacker,
    LPVOID *ppOrig
)
{
    // Check args
    if (::IsBadStringPtrA(szVictim, -1) ||
            (!IS_INTRESOURCE(szEntry) && ::IsBadStringPtrA(szEntry, -1)) ||
            ::IsBadCodePtr(FARPROC(pHijacker)))
    {
        return E_INVALIDARG;
    }

    PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);

    if (::IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)) ||
            IMAGE_DOS_SIGNATURE != pDosHeader->e_magic)
    {
        return E_INVALIDARG;
    }

    PIMAGE_NT_HEADERS pNTHeaders =
        MakePtr(PIMAGE_NT_HEADERS, hModule, pDosHeader->e_lfanew);

    if (::IsBadReadPtr(pNTHeaders, sizeof(IMAGE_NT_HEADERS)) ||
            IMAGE_NT_SIGNATURE != pNTHeaders->Signature)
    {
        return E_INVALIDARG;
    }

    HRESULT hr = E_UNEXPECTED;

    // Locate the victim
    IMAGE_DATA_DIRECTORY& impDir =
        pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDesc =
        MakePtr(PIMAGE_IMPORT_DESCRIPTOR, hModule, impDir.VirtualAddress),
        pEnd = pImpDesc + impDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;

    while(pImpDesc < pEnd)
    {
        if (0 == ::lstrcmpiA(MakePtr(LPSTR, hModule, pImpDesc->Name), szVictim))
        {
            if (0 == pImpDesc->OriginalFirstThunk)
            {
                // no import names table
                return E_UNEXPECTED;
            }

            // Locate the entry
            PIMAGE_THUNK_DATA pNamesTable =
                MakePtr(PIMAGE_THUNK_DATA, hModule, pImpDesc->OriginalFirstThunk);

            if (IS_INTRESOURCE(szEntry))
            {
                // By ordinal
                while(pNamesTable->u1.AddressOfData)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(pNamesTable->u1.Ordinal) &&
                            WORD(szEntry) == IMAGE_ORDINAL(pNamesTable->u1.Ordinal))
                    {
                        hr = S_OK;
                        break;
                    }
                    pNamesTable++;
                }
            }
            else
            {
                // By name
                while(pNamesTable->u1.AddressOfData)
                {
                    if (!IMAGE_SNAP_BY_ORDINAL(pNamesTable->u1.Ordinal))
                    {
                        PIMAGE_IMPORT_BY_NAME pName = MakePtr(PIMAGE_IMPORT_BY_NAME,
                                                              hModule, pNamesTable->u1.AddressOfData);

                        if (0 == ::lstrcmpiA(LPSTR(pName->Name), szEntry))
                        {
                            hr = S_OK;
                            break;
                        }
                    }
                    pNamesTable++;
                }
            }

            if (SUCCEEDED(hr))
            {
                // Get address
                LPVOID *pProc = MakePtr(LPVOID *, pNamesTable,
                                        pImpDesc->FirstThunk - pImpDesc->OriginalFirstThunk);

                // Save original handler
                if (ppOrig)
                    *ppOrig = *pProc;

                // write to write-protected memory
                return WriteProtectedMemory(pProc, &pHijacker, sizeof(LPVOID));
            }
            break;
        }
        pImpDesc++;
    }
    return hr;
}

HRESULT WriteProtectedMemory(LPVOID pDest, LPCVOID pSrc, DWORD dwSize)
{
    // Make it writable
    DWORD dwOldProtect = 0;
    if (::VirtualProtect(pDest, dwSize, PAGE_READWRITE, &dwOldProtect))
    {
        ::MoveMemory(pDest, pSrc, dwSize);

        // Restore protection
        ::VirtualProtect(pDest, dwSize, dwOldProtect, &dwOldProtect);
        return S_OK;
    }

    return HRESULT_FROM_WIN32(GetLastError());
}
