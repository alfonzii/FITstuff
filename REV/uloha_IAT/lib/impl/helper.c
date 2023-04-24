#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "..\helper.h"

static void *old_malloc = NULL;
static void *old_calloc = NULL;
static void *old_realloc = NULL;
static void *old_free = NULL;
static int last_hook = 0;

// Would be better to set it as pure constants, not as calls, because we are not changing anything.
// However, you cannot initialize constants from function calls in C, so I'm not sure, how to do it.

#define P_IAT_START (PIMAGE_THUNK_DATA) GetPtrFromDosOffset( \
    GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT).VirtualAddress)
#define P_IAT_END (PIMAGE_THUNK_DATA) GetPtrFromDosOffset( \
    GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT).VirtualAddress + GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT).Size)

PIMAGE_DOS_HEADER GetDosHeader() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means actual process
    return (PIMAGE_DOS_HEADER)hPEFile; // retrieve DOS header
}

PIMAGE_NT_HEADERS GetPeHeader() {
    PIMAGE_DOS_HEADER p_dosHeader = GetDosHeader();
    return (PIMAGE_NT_HEADERS)(((BYTE *)p_dosHeader) + p_dosHeader->e_lfanew); // retrieve PE header
}

IMAGE_DATA_DIRECTORY GetDataDirectory(int entry_point)  {
    return GetPeHeader()->OptionalHeader.DataDirectory[entry_point];
}

BYTE *GetPtrFromDosOffset(DWORD rva) {
    return ((BYTE *)GetDosHeader()) + rva;
}

BOOL SetIatProtection(DWORD protection_type, PDWORD old_prot_type) {
    IMAGE_DATA_DIRECTORY iatDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);
    return VirtualProtect(
        (LPVOID) GetPtrFromDosOffset(iatDataDirectory.VirtualAddress),
        iatDataDirectory.Size,
        protection_type,
        old_prot_type
    );
}

BOOL IsIatPtrValid(PIMAGE_THUNK_DATA p_imageThunkData) {
    if (p_imageThunkData >= P_IAT_START && p_imageThunkData < P_IAT_END) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

static int SetOldAllocAddr(char *func_name, void *p_old_alloc_fun) {
    if (strcmp(func_name, "malloc") == 0) {
        old_malloc = p_old_alloc_fun;
        last_hook = 1;
        return 1;
    }
    else if (strcmp(func_name, "calloc") == 0) {
        old_calloc = p_old_alloc_fun;
        last_hook = 2;
        return 2;
    }
    else if (strcmp(func_name, "realloc") == 0) {
        old_realloc = p_old_alloc_fun;
        last_hook = 3;
        return 3;
    }
    else if (strcmp(func_name, "free") == 0) {
        old_free = p_old_alloc_fun;
        last_hook = 4;
        return 4;
    }
    else {
        fprintf(stderr, "[SetOldAllocAddr-ERROR]: Hooking of non-alloc function not allowed in this program!\n");
        exit(1);
    }
}

int HookDllFunction(PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor, char *func_name, void *new_func_addr) {
    PIMAGE_THUNK_DATA p_originalThunkData =
        (PIMAGE_THUNK_DATA) GetPtrFromDosOffset(p_importDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA p_thunkData =
        (PIMAGE_THUNK_DATA) GetPtrFromDosOffset(p_importDescriptor->FirstThunk);
    int hooked = 0;

    for (; p_originalThunkData->u1.AddressOfData != NULL, p_thunkData->u1.AddressOfData != NULL; ++p_originalThunkData, ++p_thunkData) {
        if (!IsIatPtrValid(p_thunkData)) {
            fprintf(stderr, "[HookDllFunction-ERROR]: IAT pointer is pointing outside of IAT scope.\n");
            exit(1);
        }

        PIMAGE_IMPORT_BY_NAME p_import = 
                    (PIMAGE_IMPORT_BY_NAME) GetPtrFromDosOffset(p_originalThunkData->u1.AddressOfData);


       // If function name from HintName array matches name of function we want to hook
        if(strcmp(p_import->Name, func_name) == 0) {
            // Save address of original imported unhooked function so we can later recover
            SetOldAllocAddr(func_name, (void*)p_thunkData->u1.Function);
            // Replace with address of our own in IAT (orig function is now hooked to our function)
            p_thunkData->u1.Function = new_func_addr;
            hooked++;
        }
    }
    if (p_originalThunkData->u1.AddressOfData == NULL && p_thunkData->u1.AddressOfData != NULL) {
        //return -1;
        fprintf(stderr, "[HookDllFunction-ERROR]: OriginalFirstThunk data indicating end of array but FirstThunk data not.\n");
        exit(1);
    }
    if (p_originalThunkData->u1.AddressOfData != NULL && p_thunkData->u1.AddressOfData == NULL) {
        //return -2;
        fprintf(stderr, "[HookDllFunction-ERROR]: FirstThunk data indicating end of array but OriginalFirstThunk data not.\n");
        exit(1);
    }
    return hooked;
}

static BOOL IsImportDescriptorNull(PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor) {
    if (p_importDescriptor->Characteristics != NULL)
        return FALSE;
    if (p_importDescriptor->TimeDateStamp != NULL)
        return FALSE;
    if (p_importDescriptor->ForwarderChain != NULL)
        return FALSE;
    if (p_importDescriptor->Name != NULL)
        return FALSE;
    if (p_importDescriptor->FirstThunk != NULL)
        return FALSE;

    return TRUE;
}

static void *GetLastHookOldAllocAddr() {
    switch(last_hook) {
        case 0:
            // Should not happen
            return NULL;

        case 1:
            return old_malloc;
        
        case 2:
            return old_calloc;

        case 3:
            return old_realloc;

        case 4:
            return old_free;
            break;

        default:
            fprintf(stderr, "[GetLastHookOldAllocAddr-ERROR]: Error in GetLastHookOldAllocAddr(). last_hook variable set incorrectly.\n");
            exit(1);
    }
}

void *HookInAllDlls(char *func_name, void *new_func_addr) {
    IMAGE_DATA_DIRECTORY importDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);

    PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromDosOffset(importDataDirectory.VirtualAddress);


    BOOL was_hooked = FALSE;

    int numOfLinkedDlls =
        (int)importDataDirectory.Size / (int)sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1; // -1, bcs of last image_import_descriptor is zeroed.

    int processedDlls = 0;

    /* We cannot compare with p_importDescriptorEnd because theoretically that end could be same
    *  as some other descriptor from my imported DLLs. Then, we could be thinking we are on the end,
    *  as we would be pointing to very same struct as importDescriptorEnd, but we would be somewhere
    *  in the array on totally valid DLL.
    *  Its safer to iterate through number of processed DLLs.
    * 
    *  Also, p_importDescriptor on the end should be all-zeroed, not just OriginalFirstThunk.
    */

    for (; processedDlls < numOfLinkedDlls && !IsImportDescriptorNull(p_importDescriptor); ++p_importDescriptor, ++processedDlls) {
        int hooked = HookDllFunction(p_importDescriptor, func_name, new_func_addr);
        if (hooked > 0)
            was_hooked = TRUE;
    }

    if (processedDlls == numOfLinkedDlls && !IsImportDescriptorNull(p_importDescriptor)) {
        fprintf(stderr, "[HookInAllDlls-ERROR]: Last import descriptor was not null. There is inconsistency between "
                         "number of linked DLLs and size of DataDirectoryImport array.\n");
        exit(1);
    }

    if (processedDlls < numOfLinkedDlls && IsImportDescriptorNull(p_importDescriptor)) {
        fprintf(stderr, "[HookInAllDlls-ERROR]: DataDirectoryImport array was zero terminated earlier than it should. "
                         "By DataDirectoryImport.Size member, there are still some DLLs to be "
                         "processed. There is inconsistency between number of linked DLLs and "
                         "size of DataDirectoryImport array.\n");
        exit(1);
    }

    if(was_hooked == FALSE) {
        last_hook = 0;
        return NULL;
    }

    return GetLastHookOldAllocAddr();
}