#include <stdio.h>
#include <windows.h>

#include "..\debug-tests.h"
#include "..\malloc-debug.h"
#include "..\helper.h"


void PrintImportedDLLs() {
    IMAGE_DATA_DIRECTORY importDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    IMAGE_DATA_DIRECTORY iatDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);



    PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromDosOffset(importDataDirectory.VirtualAddress);

    PIMAGE_IMPORT_DESCRIPTOR p_importDescriptorEnd =
        (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromDosOffset(importDataDirectory.VirtualAddress + importDataDirectory.Size);

    int numOfLinkedDlls = (int)importDataDirectory.Size / (int)sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1; // -1, bcs of last image_import_descriptor is zeroed.

    printf("Number of linked DLLs is %d\n\n", numOfLinkedDlls);



    for (; p_importDescriptor < p_importDescriptorEnd && p_importDescriptor->OriginalFirstThunk != NULL; ++p_importDescriptor)
    {
        char* pDLLName = (char*) GetPtrFromDosOffset(p_importDescriptor->Name);
        printf("DLL: %s\n", pDLLName );

        if (p_importDescriptor->Characteristics != NULL) // neviem, preco tu je toto, ked rovnaka kontrola sa robi uz pri FOR loope
        {
            PIMAGE_THUNK_DATA pImageThunkData = (PIMAGE_THUNK_DATA) GetPtrFromDosOffset(p_importDescriptor->OriginalFirstThunk);
            for (; pImageThunkData->u1.AddressOfData != NULL; ++pImageThunkData )
            {
                // pozor, napřed bychom měli otestovat typ importu...
                PIMAGE_IMPORT_BY_NAME pImport = 
                    (PIMAGE_IMPORT_BY_NAME) GetPtrFromDosOffset(pImageThunkData->u1.AddressOfData);
                
                printf("%04hx %s\n", pImport->Hint, pImport->Name);
            }
        }
        printf("\n");
    }
}


void TestHook() {
    IMAGE_DATA_DIRECTORY importDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    IMAGE_DATA_DIRECTORY iatDataDirectory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);



    PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromDosOffset(importDataDirectory.VirtualAddress);

    PIMAGE_IMPORT_DESCRIPTOR p_importDescriptorEnd =
        (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromDosOffset(importDataDirectory.VirtualAddress + importDataDirectory.Size);

    int numOfLinkedDlls = (int)importDataDirectory.Size / (int)sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1; // -1, bcs of last image_import_descriptor is zeroed.

    printf("Number of linked DLLs is %d\n\n", numOfLinkedDlls);


    DWORD old_page;
    SetIatProtection(PAGE_READWRITE, &old_page);
    HookInAllDlls("malloc", MallocDebug_malloc);
    SetIatProtection(old_page, &old_page);
    malloc(20);
    return;
}