#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main()
{
    printf("Hello, world.\n");
    void *ptr = malloc(10);
    getc(stdin);
    free(ptr);

    HMODULE hPEFile = GetModuleHandle(NULL); // NULL znamená aktuální proces
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE *)pDosHeader) + pDosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY importDataDirectory =
        pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    IMAGE_DATA_DIRECTORY iatDataDirectory =
        pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
}