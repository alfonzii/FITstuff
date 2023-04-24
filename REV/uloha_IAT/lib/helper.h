#include <windows.h>

#ifndef HELPER
#define HELPER

/**
 * Returns pointer to DOS header of running program
*/
PIMAGE_DOS_HEADER GetDosHeader();

/**
 * Returns pointer to PE header of running program
*/
PIMAGE_NT_HEADERS GetPeHeader();


/**
 * Returns structure from DataDirectory array in (PE) Optional header for given entry point
 * 
 * @param entry_point Index in DataDirectory array ("IMAGE_DIRECTORY_ENTRY_..." constant could be used)
*/
IMAGE_DATA_DIRECTORY GetDataDirectory(int entry_point);


/**
 * Returns pointer to absolute address calculated as offset of RVA from DOS header beginning.
 * Pointer needs to be properly casted to correct type to be used.
 * 
 * @param rva Relative Virtual Address
*/
BYTE* GetPtrFromDosOffset(DWORD rva);

/**
 * Set page/pages protecting IAT to desired type.
 * 
 * @param protection_type New type to be used for pages for IAT
 * @param old_prot_type Output parameter: Address of variable, where old type should be stored
 * 
 * @return Non-zero value if success
*/
BOOL SetIatProtection(DWORD protection_type, PDWORD old_prot_type);

/**
 * Function checks, if this pointer points into area reserved for IAT, meaning it is valid.
 * 
 * @param p_imageThunkData Pointer which is pointing into IAT on IMAGE_THUNK_DATA.
 * 
 * @return Non-zero value if success. Zero value means pointer is outside of IAT boundaries.
*/
BOOL IsIatPtrValid(PIMAGE_THUNK_DATA p_imageThunkData);

/**
 * Hooks selected imported function to new one. Function we are hooking must be present in IAT,
 * meaning it must be imported from DLL. Otherwise, hook is unable to carry out. HookDllFunction
 * hooks all occurences of selected function in imported DLLs. IAT must be set to WRITABLE prior
 * to calling this function. Otherwise, undefined behaviour must be expected.
 * 
 * @param p_importDescriptor Image import descriptor (representing DLL) in which to look for function
 * and try to hook it
 * @param *fun_name String representing name of function we want to hook
 * @param *new_fun_addr Pointer/address of new function, which will replace functionality of
 * original function after hook
 * 
 * @return On success HookDllFunction returns number of successful hooks. If 0 is returned, then
 * no function was hooked because there is no `*fun_name` present in given DLL.
 * Should an error arise, function will print error message into stderr and exit process.
 */
int HookDllFunction(PIMAGE_IMPORT_DESCRIPTOR p_importDescriptor, char *func_name, void *new_func_addr);


/**
 * Traverses all imported DLLs and hooks every occurence of `fun_name` with `new_fun_address`.
 * It's accomplished by calling HookDllFunction on every import descriptor. IAT must be set to
 * WRITABLE prior to calling this function. Otherwise, undefined behaviour is to be expected.
 * 
 * @param *fun_name String representing name of function we want to hook
 * @param *new_fun_adddress
 * 
 * @return Pointer to address of old function in memory
*/
void *HookInAllDlls(char *func_name, void *new_func_addr);


#endif