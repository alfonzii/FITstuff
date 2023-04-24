# 2. Import Address Table

Your program compiled with MS Visual Studio typically depends on an external runtime library such as `MSVCRT12.DLL` (the version in the name may vary according to the compiler version, this name applies to Visual Studio 2013). This library contains functions `malloc`, `calloc`, `realloc`, and `free`. Write a program which will contain functions:

* `MallocDebug_Init`
* `MallocDebug_Done`
* `MallocDebug_malloc`
* `MallocDebug_calloc`
* `MallocDebug_realloc`
* `MallocDebug_free`

The `MallocDebug_Init` function will find the IAT position of the `malloc`, `calloc`, `realloc`, and `free` functions and change (= patch) their addresses in the IAT to the addresses of `MallocDebug_malloc`, `MallocDebug_calloc`, `MallocDebug_realloc`, and `MallocDebug_free` respectively (the so-called substitution functions).

These substitution functions will, in the course of their execution, create a record of the operation and its parameters (use a static global array of a fixed size, don't worry about multithreading support or dynamic allocation) on allocation and look up and remove (and complain if this failed) the record on deallocation. They will also call the original function to actually perform the requested operation; note that in these calls you can't use e.g. `malloc` directly, you need to call a function pointer which you had saved during `MallocDebug_Init`. This will provide us with an ability to log memory allocation/deallocation operations.

The `MallocDebug_Done` function will reset the IAT to its original state and report any non-freed memory blocks. Make sure to verify that these leaked blocks are reported correctly (e.g. by creating an intentional memory leak).

## Solutions of Common Issues

### IMPORTANT
If your compiled binary uses an embedded (static) runtime library rather than a dynamically loaded one, you won't be able to finish the homework. In that case you can use the `/MD` argument which will force the compiler to use the runtime in a shared library. Use CFF Explorer to verify that your application is importing memory functions from a DLL!


### TIP
*Writing into the IAT*
IAT is usually write-protected. In order to be able to write into it, you must use e.g. the link:https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898(v=vs.85).aspx[VirtualProtect] API to unlock the page for writing.

```
BOOL WINAPI VirtualProtect (
  (LPVOID) lpAddress,   // an address in a block to change memory protection for
  (size_t) dwSize,      // size of the block
  PAGE_READWRITE,       // memory protection flags
  (PDWORD)&dwOldProtect // old protection value
);
```


## Common Errors

### NOTE
When processing the import directory, you don't need to support any other thunks than pointers to `IMAGE_IMPORT_BY_NAME`, but aside from that your code should be compatible with any import directory, including a malformed one. It's perfectly legitimate to emit a warning that the import directory is damaged and the application will terminate, but it's not acceptable if you simply crash on a memory access which you could have detected as incorrect by strictly following PE specifications.

### NOTE
It's quite normal that an application imports one library multiple times. It can even import the same function multiple times! Your solution should be able to handle such a case.

### IMPORTANT
It is *not* the purpose of this task to write a new memory manager. Quite the opposite, in fact -- we are modelling an attempt to monitor a program's behavior in a specific area, and it rather defeats the purpose if we drastically change the area. Your implementation should simply store the necessary logging data and then (or before that) call the original versions of the memory management functions.

### NOTE
Your implementation should adhere to the specification of the substituted functions. Study their documentation and make sure your solution works correctly for all boundary cases (and all use cases) the memory functions can reach. A common error even in otherwise nice solutions is that the student did not properly handle all possible uses of memory functions -- `realloc` in particular has a lot of different uses.

### NOTE
Make sure your code works fine even if the `MallocDebug_Init` and `MallocDebug_Done` functions are called multiple times and in any order.
