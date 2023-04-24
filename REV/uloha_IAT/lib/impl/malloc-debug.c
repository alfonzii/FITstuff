#include <stdlib.h>
#include <windows.h>

#include "..\malloc-debug.h"
#include "..\helper.h"

#define N 1024

// Old functions pointers so we can call them in hooked ones

static void* (*old_malloc)(size_t) = NULL;
static void* (*old_calloc)(size_t, size_t) = NULL;
static void* (*old_realloc)(void*, size_t) = NULL;
static void (*old_free)(void*) = NULL;


enum ProgramState {kStart, kInitialized};

typedef struct AllocLog {
    void *memblock;
    size_t size;
} AllocLog_t;

static BOOL first_run = TRUE;

// Array used for storing logs about allocations
static AllocLog_t log_arr[N];
static size_t arr_index = 0;
static enum ProgramState state = kStart;

//-------------------------------------AUXILIARY ARRAY FUNCTIONS------------------------------------

static void ClearLogArr() {
    for (int i = 0; i < N; ++i) {
        log_arr[i].memblock = NULL;
        log_arr[i].size = 0;
    }
}

static void log_arr_push(AllocLog_t log) {
    if (arr_index == N) {
        fprintf(stderr, "[log_arr_push-ERROR]: Maximum limit of allocation logs reached. "
        "Increase static global array, recompile and re-run.\n");
        exit(1);
    }
    log_arr[arr_index] = log;
    arr_index++;
}

static void log_arr_clear() {
    arr_index = 0;
}

// Return position if success. -1 if fail.
static int log_arr_find(void *memptr) {
    if (memptr == NULL)
        return -1;

    for (int i = 0; i < arr_index; ++i) {
        if (log_arr[i].memblock == memptr)
            return i;
    }
    return -1;
}

// Return TRUE if erased. FALSE if not present in array (nothing to erase).
static BOOL log_arr_erase(void *memptr) {
    int i = log_arr_find(memptr);
    if (i > -1) {
        log_arr[i].memblock = NULL;
        log_arr[i].size = 0;
        return TRUE;
    }
    return FALSE;
}

/**
 * Prints out found leaks in memory so far. Best to be called when finishing MallocDebug session,
 * eg. from MallocDebug_done() function. That way, we ensure, we print out all leaks during session.
 * 
 * @return Number of memory leaks found.
*/
static int ReportLeaks() {
    int leaks = 0;

    for (int i = 0; i < arr_index; ++i) {
        if (log_arr[i].memblock != NULL) {
            if (log_arr[i].size == -1) {
                printf("[ReportLeaks]: On address %p is leaked memory of unknown size after calloc() call "
                       "with one of arguments being zero.\n", log_arr[i].memblock);
            } else {
                // Microsoft specific printf prefix for size_t (%Iu)
                printf("[ReportLeaks]: On address %p is leaked memory of size %IuB.\n", log_arr[i].memblock, log_arr[i].size);
            }
            leaks++;
        }
    }

    if (leaks == 0) {
        printf("[ReportLeaks]: No memory leaks found! Yay!\n");
    }
    return leaks;
}

//--------------------------------------GENERAL AUX FUNCTIONS---------------------------------------

void CheckErrno(char *operation) {
    if (errno > 0) {
        printf("[CheckErrno]: Error %d (check errno constants for more details) during %s occured!!!\n", errno, operation);
        errno = 0;
    }
}


//--------------------------------------IMPLEMENTATION FUNCTIONS------------------------------------

int MallocDebug_init() {
    if (first_run) {
        ClearLogArr();
        first_run = FALSE;
    }

    if (state == kInitialized) {
        printf("[MallocDebug_init]: Invalid. Trying to initialize already initialized MallocDebug session.\n");
        return 1;
    }
    // else (state == kStart)
    log_arr_clear();

    // Prepare MallocDebug session by hooking all allocation functions
    DWORD old_page_type;
    SetIatProtection(PAGE_READWRITE, &old_page_type);
    old_malloc = HookInAllDlls("malloc", MallocDebug_malloc);
    old_calloc = HookInAllDlls("calloc", MallocDebug_calloc);
    old_realloc = HookInAllDlls("realloc", MallocDebug_realloc);
    old_free = HookInAllDlls("free", MallocDebug_free);
    SetIatProtection(old_page_type, &old_page_type);

    state = kInitialized;

    printf("[MallocDebug_init]: MallocDebug session successfully initialized.\n");

    return 0;
}

int MallocDebug_done() {
    if (state == kStart) {
        printf("[MallocDebug_done]: Invalid. Trying to finish uninitialized MallocDebug session.\n");
        return 1;
    }
    // else (state == kInitialized)
    ReportLeaks();

    DWORD old_page_type;
    SetIatProtection(PAGE_READWRITE, &old_page_type);
    HookInAllDlls("malloc", old_malloc);
    HookInAllDlls("calloc", old_calloc);
    HookInAllDlls("realloc", old_realloc);
    HookInAllDlls("free", old_free);
    SetIatProtection(old_page_type, &old_page_type);

    state = kStart;

    printf("[MallocDebug_done]: MallocDebug session successfully finished.\n");

    return 0;
}

void *MallocDebug_malloc(size_t size) {
    void *p_memblock = old_malloc(size);
    if (p_memblock == NULL) {
        printf("[MallocDebug_malloc]: Not enough memory for allocation of %IuB\n", size);
    } else {
        AllocLog_t log;
        log.memblock = p_memblock;
        log.size = size;
        log_arr_push(log);
    }
    return p_memblock;
}


void *MallocDebug_calloc(size_t number, size_t size) {

    void *p_memblock = old_calloc(number, size);

    // Not in MS documentation, but in example on calloc()
    if (p_memblock == NULL) {
        printf("[MallocDebug_calloc]: Not enough memory to allocate %Iu elements of size %IuB", number, size);
        return NULL;
    }

    size_t real_size = number * size;

    if (number == 0 || size == 0) {
        printf("[MallocDebug_calloc]: One of arguments was 0. An attempt to read or write through "
               "the returned pointer leads to undefined behavior.\n");
        real_size = -1;
    }

    CheckErrno("calloc()");

    AllocLog_t log;
    log.memblock = p_memblock;
    log.size = real_size;
    log_arr_push(log);

    return p_memblock;
}

void *MallocDebug_realloc(void *memblock, size_t size) {
    if (memblock == NULL) {
    // Realloc in such case behaves exactly as malloc
    // As we cannot call MallocDebug_malloc in this case, we have to copy code (slightly modified)
    // from malloc

    void *p_memblock = old_realloc(NULL, size);
    if (p_memblock == NULL) {
        printf("[MallocDebug_realloc]: Not enough memory for allocation of %IuB\n", size);
    } else {
        AllocLog_t log;
        log.memblock = p_memblock;
        log.size = size;
        log_arr_push(log);
    }
    return p_memblock;
    }
    // else (memblock != NULL)
    if (log_arr_find(memblock) == -1) {
        printf("[MallocDebug_realloc]: Address of memory block isn't NULL, but it isn't a pointer "
        "returned by a previous call to calloc, malloc, or realloc! Undefined behaviour can happen.\n");
    }

    // Free memory block; return NULL; memblock left to point on freed block
    if (size == 0) {
        log_arr_erase(memblock);
        return old_realloc(memblock, size);
    }
    // else (size != 0)
    void *new_memblock = old_realloc(memblock, size);
    if (new_memblock == NULL) {
        printf("[MallocDebug_realloc]: Not enough memory for reallocation of memory block on addrress %p "
               "to size %Iu.\n", memblock, size);
    }
    else {
        log_arr_erase(memblock);
        AllocLog_t log;
        log.memblock = new_memblock;
        log.size = size;
        log_arr_push(log);
    }

    CheckErrno("realloc()");

    return new_memblock;
}

void MallocDebug_free(void *memblock) {

    if (memblock == NULL) {
        old_free(memblock);
        return;
    }
    BOOL is_erased = log_arr_erase(memblock);
    if (is_erased == FALSE) {
        printf("[MallocDebug_free-ERROR]: You are trying to deallocate memory on bad address %p! " 
               "This is going to result in undefined behaviour! Expect, that subsequent "
               "allocation requests may cause errors.\n", memblock);
    }

    old_free(memblock);

    CheckErrno("free()");
}