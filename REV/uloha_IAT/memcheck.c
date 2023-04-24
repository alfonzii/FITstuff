#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "lib\debug-tests.h"
#include "lib\malloc-debug.h"
#include "lib\helper.h"

int main()
{

    printf("Hello, world.\n");

    size_t k = -1;

    void *p = realloc(NULL, 0);

    MallocDebug_init();

    void *ptr = malloc(10);
    printf("ptr: %p\n", ptr);

    void *ptr2 = realloc(NULL, 10);
    
    malloc(30);
    free(NULL);
    free(ptr2);
    printf("ptr2: %p\n", ptr2);
    free(ptr);

    realloc(NULL, 30);
    realloc(NULL, 30);
    realloc(NULL, 30);

    MallocDebug_done();

    MallocDebug_done();

    ptr = malloc(40);
    ptr2 = malloc(128);

    malloc(100);
    free(ptr);
    free(ptr2);



    MallocDebug_init();

    ptr = malloc(50);
    free(ptr);
    malloc(20);
    ptr2 = calloc(0, 16);
    //free(ptr);

    MallocDebug_init();
    MallocDebug_done();
    

   MallocDebug_init();

   long *buffer, *oldbuffer;
   size_t size;

   if( (buffer = (long *)malloc( 1000 * sizeof( long ) )) == NULL )
      exit( 1 );

   size = _msize( buffer );
   printf_s( "Size of block after malloc of 1000 longs: %u\n", size );

   // Reallocate and show new size:
   oldbuffer = buffer;     // save pointer in case realloc fails
   if( (buffer = realloc( buffer, size + (1000 * sizeof( long )) ))
        ==  NULL )
   {
      free( oldbuffer );  // free original block
      exit( 1 );
   }
   size = _msize( buffer );
   printf_s( "Size of block after realloc of 1000 more longs: %u\n",
            size );

    malloc(-4);

   long *new_buffer = realloc(buffer, -5);
   free( buffer );
   free( new_buffer );

   MallocDebug_done();

    //TestHook();
}



