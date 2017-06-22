//
//  main.cpp
//  CPlusPlusPlayground
//
//  Created by Marcel Fernandez (marcelfernandez13@gmail.com) on 8/15/16.
//

#include "MemoryChecker.h"
#include <iostream>

int main(int argc, const char * argv[]) {
    checkScopeMemory();
    
    
    int* i = chkNew int;
    *i = 113;
    chkDelete i;
    
    char* buffer = (char *) chkMalloc(100);
    chkFree(buffer);
    
    int *array = chkNew int[100];
    array[50] = 113;
    chkDelete[] array;
    
    float* toHandle = new float;
    *toHandle = 3.14;
    
    float* handledPtr = (float *) chk_handle_ptr(toHandle, sizeof(float), __FILE__, __LINE__);
    // Some work with handledPtr
    // ...
    //
    printf("the handledPtr value is %0.2f\n\n", *handledPtr);
    chk_release_handled_ptr(handledPtr);
    
    // If you use chk_handle_ptr and chk_release_handled_ptr don't forget to delete "toHandle".
    // This function is to add a preallocated pointer to the memory control. but when you call
    // chk_release_handled_ptr, you must be responsable for the deallocation of the original pointer.
    
    delete toHandle;
    
    return 0;
}
