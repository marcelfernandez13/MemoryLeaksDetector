#ifndef _MEMORY_CHECKER_H_
#define _MEMORY_CHECKER_H_

#ifdef MEMORY_MANAGEMENT

#include <stdio.h>

class Block;
class MemoryManager;
        
class MemBlockChecker
{
    
private:
    const char* mpFile;
    unsigned int mLine;
    Block* mpBlocks;
    MemoryManager* mpManager;
            
public:
    
    static void initGlobalCheck(bool aTrackUnknown = false);
    static void destroyGlobalCheck();
            
    MemBlockChecker* mpNext;
    MemBlockChecker* mpPrev;
            
    MemBlockChecker(const char* apFile, unsigned int aLine, bool aTrackUnknown);
    ~MemBlockChecker();
            
    void addBlock(const Block& aBlock);
    void removeBlock(const Block& aBlock);
    void printBlockReport() const;
};

#define checkScopeMemory() MemBlockChecker __mem_check__(__FILE__, __LINE__, false); (void)__mem_check__;

#define checkGlobalMemory() MemBlockChecker::initGlobalCheck()
#define finishGlobalMemoryCheck() MemBlockChecker::destroyGlobalCheck()

#define chkNew new(__FILE__,__LINE__)
#define chkDelete delete
#define chkMalloc(size) chk_malloc(size,__FILE__,__LINE__)
#define chkCalloc(num,size) chk_calloc(num,size,__FILE__,__LINE__)
#define chkFree chk_free

void* operator new(size_t aSize);
void* operator new[] (size_t aSize);

void* operator new(size_t aSize, const char* apFile, unsigned int aLine);
void* operator new[] (size_t aSize, const char* apFile, unsigned int aLine);

#ifdef WIN32
void operator delete(void* apAddr);
void operator delete[] (void* apAddr);
#else
void operator delete(void* apAddr) noexcept;
void operator delete[] (void* apAddr) noexcept;
#endif

void operator delete(void* apAddr, const char* apFile, unsigned int aLine);
void operator delete[](void* apAddr, const char* apFile, unsigned int aLine);

void* chk_malloc(size_t aSize, const char* apFile, unsigned int aLine, void* apHandledPtr = nullptr);
void* chk_calloc(size_t aNum, size_t aSize, const char* apFile, unsigned int aLine);
void  chk_free(void* apAddr);

void* chk_handle_ptr(void* apAddr, size_t aSize, const char* apFile, unsigned int aLine);
void* chk_release_handled_ptr(void* apAddr);

#else

#define checkScopeMemory() (void)0
#define checkGlobalMemory() (void)0
#define finishGlobalMemoryCheck() (void)0

#define chkNew new
#define chkDelete delete
#define chkMalloc malloc
#define chkCalloc calloc
#define chkFree free

#endif // MEMORY_MANAGEMENT

#endif // _MEMORY_CHECKER_H_
