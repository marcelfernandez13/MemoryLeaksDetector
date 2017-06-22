
#ifdef MEMORY_MANAGEMENT

#include "MemoryChecker.h"

#include <assert.h>
#include <cstring>
#include <mutex>
#include <thread>

const char MAGIC[] = "magick";
const unsigned int MAX_MEM_ALLOC_ALLOWED_BYTES = 3e+9;

MemoryManager* pMemAnalyzer = nullptr;
unsigned int instanceCount = 0;
bool usingGlobalCheck = false;
std::mutex allocMutex;


struct Block
{
    size_t size;
    const char* pFile;
    char pMagic[7];
    unsigned int line;
    bool isArray;
    bool fromMalloc;
    bool tracked;
    void* handledPtr;
    Block* pPrev;
    Block* pNext;
    
    Block()
    {
        size = 0;
        pMagic[0] = '\0';
        pFile = nullptr;
        line = 0;
        isArray = false;
        fromMalloc = false;
        tracked = false;
        handledPtr = nullptr;
        pPrev = pNext = nullptr;
    }
};

class MemoryManager
{
    
public:
    
    MemoryManager(const bool aTrackUnknown, const unsigned int aMaxAllowedBytes = 0, const bool aTrackSizes = false) :
    mpHead(nullptr),
    mpTail(nullptr),
    mNumNewCalls(0),
    mNumDeleteCalls(0),
    mNumBlocks(0),
    mNumBytes(0),
    mMaxAllowedBytes(aMaxAllowedBytes),
    mMaxAllocatedBytes(0),
    mMaxBlockSize(0),
    mTrackSizes(aTrackSizes),
    mTrackUnknown(aTrackUnknown),
    mpScopeStack(nullptr),
    mpCurrentScope(nullptr)
    {
        std::memset(mAuiHistogram, 0, 32 * sizeof(size_t));
    }
    
    ~MemoryManager()
    {
        allocMutex.lock();
        
        printFinalReport();
        assert(!mpHead); // Leaks found!!!!
        
        while (mpHead != nullptr)
        {
            Block* pToDelete = mpHead;
            if (pToDelete)
            {
                mpHead = mpHead->pNext;
                free(pToDelete);
            }
        }
        
        allocMutex.unlock();
    }
    
    bool trackUnknown() const { return mTrackUnknown; }
    
    void addScope(MemBlockChecker& aScope)
    {
        if (!mpScopeStack)
        {
            mpScopeStack = &aScope;
            mpCurrentScope = mpScopeStack;
        }
        else
        {
            MemBlockChecker* pScope = mpScopeStack;
            while (pScope->mpNext)
            {
                pScope = pScope->mpNext;
            }
            
            pScope->mpNext = &aScope;
            aScope.mpPrev = pScope;
            mpCurrentScope = &aScope;
        }
    }
    
    void removeCurrentScope()
    {
        if (mpScopeStack)
        {
            assert(mpCurrentScope);
            // Last block does not report because memory summary
            // is going to be printed
            
            if (mpCurrentScope->mpPrev)
            {
                mpCurrentScope->printBlockReport();
                mpCurrentScope->mpPrev->mpNext = nullptr;
                mpCurrentScope = mpCurrentScope->mpPrev;
            }
            else
            {
                mpScopeStack = mpCurrentScope = nullptr;
            }
        }
    }
    
    void* allocate(size_t aSize, const char* apFile,
                   const unsigned int aLine, const bool aIsArray,
                   const bool aFromMalloc = false, void* apHandledPtr = nullptr)
    {
        mNumNewCalls++;
        
        // Allocate additional storage for the block header
        // information.
        size_t extendedSize = sizeof(Block) + aSize;
        char* pAddr = (char *) malloc(extendedSize);
        
        // Save the allocation information.
        Block* pBlock = (Block *) pAddr;
        pBlock->size = aSize;
        pBlock->pFile = apFile;
        pBlock->line = aLine;
        pBlock->isArray = aIsArray;
        pBlock->fromMalloc = aFromMalloc;
        pBlock->tracked = true;
        pBlock->handledPtr = apHandledPtr;
        std::strcpy(pBlock->pMagic, MAGIC);
        
        insertBlock(pBlock);
        
        // Move the pointer to the start of what the user expects
        // from ’new’.
        pAddr += sizeof(Block);
        // Keep track of the number of allocated blocks and bytes.
        mNumBlocks++;
        mNumBytes += aSize;
        if (mMaxAllowedBytes > 0
            && mNumBytes > mMaxAllowedBytes)
        {
            assert(!"The allocation has exceeded the maximum number of bytes.");
        }
        
        // Keep track of the maximum number of bytes allocated.
        if (mNumBytes > mMaxAllocatedBytes)
        {
            mMaxAllocatedBytes = mNumBytes;
        }
        // Keep track of the distribution of sizes for allocations.
        if (mTrackSizes)
        {
            // Keep track of the largest block ever allocated.
            if (aSize > mMaxBlockSize)
            {
                mMaxBlockSize = aSize;
            }
            unsigned int uiTwoPowerI = 1;
            int i;
            for (i = 0; i <= 30; i++, uiTwoPowerI <<= 1)
            {
                if (aSize <= uiTwoPowerI)
                {
                    mAuiHistogram[i]++;
                    break;
                }
            }
            if (i == 31)
            {
                mAuiHistogram[i]++;
            }
        }
        
        return (void *) pAddr;
    }
    
    void deallocate(char* apAddr, const bool aIsArray, const bool aFromMalloc = false)
    {
        if (!apAddr) return;
        
        // Move the pointer to the start of the actual allocated block.
        apAddr -= sizeof(Block);
        
        // Get the allocation information and remove the block. The removal
        // modifies only the Prev and Next pointers, so the block information is
        // accessible after the call.
        
        Block* pBlock = (Block *) apAddr;
        
        if (!pBlock->tracked)
        {
            free(pBlock);
            return;
        }
        
        if (std::strcmp(pBlock->pMagic, MAGIC) != 0) {
            apAddr += sizeof(Block);
            free(apAddr);
        }
        
        mNumDeleteCalls++;
        removeBlock(pBlock);
        
        // Check for correct pairing of new/delete or new[]/delete[].
        // If this block is non tracked memory, we avoid validation.
        assert(!pBlock->pFile || pBlock->isArray == aIsArray);
        assert(!pBlock->pFile || pBlock->fromMalloc == aFromMalloc);
        
        // Keep track of the number of allocated blocks and bytes. If the number
        // of blocks is zero at this time, a delete has been called twice on the
        // same pointer. If the number of bytes is too small at this time, some
        // internal problem has occurred within this class and needs to be
        // diagnosed.
        assert(mNumBlocks > 0 && mNumBytes >= pBlock->size);
        mNumBlocks--;
        mNumBytes -= pBlock->size;
        
        // Deallocate the memory block.
        free(apAddr);
    }
    
private:
    
    void printFinalReport()
    {
        printf("******************************************************\n");
        printf("*************** Memory Checker Report ****************\n");
        printf("******************************************************\n\n");
        
        // Total calls.
        printf("Total number of 'new' calls = %u\n", (unsigned int) mNumNewCalls);
        printf("Total number of 'delete' calls = %u\n", (unsigned int) mNumDeleteCalls);
        printf("Maximum number of allocated bytes = %u\n\n", (unsigned int) mMaxAllocatedBytes);
        
        // Remaining counts.
        printf("Remaining number of blocks = %u\n", (unsigned int) mNumBlocks);
        printf("Remaining number of bytes  = %u\n\n", ((unsigned int) mNumBlocks == 0 ? 0 : mNumBytes));
        
        // Count the blocks and bytes from known and unknown sources.
        size_t numKnownBlocks = 0;
        size_t numKnownBytes = 0;
        size_t numUnknownBlocks = 0;
        size_t numUnknownBytes = 0;
        
        Block* pBlock = mpHead;
        
        while (pBlock)
        {
            if (pBlock->pFile)
            {
                numKnownBlocks++;
                numKnownBytes += pBlock->size;
            }
            else
            {
                numUnknownBlocks++;
                numUnknownBytes += pBlock->size;
            }
            
            pBlock = pBlock->pNext;
        }
        
        printf("Remaining number of known blocks = %u\n", (unsigned int) numKnownBlocks);
        printf("Remaining number of known bytes  = %u\n\n", (unsigned int) numKnownBytes);
        printf("Remaining number of unknown blocks = %u\n", (unsigned int) numUnknownBlocks);
        printf("Remaining number of unknown bytes  = %u\n\n", (unsigned int) numUnknownBytes);
        
        // Report the information for each block.
        pBlock = mpHead;
        size_t aIndex = 0;
        
        while (pBlock)
        {
            printf("Leaked block = %u ", (unsigned int) aIndex);
            printf("size  = %u ", (unsigned int) pBlock->size);
            
            if (pBlock->pFile)
            {
                printf("file  = %s ", pBlock->pFile);
                printf("line  = %u ", pBlock->line);
            }
            else
            {
                printf("file  = unknown ");
                printf("line  = unknown ");
            }
            
            printf("array = %s \n\n", pBlock->isArray ? "yes" : "no");
            pBlock = pBlock->pNext;
            aIndex++;
        }
    }
    
    void insertBlock(Block* const apBlock)
    {
        allocMutex.lock();
        
        // New blocks are inserted at the tail of the doubly linked list.
        if (mpTail)
        {
            apBlock->pPrev = mpTail;
            apBlock->pNext = nullptr;
            mpTail->pNext = apBlock;
            mpTail = apBlock;
        }
        else
        {
            apBlock->pPrev = nullptr;
            apBlock->pNext = nullptr;
            mpHead = apBlock;
            mpTail= apBlock;
        }
        
        if (mpCurrentScope)
        {
            mpCurrentScope->addBlock(*apBlock);
        }
        
        allocMutex.unlock();
    }
    
    void removeBlock(Block* const apBlock)
    {
        allocMutex.lock();
        
        if (apBlock->pPrev)
        {
            apBlock->pPrev->pNext = apBlock->pNext;
        }
        else
        {
            mpHead = apBlock->pNext;
        }
        
        if (apBlock->pNext)
        {
            apBlock->pNext->pPrev = apBlock->pPrev;
        }
        else
        {
            mpTail = apBlock->pPrev;
        }
        
        if (mpCurrentScope)
        {
            mpCurrentScope->removeBlock(*apBlock);
        }
        
        allocMutex.unlock();
    }
    
    Block* mpHead;
    Block* mpTail;
    unsigned int mNumNewCalls;
    unsigned int mNumDeleteCalls;
    unsigned int mNumBlocks;
    unsigned int mNumBytes;
    unsigned int mMaxAllowedBytes;
    unsigned int mMaxAllocatedBytes;
    size_t mMaxBlockSize;
    size_t mAuiHistogram[32];
    bool mTrackSizes;
    bool mTrackUnknown;
    MemBlockChecker* mpScopeStack;
    MemBlockChecker* mpCurrentScope;
};


// MemBlockChecker implementation

MemBlockChecker::MemBlockChecker(const char* apFile, const unsigned int aLine, const bool aTrackUnknown)
{
    if (usingGlobalCheck) return;
    
    if (!pMemAnalyzer)
    {
        MemoryManager* pManager = (MemoryManager *) malloc(sizeof(MemoryManager));
        pMemAnalyzer = ::new(pManager) MemoryManager(aTrackUnknown);
    }
    
    assert(pMemAnalyzer);
    mpFile = apFile;
    mLine = aLine;
    mpBlocks = nullptr;
    mpNext = nullptr;
    mpPrev = nullptr;
    
    instanceCount++;
    mpManager = pMemAnalyzer;
    mpManager->addScope(*this);
}

MemBlockChecker::~MemBlockChecker()
{
    if (usingGlobalCheck) return;
    
    mpManager->removeCurrentScope();
    
    while (mpBlocks)
    {
        Block* pToDelete = mpBlocks;
        if (pToDelete)
        {
            mpBlocks = mpBlocks->pNext;
            free(pToDelete);
        }
    }
    
    instanceCount--;
    if (instanceCount == 0)
    {
        pMemAnalyzer->~MemoryManager();
        free(pMemAnalyzer);
        pMemAnalyzer = nullptr;
    }
}

// Static
void MemBlockChecker::initGlobalCheck(const bool aTrackUnknown)
{
    if (!pMemAnalyzer)
    {
        MemoryManager* pManager = (MemoryManager *) malloc(sizeof(MemoryManager));
        pMemAnalyzer = ::new(pManager) MemoryManager(aTrackUnknown);
        usingGlobalCheck = true;
    }
}

// Static
void MemBlockChecker::destroyGlobalCheck()
{
    if (pMemAnalyzer && usingGlobalCheck)
    {
        pMemAnalyzer->~MemoryManager();
        free(pMemAnalyzer);
        pMemAnalyzer = nullptr;
        usingGlobalCheck = false;
    }
}

void MemBlockChecker::addBlock(const Block& aBlock)
{
    Block* const pNewBlock = (Block *) malloc(sizeof(Block));
    pNewBlock->pNext = pNewBlock->pPrev = nullptr;
    
    pNewBlock->isArray = aBlock.isArray;
    pNewBlock->line = aBlock.line;
    pNewBlock->fromMalloc = aBlock.fromMalloc;
    pNewBlock->pFile = aBlock.pFile;
    pNewBlock->size = aBlock.size;
    
    if (!mpBlocks)
    {
        mpBlocks = pNewBlock;
    }
    else
    {
        Block* pAux = mpBlocks;
        
        while (pAux->pNext)
        {
            pAux = pAux->pNext;
        }
        
        pNewBlock->pPrev = pAux;
        pAux->pNext = pNewBlock;
    }
}

void MemBlockChecker::removeBlock(const Block& aBlock)
{
    if (mpBlocks)
    {
        Block* pAux = mpBlocks;
        while (pAux)
        {
            if (pAux->pFile && aBlock.pFile &&
                (std::strcmp(pAux->pFile, aBlock.pFile) == 0 && pAux->line == aBlock.line))
            {
                if (pAux->pPrev)
                {
                    pAux->pPrev->pNext = pAux->pNext;
                }
                
                if (pAux->pNext)
                {
                    pAux->pNext->pPrev = pAux->pPrev;
                }
                
                if (pAux == mpBlocks)
                {
                    mpBlocks = pAux->pNext;
                }
                
                free(pAux);
                return;
            }
            
            pAux = pAux->pNext;
        }
    }
}

void MemBlockChecker::printBlockReport() const
{
    if (!mpBlocks) return;
    
    printf("******************************************************\n");
    printf("Scope Report:\n");
    printf("File: %s\n", mpFile);
    printf("Line: %u\n\n", mLine);
    
    Block* pAux = mpBlocks;
    
    while (pAux)
    {
        printf("Leaked block: ");
        printf("size  = %u ", (unsigned int) pAux->size);
        
        if (pAux->pFile)
        {
            printf("file  = %s ", pAux->pFile);
            printf("line  = %u ", pAux->line);
        }
        else
        {
            printf("file  = unknown ");
            printf("line  = unknown ");
        }
        
        printf("array = %s\n", pAux->isArray ? "yes" : "no");
        
        pAux = pAux->pNext;
    }
    
    printf("\n******************************************************\n\n");
}

void* operator new(const size_t aSize)
{
    void* ptr = nullptr;
    
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES)
    {
        if (pMemAnalyzer && pMemAnalyzer->trackUnknown())
        {
            ptr = pMemAnalyzer->allocate(aSize, nullptr, 0, false);
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = nullptr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            ptr = pAuxPtr + blockSize;
        }
    }
    
    
    if (!ptr)
    {
        assert(!"Size not allowed");
        throw std::bad_alloc();
    }
    
    return ptr;
}

void* operator new[](const size_t aSize)
{
    void* ptr = nullptr;
    
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES)
    {
        if (pMemAnalyzer && pMemAnalyzer->trackUnknown())
        {
            ptr = pMemAnalyzer->allocate(aSize, nullptr, 0, true);
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = nullptr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            ptr = pAuxPtr + blockSize;
        }
    }
    
    if (!ptr)
    {
        assert(!"Size not allowed");
        throw std::bad_alloc();
    }
    
    return ptr;
}

void operator delete(void* const apAddr)
{
    if (!apAddr) return;
    
    if (pMemAnalyzer)
    {
        pMemAnalyzer->deallocate((char *) apAddr, false);
    }
    else
    {
        char* pAuxPtr = (char *) apAddr;
        Block* pBlock = (Block *) (pAuxPtr - sizeof(Block));
        // This address was allocated here
        if (std::strcmp(pBlock->pMagic, MAGIC) == 0)
        {
            free(pBlock);
        }
        else
        {
            free(apAddr);
        }
    }
}

void operator delete[](void* const apAddr)
{
    if (!apAddr) return;
    
    if (pMemAnalyzer)
    {
        pMemAnalyzer->deallocate((char *) apAddr, true);
    }
    else
    {
        char* pAuxPtr = (char *) apAddr;
        Block* pBlock = (Block *) (pAuxPtr - sizeof(Block));
        // This address was allocated here
        if (std::strcmp(pBlock->pMagic, MAGIC) == 0)
        {
            free(pBlock);
        }
        else
        {
            free(apAddr);
        }
    }
}

void* operator new(const size_t aSize, const char* apFile, const unsigned int aLine)
{
    void* ptr = nullptr;
    
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES)
    {
        if (pMemAnalyzer)
        {
            ptr = pMemAnalyzer->allocate(aSize, apFile, aLine, false);
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = nullptr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            ptr = pAuxPtr + blockSize;
        }
    }
    
    if (!ptr)
    {
        assert(!"Size not allowed");
        throw std::bad_alloc();
    }
    
    return ptr;
}

void* operator new[](const size_t aSize, const char* apFile, const unsigned int aLine)
{
    void* ptr = nullptr;
    
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES)
    {
        if (pMemAnalyzer)
        {
            ptr = pMemAnalyzer->allocate(aSize, apFile, aLine, true);
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = nullptr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            ptr = pAuxPtr + blockSize;
        }
    }
    
    if (!ptr)
    {
        assert(!"Size not allowed");
        throw std::bad_alloc();
    }
    
    return ptr;
}

void operator delete(void* const apAddr, const char* apFile, const unsigned int aLine)
{
    if (!apAddr) return;
    
    if (pMemAnalyzer)
    {
        pMemAnalyzer->deallocate((char *) apAddr, false);
    }
    else
    {
        char* pAuxPtr = (char *) apAddr;
        Block* pBlock = (Block *) (pAuxPtr - sizeof(Block));
        // This address was allocated here
        if (std::strcmp(pBlock->pMagic, MAGIC) == 0)
        {
            free(pBlock);
        }
        else
        {
            free(apAddr);
        }
    }
}

void operator delete[](void* const apAddr, const char* apFile, const unsigned int aLine)
{
    if (!apAddr) return;
    
    if (pMemAnalyzer)
    {
        pMemAnalyzer->deallocate((char *) apAddr, true);
    }
    else
    {
        char* pAuxPtr = (char *) apAddr;
        Block* pBlock = (Block *) (pAuxPtr - sizeof(Block));
        // This address was allocated here
        if (std::strcmp(pBlock->pMagic, MAGIC) == 0)
        {
            free(pBlock);
        }
        else
        {
            free(apAddr);
        }
    }
}

void* chk_malloc(const size_t aSize, const char* apFile, const unsigned int aLine, void* apHandledPtr)
{
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES)
    {
        if (pMemAnalyzer)
        {
            return pMemAnalyzer->allocate(aSize, apFile, aLine, false, true, apHandledPtr);
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = apHandledPtr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            
            return pAuxPtr + blockSize;
        }
    }
    
    assert(!"Size not allowed");
    
    return nullptr;
}

void* chk_calloc(const size_t aNum, const size_t aSize, const char* apFile, unsigned int aLine)
{
    if (aSize > 0 && aSize <= MAX_MEM_ALLOC_ALLOWED_BYTES) {
        if (pMemAnalyzer)
        {
            void* ptr = pMemAnalyzer->allocate(aNum * aSize, apFile, aLine, false, true);
            std::memset(ptr, 0, aNum * aSize);
            return ptr;
        }
        else
        {
            const unsigned int blockSize = sizeof(Block);
            char* pAuxPtr = (char *) malloc(aNum * aSize + blockSize);
            Block* pBlock = (Block *)pAuxPtr;
            pBlock->size = aSize;
            pBlock->isArray = false;
            pBlock->fromMalloc = false;
            pBlock->tracked = false;
            pBlock->handledPtr = nullptr;
            pBlock->pNext = pBlock->pPrev = nullptr;
            std::strcpy(pBlock->pMagic, MAGIC);
            void* ptr = pAuxPtr + blockSize;
            std::memset(ptr, 0, aNum * aSize);
            
            return ptr;
        }
    }
    
    assert(!"Size not allowed");
    
    return nullptr;
}

void chk_free(void* const apAddr)
{
    if (pMemAnalyzer)
    {
        pMemAnalyzer->deallocate((char *) apAddr, false, true);
    }
    else
    {
        char* pAuxPtr = (char *) apAddr;
        Block* pBlock = (Block *) (pAuxPtr - sizeof(Block));
        // This address was allocated here
        if (std::strcmp(pBlock->pMagic, MAGIC) == 0)
        {
            free(pBlock);
        }
        else
        {
            free(apAddr);
        }
    }
}

void* chk_handle_ptr(void* apAddr, size_t aSize, const char* apFile, const unsigned int aLine)
{
    void* ptr = chk_malloc(aSize, apFile, aLine, apAddr);
    std::memcpy(ptr, apAddr, aSize);
    return ptr;
}

void* chk_release_handled_ptr(void* apAddr)
{
    char* ptr = (char *) apAddr;
    Block* pBlock = (Block *) (ptr - sizeof(Block));
    void* pHandledPtr = pBlock->handledPtr;
    chk_free(apAddr);
    
    return pHandledPtr;
}

#endif
