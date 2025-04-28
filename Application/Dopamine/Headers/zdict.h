#if defined (__cplusplus)
extern "C" {
#endif

#ifndef ZSTD_ZDICT_H
#define ZSTD_ZDICT_H

#include <stddef.h>  

#ifndef ZDICTLIB_VISIBLE

#  ifdef ZDICTLIB_VISIBILITY
#    define ZDICTLIB_VISIBLE ZDICTLIB_VISIBILITY
#  elif defined(__GNUC__) && (__GNUC__ >= 4) && !defined(__MINGW32__)
#    define ZDICTLIB_VISIBLE __attribute__ ((visibility ("default")))
#  else
#    define ZDICTLIB_VISIBLE
#  endif
#endif

#ifndef ZDICTLIB_HIDDEN
#  if defined(__GNUC__) && (__GNUC__ >= 4) && !defined(__MINGW32__)
#    define ZDICTLIB_HIDDEN __attribute__ ((visibility ("hidden")))
#  else
#    define ZDICTLIB_HIDDEN
#  endif
#endif

#if defined(ZSTD_DLL_EXPORT) && (ZSTD_DLL_EXPORT==1)
#  define ZDICTLIB_API __declspec(dllexport) ZDICTLIB_VISIBLE
#elif defined(ZSTD_DLL_IMPORT) && (ZSTD_DLL_IMPORT==1)
#  define ZDICTLIB_API __declspec(dllimport) ZDICTLIB_VISIBLE 
#else
#  define ZDICTLIB_API ZDICTLIB_VISIBLE
#endif

ZDICTLIB_API size_t ZDICT_trainFromBuffer(void* dictBuffer, size_t dictBufferCapacity,
                                    const void* samplesBuffer,
                                    const size_t* samplesSizes, unsigned nbSamples);

typedef struct {
    int      compressionLevel;   
    unsigned notificationLevel;  
    unsigned dictID;             
} ZDICT_params_t;

ZDICTLIB_API size_t ZDICT_finalizeDictionary(void* dstDictBuffer, size_t maxDictSize,
                                const void* dictContent, size_t dictContentSize,
                                const void* samplesBuffer, const size_t* samplesSizes, unsigned nbSamples,
                                ZDICT_params_t parameters);

ZDICTLIB_API unsigned ZDICT_getDictID(const void* dictBuffer, size_t dictSize);  
ZDICTLIB_API size_t ZDICT_getDictHeaderSize(const void* dictBuffer, size_t dictSize);  
ZDICTLIB_API unsigned ZDICT_isError(size_t errorCode);
ZDICTLIB_API const char* ZDICT_getErrorName(size_t errorCode);

#endif   

#if defined(ZDICT_STATIC_LINKING_ONLY) && !defined(ZSTD_ZDICT_H_STATIC)
#define ZSTD_ZDICT_H_STATIC

#ifndef ZDICTLIB_STATIC_API
#  if defined(ZSTD_DLL_EXPORT) && (ZSTD_DLL_EXPORT==1)
#    define ZDICTLIB_STATIC_API __declspec(dllexport) ZDICTLIB_VISIBLE
#  elif defined(ZSTD_DLL_IMPORT) && (ZSTD_DLL_IMPORT==1)
#    define ZDICTLIB_STATIC_API __declspec(dllimport) ZDICTLIB_VISIBLE
#  else
#    define ZDICTLIB_STATIC_API ZDICTLIB_VISIBLE
#  endif
#endif

#define ZDICT_DICTSIZE_MIN    256

#define ZDICT_CONTENTSIZE_MIN 128

typedef struct {
    unsigned k;                  
    unsigned d;                  
    unsigned steps;              
    unsigned nbThreads;          
    double splitPoint;           
    unsigned shrinkDict;         
    unsigned shrinkDictMaxRegression; 
    ZDICT_params_t zParams;
} ZDICT_cover_params_t;

typedef struct {
    unsigned k;                  
    unsigned d;                  
    unsigned f;                  
    unsigned steps;              
    unsigned nbThreads;          
    double splitPoint;           
    unsigned accel;              
    unsigned shrinkDict;         
    unsigned shrinkDictMaxRegression; 

    ZDICT_params_t zParams;
} ZDICT_fastCover_params_t;

ZDICTLIB_STATIC_API size_t ZDICT_trainFromBuffer_cover(
          void *dictBuffer, size_t dictBufferCapacity,
    const void *samplesBuffer, const size_t *samplesSizes, unsigned nbSamples,
          ZDICT_cover_params_t parameters);

ZDICTLIB_STATIC_API size_t ZDICT_optimizeTrainFromBuffer_cover(
          void* dictBuffer, size_t dictBufferCapacity,
    const void* samplesBuffer, const size_t* samplesSizes, unsigned nbSamples,
          ZDICT_cover_params_t* parameters);

ZDICTLIB_STATIC_API size_t ZDICT_trainFromBuffer_fastCover(void *dictBuffer,
                    size_t dictBufferCapacity, const void *samplesBuffer,
                    const size_t *samplesSizes, unsigned nbSamples,
                    ZDICT_fastCover_params_t parameters);

ZDICTLIB_STATIC_API size_t ZDICT_optimizeTrainFromBuffer_fastCover(void* dictBuffer,
                    size_t dictBufferCapacity, const void* samplesBuffer,
                    const size_t* samplesSizes, unsigned nbSamples,
                    ZDICT_fastCover_params_t* parameters);

typedef struct {
    unsigned selectivityLevel;   
    ZDICT_params_t zParams;
} ZDICT_legacy_params_t;

ZDICTLIB_STATIC_API size_t ZDICT_trainFromBuffer_legacy(
    void* dictBuffer, size_t dictBufferCapacity,
    const void* samplesBuffer, const size_t* samplesSizes, unsigned nbSamples,
    ZDICT_legacy_params_t parameters);

#ifdef ZDICT_DISABLE_DEPRECATE_WARNINGS
#  define ZDICT_DEPRECATED(message) 
#else
#  define ZDICT_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)
#  if defined (__cplusplus) && (__cplusplus >= 201402) 
#    define ZDICT_DEPRECATED(message) [[deprecated(message)]]
#  elif defined(__clang__) || (ZDICT_GCC_VERSION >= 405)
#    define ZDICT_DEPRECATED(message) __attribute__((deprecated(message)))
#  elif (ZDICT_GCC_VERSION >= 301)
#    define ZDICT_DEPRECATED(message) __attribute__((deprecated))
#  elif defined(_MSC_VER)
#    define ZDICT_DEPRECATED(message) __declspec(deprecated(message))
#  else
#    pragma message("WARNING: You need to implement ZDICT_DEPRECATED for this compiler")
#    define ZDICT_DEPRECATED(message)
#  endif
#endif 

ZDICT_DEPRECATED("use ZDICT_finalizeDictionary() instead")
ZDICTLIB_STATIC_API
size_t ZDICT_addEntropyTablesFromBuffer(void* dictBuffer, size_t dictContentSize, size_t dictBufferCapacity,
                                  const void* samplesBuffer, const size_t* samplesSizes, unsigned nbSamples);

#endif   

#if defined (__cplusplus)
}
#endif