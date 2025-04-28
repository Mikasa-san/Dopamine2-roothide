#ifndef ZSTD_ERRORS_H_398273423
#define ZSTD_ERRORS_H_398273423

#if defined (__cplusplus)
extern "C" {
#endif

#include <stddef.h>   

#ifndef ZSTDERRORLIB_VISIBLE

#  ifdef ZSTDERRORLIB_VISIBILITY
#    define ZSTDERRORLIB_VISIBLE ZSTDERRORLIB_VISIBILITY
#  elif defined(__GNUC__) && (__GNUC__ >= 4) && !defined(__MINGW32__)
#    define ZSTDERRORLIB_VISIBLE __attribute__ ((visibility ("default")))
#  else
#    define ZSTDERRORLIB_VISIBLE
#  endif
#endif

#ifndef ZSTDERRORLIB_HIDDEN
#  if defined(__GNUC__) && (__GNUC__ >= 4) && !defined(__MINGW32__)
#    define ZSTDERRORLIB_HIDDEN __attribute__ ((visibility ("hidden")))
#  else
#    define ZSTDERRORLIB_HIDDEN
#  endif
#endif

#if defined(ZSTD_DLL_EXPORT) && (ZSTD_DLL_EXPORT==1)
#  define ZSTDERRORLIB_API __declspec(dllexport) ZSTDERRORLIB_VISIBLE
#elif defined(ZSTD_DLL_IMPORT) && (ZSTD_DLL_IMPORT==1)
#  define ZSTDERRORLIB_API __declspec(dllimport) ZSTDERRORLIB_VISIBLE 
#else
#  define ZSTDERRORLIB_API ZSTDERRORLIB_VISIBLE
#endif

typedef enum {
  ZSTD_error_no_error = 0,
  ZSTD_error_GENERIC  = 1,
  ZSTD_error_prefix_unknown                = 10,
  ZSTD_error_version_unsupported           = 12,
  ZSTD_error_frameParameter_unsupported    = 14,
  ZSTD_error_frameParameter_windowTooLarge = 16,
  ZSTD_error_corruption_detected = 20,
  ZSTD_error_checksum_wrong      = 22,
  ZSTD_error_literals_headerWrong = 24,
  ZSTD_error_dictionary_corrupted      = 30,
  ZSTD_error_dictionary_wrong          = 32,
  ZSTD_error_dictionaryCreation_failed = 34,
  ZSTD_error_parameter_unsupported   = 40,
  ZSTD_error_parameter_combination_unsupported = 41,
  ZSTD_error_parameter_outOfBound    = 42,
  ZSTD_error_tableLog_tooLarge       = 44,
  ZSTD_error_maxSymbolValue_tooLarge = 46,
  ZSTD_error_maxSymbolValue_tooSmall = 48,
  ZSTD_error_stabilityCondition_notRespected = 50,
  ZSTD_error_stage_wrong       = 60,
  ZSTD_error_init_missing      = 62,
  ZSTD_error_memory_allocation = 64,
  ZSTD_error_workSpace_tooSmall= 66,
  ZSTD_error_dstSize_tooSmall = 70,
  ZSTD_error_srcSize_wrong    = 72,
  ZSTD_error_dstBuffer_null   = 74,
  ZSTD_error_noForwardProgress_destFull = 80,
  ZSTD_error_noForwardProgress_inputEmpty = 82,

  ZSTD_error_frameIndex_tooLarge = 100,
  ZSTD_error_seekableIO          = 102,
  ZSTD_error_dstBuffer_wrong     = 104,
  ZSTD_error_srcBuffer_wrong     = 105,
  ZSTD_error_sequenceProducer_failed = 106,
  ZSTD_error_externalSequences_invalid = 107,
  ZSTD_error_maxCode = 120  
} ZSTD_ErrorCode;

ZSTDERRORLIB_API ZSTD_ErrorCode ZSTD_getErrorCode(size_t functionResult);
ZSTDERRORLIB_API const char* ZSTD_getErrorString(ZSTD_ErrorCode code);   

#if defined (__cplusplus)
}
#endif

#endif 