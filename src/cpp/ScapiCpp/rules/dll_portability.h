#ifndef make_rules_dll_portability_h_defined
#define make_rules_dll_portability_h_defined

#ifdef _MSC_VER
//         extern __declspec(dllexport) int _cdecl helper();

#define  EXPORT_DLL_MEMBER  __declspec(dllexport)
#define  EXPORT_DLL_CDECL   _cdecl

#else

// the above foolishness is not needed on linux due to the architects not being idiots.
#define EXPORT_DLL_MEMBER
#define EXPORT_DLL_CDECL

#endif

#endif
