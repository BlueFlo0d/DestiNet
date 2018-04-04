#include <stdio.h>
#define DN_VERBOSE_1
#define DN_VERBOSE_2
//#define DN_VERBOSE_3
//#define DN_VERBOSE_4
//#define DN_VERBOSE_5
#define _dn_info(...) printf("[DestiNet Info]"__VA_ARGS__);fputc('\n',stdout)

#ifdef DN_VERBOSE_4
#define dn_info4(...) _dn_info(__VA_ARGS__)
#else
#define dn_info4(...)
#endif
#ifdef DN_VERBOSE_3
#define dn_info3(...) _dn_info(__VA_ARGS__)
#else
#define dn_info3(...)
#endif
#ifdef DN_VERBOSE_2
#define dn_info2(...) _dn_info(__VA_ARGS__)
#else
#define dn_info2(...)
#endif
#ifdef DN_VERBOSE_1
#define dn_info(...) _dn_info(__VA_ARGS__)
#else
#define dn_info(...)
#endif

#define dn_err(...) printf("[DestiNet Error]"__VA_ARGS__);fputc('\n',stdout)
