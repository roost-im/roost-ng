# pylint: skip-file
import cffi

ffibuilder = cffi.FFI()

ffibuilder.cdef("""
typedef int Code_t;
typedef struct _znotice_t {...;} ZNotice_t;
typedef Code_t (*Z_AuthProc)(ZNotice_t*, char *, int, int *);
typedef char ZPacket_t[...];
typedef struct _ZAsyncLocateData_t {...;} ZAsyncLocateData_t;
typedef enum {...} ZNotice_Kind_t;
typedef struct _ZUnique_Id_t {...;} ZUnique_Id_t;
typedef struct _ZSubscriptions_t {...;} ZSubscription_t;
typedef struct _ZLocations_t {...;} ZLocations_t;

char *ZGetSender(void);
char *ZGetVariable(char *);
Code_t ZSetVariable(char *var, char *value);
Code_t ZUnsetVariable(char *var);
int ZGetWGPort(void);
Code_t ZSetDestAddr(struct sockaddr_in *);
Code_t ZParseNotice(char*, int, ZNotice_t *);
Code_t ZReadAscii(char*, int, unsigned char*, int);
Code_t ZReadAscii32(char *, int, unsigned long *);
Code_t ZReadAscii16(char *, int, unsigned short *);
Code_t ZReadZcode(unsigned char*, unsigned char*, int, int *);
Code_t ZSendPacket(char*, int, int);
Code_t ZSendList(ZNotice_t*, char *[], int, Z_AuthProc);
Code_t ZSrvSendList(ZNotice_t*, char*[], int, Z_AuthProc,
                    Code_t (*)(ZNotice_t *, char *, int, int));
Code_t ZSendRawList(ZNotice_t*, char *[], int);
Code_t ZSendNotice(ZNotice_t *, Z_AuthProc);
Code_t ZSendRawNotice(ZNotice_t *);
Code_t ZSrvSendNotice(ZNotice_t*, Z_AuthProc,
                      Code_t (*)(ZNotice_t *, char *, int, int));
Code_t ZFormatNotice(ZNotice_t*, char**, int*, Z_AuthProc);
Code_t ZNewFormatNotice(ZNotice_t*, char**, int*, Z_AuthProc);
Code_t ZFormatNoticeList(ZNotice_t*, char**, int,
                         char **, int*, Z_AuthProc);
Code_t ZFormatRawNoticeList(ZNotice_t *, char *[], int, char **, int *);
// Code_t ZFormatSmallNotice(ZNotice_t*, ZPacket_t, int*, Z_AuthProc);
Code_t ZFormatSmallRawNotice(ZNotice_t *, ZPacket_t, int *);
Code_t ZNewFormatSmallRawNotice(ZNotice_t *, ZPacket_t, int *);
Code_t ZFormatSmallRawNoticeList(ZNotice_t *, char *[], int, ZPacket_t, int *);
Code_t ZLocateUser(char *, int *, Z_AuthProc);
Code_t ZRequestLocations(char *, ZAsyncLocateData_t *,
                         ZNotice_Kind_t, Z_AuthProc);
Code_t ZhmStat(struct in_addr *, ZNotice_t *);
Code_t ZInitialize(void);
Code_t ZSetServerState(int);
Code_t ZSetFD(int);
int ZCompareUID(ZUnique_Id_t*, ZUnique_Id_t*);
Code_t ZSrvSendRawList(ZNotice_t*, char*[], int,
                       Code_t (*)(ZNotice_t *, char *, int, int));
Code_t ZMakeAscii(char*, int, unsigned char*, int);
Code_t ZMakeAscii32(char *, int, unsigned long);
Code_t ZMakeAscii16(char *, int, unsigned int);
Code_t ZMakeZcode(char*, int, unsigned char*, int);
Code_t ZMakeZcode32(char *, int, unsigned long);
Code_t ZReceivePacket(ZPacket_t, int*, struct sockaddr_in*);
Code_t ZCheckAuthentication(ZNotice_t*, struct sockaddr_in*);
Code_t ZCheckZcodeAuthentication(ZNotice_t*, struct sockaddr_in*);
// Code_t ZCheckZcodeRealmAuthentication(ZNotice_t*, struct sockaddr_in*, char *realm);
Code_t ZInitLocationInfo(char *hostname, char *tty);
Code_t ZSetLocation(char *exposure);
Code_t ZUnsetLocation(void);
Code_t ZFlushMyLocations(void);
Code_t ZFlushUserLocations(char *);
char *ZParseExposureLevel(char *text);
Code_t ZFormatRawNotice(ZNotice_t *, char**, int *);
Code_t ZRetrieveSubscriptions(unsigned short, int*);
Code_t ZRetrieveDefaultSubscriptions(int *);
Code_t ZGetSubscriptions(ZSubscription_t *, int *);
Code_t ZOpenPort(unsigned short *port);
Code_t ZClosePort(void);
Code_t ZFlushLocations(void);
Code_t ZFlushSubscriptions(void);
Code_t ZFreeNotice(ZNotice_t *notice);
Code_t ZGetLocations(ZLocations_t *, int *);
Code_t ZParseLocations(register ZNotice_t *notice,
                       register ZAsyncLocateData_t *zald, int *nlocs,
                       char **user);
int ZCompareALDPred(ZNotice_t *notice, void *zald);
void ZFreeALD(register ZAsyncLocateData_t *zald);
Code_t ZCheckIfNotice(ZNotice_t *notice, struct sockaddr_in *from,
                      register int (*predicate)(ZNotice_t *,void *),
                      void *args);
Code_t ZPeekPacket(char **buffer, int *ret_len,
                   struct sockaddr_in *from);
Code_t ZPeekNotice(ZNotice_t *notice, struct sockaddr_in *from);
Code_t ZIfNotice(ZNotice_t *notice, struct sockaddr_in *from,
                 int (*predicate)(ZNotice_t *, void *), void *args);
Code_t ZPeekIfNotice(ZNotice_t *notice, struct sockaddr_in *from,
                 int (*predicate)(ZNotice_t *, char *), char *args);
Code_t ZSubscriptions(ZSubscription_t *sublist, int nitems,
                      unsigned int port,
                      char *opcode,
                      Code_t (*send_routine)(ZNotice_t *, char *, int, int));
// Code_t ZPunt(ZSubscription_t *sublist, int nitems, unsigned int port);
Code_t ZSubscribeTo(ZSubscription_t *sublist, int nitems,
                    unsigned int port);
Code_t ZSubscribeToSansDefaults(ZSubscription_t *sublist, int nitems,
                                unsigned int port);
Code_t ZUnsubscribeTo(ZSubscription_t *sublist, int nitems,
                      unsigned int port);
Code_t ZCancelSubscriptions(unsigned int port);
Code_t ZFlushUserSubscriptions(char *recip);
int ZPending(void);
Code_t ZReceiveNotice(ZNotice_t *notice, struct sockaddr_in *from);
const char *ZGetCharsetString(char *charset);
unsigned short ZGetCharset(char *charset);
const char *ZCharsetToString(unsigned short charset);
Code_t ZTransliterate(char *in, int inlen, char *inset, char *outset, char **out, int *outlen);
char *ZExpandRealm(char *realm);
Code_t ZDumpSession(char **buffer, int *ret_len);
Code_t ZLoadSession(char *buffer, int len);
""")

ffibuilder.set_source(
    '_zephyr',
    """
#include "zephyr/zephyr.h"
""",
    libraries=['zephyr'])

if __name__ == '__main__':
    ffibuilder.compile(verbose=True)
