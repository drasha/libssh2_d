/* Copyright (c) 2004-2009, Sara Golemon <sarag@libssh2.org>
 * Copyright (c) 2009-2012 Daniel Stenberg
 * Copyright (c) 2010 Simon Josefsson <simon@josefsson.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

module deimos.libssh2;

immutable LIBSSH2_COPYRIGHT = "2004-2012 The libssh2 project and its contributors.";

/* We use underscore instead of dash when appending DEV in dev versions just
   to make the BANNER define (used by src/session.c) be a valid SSH
   banner. Release versions have no appended strings and may of course not
   have dashes either. */
immutable LIBSSH2_VERSION = "1.4.4_DEV";

/* The numeric version number is also available "in parts" by using these
   defines: */
immutable LIBSSH2_VERSION_MAJOR  = 1;
immutable LIBSSH2_VERSION_MINOR  = 4;
immutable LIBSSH2_VERSION_PATCH  = 4;

/* This is the numeric version of the libssh2 version number, meant for easier
   parsing and comparions by programs. The LIBSSH2_VERSION_NUM define will
   always follow this syntax:

         0xXXYYZZ

   Where XX, YY and ZZ are the main version, release and patch numbers in
   hexadecimal (using 8 bits each). All three numbers are always represented
   using two digits.  1.2 would appear as "0x010200" while version 9.11.7
   appears as "0x090b07".

   This 6-digit (24 bits) hexadecimal number does not show pre-release number,
   and it is always a greater number in a more recent release. It makes
   comparisons with greater than and less than work.
*/
immutable LIBSSH2_VERSION_NUM    = 0x010404;

/*
 * This is the date and time when the full source package was created. The
 * timestamp is not stored in the source code repo, as the timestamp is
 * properly set in the tarballs by the maketgz script.
 *
 * The format of the date should follow this template:
 *
 * "Mon Feb 12 11:35:33 UTC 2007"
 */
immutable LIBSSH2_TIMESTAMP       = "DEV";

version(Windows)
{
 import deimos.basetsd;
 import std.c.windows.winsock;
}

import std.c.stddef;
import std.c.string;
import core.stdc.time;

version(Windows)
{
  import std.c.windows.stat;
}
else
{
  import core.sys.posix.sys.stat;
  import core.sys.posix.sys.types;
}

// WARN: Darwin and NETWARE support removed

alias uint8_t          = ubyte;
alias uint32_t         = uint;
alias libssh2_uint64_t = ulong;
alias libssh2_int64_t  = long;
alias ssize_t          = SSIZE_T;

version(Windows)
{
  alias libssh2_socket_t           = SOCKET;
  immutable LIBSSH2_INVALID_SOCKET = INVALID_SOCKET;
}
else
{
  alias libssh2_socket_t           = int;
  immutable LIBSSH2_INVALID_SOCKET = -1;
}

/* Part of every banner, user specified or not */
immutable LIBSSH2_SSH_BANNER                   = "SSH-2.0-libssh2_" ~ LIBSSH2_VERSION;

/* We *could* add a comment here if we so chose */
immutable LIBSSH2_SSH_DEFAULT_BANNER           = LIBSSH2_SSH_BANNER;
immutable LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF = LIBSSH2_SSH_DEFAULT_BANNER ~ "\r\n";

/* Default generate and safe prime sizes for diffie-hellman-group-exchange-sha1 */
immutable LIBSSH2_DH_GEX_MINGROUP = 1024;
immutable LIBSSH2_DH_GEX_OPTGROUP = 1536;
immutable LIBSSH2_DH_GEX_MAXGROUP = 2048;

/* Defaults for pty requests */
immutable LIBSSH2_TERM_WIDTH     = 80;
immutable LIBSSH2_TERM_HEIGHT    = 24;
immutable LIBSSH2_TERM_WIDTH_PX  = 0;
immutable LIBSSH2_TERM_HEIGHT_PX = 0;

/* 1/4 second */
immutable LIBSSH2_SOCKET_POLL_UDELAY   = 250000;
/* 0.25 * 120 == 30 seconds */
immutable LIBSSH2_SOCKET_POLL_MAXLOOPS = 120;

/* Maximum size to allow a payload to compress to, plays it safe by falling
   short of spec limits */
immutable LIBSSH2_PACKET_MAXCOMP = 32000;

/* Maximum size to allow a payload to deccompress to, plays it safe by
   allowing more than spec requires */
immutable LIBSSH2_PACKET_MAXDECOMP = 40000;

/* Maximum size for an inbound compressed payload, plays it safe by
   overshooting spec limits */
immutable LIBSSH2_PACKET_MAXPAYLOAD = 40000;

alias void function(size_t count, void** _abstract)            LIBSSH2_ALLOC_FUNC;
alias void function(void* ptr, size_t count, void** _abstract) LIBSSH2_REALLOC_FUNC;
alias void function(void* ptr, void** _abstract)               LIBSSH2_FREE_FUNC;

struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
{
    char* text;
    uint length;
    ubyte echo;
} 
alias LIBSSH2_USERAUTH_KBDINT_PROMPT = _LIBSSH2_USERAUTH_KBDINT_PROMPT;

struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
{
    char* text;
    uint length;
} 
alias LIBSSH2_USERAUTH_KBDINT_RESPONSE = _LIBSSH2_USERAUTH_KBDINT_RESPONSE;

/* 'publickey' authentication callback */
alias int function(LIBSSH2_SESSION* session, char** sig, size_t* sig_len,
                   const char* data, size_t data_len, void** _abstract) 
                   LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC;

/* 'keyboard-interactive' authentication callback */
alias void function(const char* name, int name_len, const char* instruction,
                    int instruction_len, int num_prompts,
                    const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
                    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses, void** _abstract)
                    LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC;

/* Callbacks for special SSH packets */
alias void function(LIBSSH2_SESSION* session, const char* message, int message_len,
                    void** _abstract)
                    LIBSSH2_IGNORE_FUNC;

alias void function(LIBSSH2_SESSION* session, int always_display, const char* message,
                    int message_len, const char* language, int language_len,
                    void** _abstract)
                    LIBSSH2_DEBUG_FUNC;

alias void function(LIBSSH2_SESSION* session, int reason, const char* message,
                    int message_len, const char* language, int language_len,
                    void** _abstract)
                    LIBSSH2_DISCONNECT_FUNC;

alias void function(LIBSSH2_SESSION* session, char** newpw, int* newpw_len,
                    void** _abstract)
                    LIBSSH2_PASSWD_CHANGEREQ_FUNC;

alias int function(LIBSSH2_SESSION* session, const char* packet, int packet_len,
                   void** _abstract)
                   LIBSSH2_MACERROR_FUNC;

alias void function(LIBSSH2_SESSION* session, LIBSSH2_CHANNEL* channel,
                    const char* shost, int sport, void** _abstract)
                    LIBSSH2_X11_OPEN_FUNC;

alias void function(LIBSSH2_SESSION* session, void** session_abstract,
                    LIBSSH2_CHANNEL* channel, void** channel_abstract)
                    LIBSSH2_CHANNEL_CLOSE_FUNC;

/* I/O callbacks */
alias ssize_t function(libssh2_socket_t socket, void* buffer, size_t length,
                       int flags, void** _abstract)
                       LIBSSH2_RECV_FUNC;

alias ssize_t function(libssh2_socket_t socket, const void* buffer, size_t length,
                       int flags, void** _abstract)
                       LIBSSH2_SEND_FUNC;

/* libssh2_session_callback_set() constants */
immutable LIBSSH2_CALLBACK_IGNORE     = 0;
immutable LIBSSH2_CALLBACK_DEBUG      = 1;
immutable LIBSSH2_CALLBACK_DISCONNECT = 2;
immutable LIBSSH2_CALLBACK_MACERROR   = 3;
immutable LIBSSH2_CALLBACK_X11        = 4;
immutable LIBSSH2_CALLBACK_SEND       = 5;
immutable LIBSSH2_CALLBACK_RECV       = 6;

/* libssh2_session_method_pref() constants */
immutable LIBSSH2_METHOD_KEX       = 0;
immutable LIBSSH2_METHOD_HOSTKEY   = 1;
immutable LIBSSH2_METHOD_CRYPT_CS  = 2;
immutable LIBSSH2_METHOD_CRYPT_SC  = 3;
immutable LIBSSH2_METHOD_MAC_CS    = 4;
immutable LIBSSH2_METHOD_MAC_SC    = 5;
immutable LIBSSH2_METHOD_COMP_CS   = 6;
immutable LIBSSH2_METHOD_COMP_SC   = 7;
immutable LIBSSH2_METHOD_LANG_CS   = 8;
immutable LIBSSH2_METHOD_LANG_SC   = 9;

/* flags */
immutable LIBSSH2_FLAG_SIGPIPE  = 1;
immutable LIBSSH2_FLAG_COMPRESS = 2;

struct _LIBSSH2_SESSION;
struct _LIBSSH2_CHANNEL;
struct _LIBSSH2_LISTENER;
struct _LIBSSH2_KNOWNHOSTS;
struct _LIBSSH2_AGENT;

alias LIBSSH2_SESSION    = _LIBSSH2_SESSION;
alias LIBSSH2_CHANNEL    = _LIBSSH2_CHANNEL;
alias LIBSSH2_LISTENER   = _LIBSSH2_LISTENER;
alias LIBSSH2_KNOWNHOSTS = _LIBSSH2_KNOWNHOSTS;
alias LIBSSH2_AGENT      = _LIBSSH2_AGENT;

struct _LIBSSH2_POLLFD 
{
    char type; /* LIBSSH2_POLLFD_* below */

    union _fd
    {
        libssh2_socket_t socket; /* File descriptors -- examined with
                                    system select() call */
        LIBSSH2_CHANNEL *channel; /* Examined by checking internal state */
        LIBSSH2_LISTENER *listener; /* Read polls only -- are inbound
                                       connections waiting to be accepted? */
    };
    alias fd = _fd;

    version(Win32)
    {
      uint events; /* Requested Events */
      uint revents; /* Returned Events */
    }
    else
    {
      ulong events; /* Requested Events */
      ulong revents; /* Returned Events */
    }
} 
alias LIBSSH2_POLLFD = _LIBSSH2_POLLFD;

/* Poll FD Descriptor Types */
immutable LIBSSH2_POLLFD_SOCKET      = 1;
immutable LIBSSH2_POLLFD_CHANNEL     = 2;
immutable LIBSSH2_POLLFD_LISTENER    = 3;

/* Note: Win32 Doesn't actually have a poll() implementation, so some of these
   values are faked with select() data */
/* Poll FD events/revents -- Match sys/poll.h where possible */
immutable LIBSSH2_POLLFD_POLLIN          = 0x0001; /* Data available to be read or
                                                      connection available --
                                                      All */
immutable LIBSSH2_POLLFD_POLLPRI         = 0x0002; /* Priority data available to
                                                      be read -- Socket only */
immutable LIBSSH2_POLLFD_POLLEXT         = 0x0002; /* Extended data available to
                                                      be read -- Channel only */
immutable LIBSSH2_POLLFD_POLLOUT         = 0x0004; /* Can may be written --
                                                      Socket/Channel */
/* revents only */
immutable LIBSSH2_POLLFD_POLLERR         = 0x0008; /* Error Condition -- Socket */
immutable LIBSSH2_POLLFD_POLLHUP         = 0x0010; /* HangUp/EOF -- Socket */
immutable LIBSSH2_POLLFD_SESSION_CLOSED  = 0x0010; /* Session Disconnect */
immutable LIBSSH2_POLLFD_POLLNVAL        = 0x0020; /* Invalid request -- Socket
                                                      Only */
immutable LIBSSH2_POLLFD_POLLEX          = 0x0040; /* Exception Condition --
                                                      Socket/Win32 */
immutable LIBSSH2_POLLFD_CHANNEL_CLOSED  = 0x0080; /* Channel Disconnect */
immutable LIBSSH2_POLLFD_LISTENER_CLOSED = 0x0080; /* Listener Disconnect */

enum HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION = 1;
/* Block Direction Types */
immutable LIBSSH2_SESSION_BLOCK_INBOUND                 = 0x0001;
immutable LIBSSH2_SESSION_BLOCK_OUTBOUND                = 0x0002;

/* Hash Types */
immutable LIBSSH2_HOSTKEY_HASH_MD5                          =  1;
immutable LIBSSH2_HOSTKEY_HASH_SHA1                         =  2;

/* Hostkey Types */
immutable LIBSSH2_HOSTKEY_TYPE_UNKNOWN			   = 0;
immutable LIBSSH2_HOSTKEY_TYPE_RSA			       = 1;
immutable LIBSSH2_HOSTKEY_TYPE_DSS			       = 2;

/* Disconnect Codes (defined by SSH protocol) */
immutable SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT         = 1;
immutable SSH_DISCONNECT_PROTOCOL_ERROR                      = 2;
immutable SSH_DISCONNECT_KEY_EXCHANGE_FAILED                 = 3;
immutable SSH_DISCONNECT_RESERVED                            = 4;
immutable SSH_DISCONNECT_MAC_ERROR                           = 5;
immutable SSH_DISCONNECT_COMPRESSION_ERROR                   = 6;
immutable SSH_DISCONNECT_SERVICE_NOT_AVAILABLE               = 7;
immutable SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED      = 8;
immutable SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE             = 9;
immutable SSH_DISCONNECT_CONNECTION_LOST                     = 10;
immutable SSH_DISCONNECT_BY_APPLICATION                      = 11;
immutable SSH_DISCONNECT_TOO_MANY_CONNECTIONS                = 12;
immutable SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              = 13;
immutable SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      = 14;
immutable SSH_DISCONNECT_ILLEGAL_USER_NAME                   = 15;

/* Error Codes (defined by libssh2) */
immutable LIBSSH2_ERROR_NONE                     = 0;

/* The library once used -1 as a generic error return value on numerous places
   through the code, which subsequently was converted to
   LIBSSH2_ERROR_SOCKET_NONE uses over time. As this is a generic error code,
   the goal is to never ever return this code but instead make sure that a
   more accurate and descriptive error code is used. */
immutable LIBSSH2_ERROR_SOCKET_NONE              = -1;

immutable LIBSSH2_ERROR_BANNER_RECV              = -2;
immutable LIBSSH2_ERROR_BANNER_SEND              = -3;
immutable LIBSSH2_ERROR_INVALID_MAC              = -4;
immutable LIBSSH2_ERROR_KEX_FAILURE              = -5;
immutable LIBSSH2_ERROR_ALLOC                    = -6;
immutable LIBSSH2_ERROR_SOCKET_SEND              = -7;
immutable LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE     = -8;
immutable LIBSSH2_ERROR_TIMEOUT                  = -9;
immutable LIBSSH2_ERROR_HOSTKEY_INIT             = -10;
immutable LIBSSH2_ERROR_HOSTKEY_SIGN             = -11;
immutable LIBSSH2_ERROR_DECRYPT                  = -12;
immutable LIBSSH2_ERROR_SOCKET_DISCONNECT        = -13;
immutable LIBSSH2_ERROR_PROTO                    = -14;
immutable LIBSSH2_ERROR_PASSWORD_EXPIRED         = -15;
immutable LIBSSH2_ERROR_FILE                     = -16;
immutable LIBSSH2_ERROR_METHOD_NONE              = -17;
immutable LIBSSH2_ERROR_AUTHENTICATION_FAILED    = -18;
immutable LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED   = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
immutable LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED     = -19;
immutable LIBSSH2_ERROR_CHANNEL_OUTOFORDER       = -20;
immutable LIBSSH2_ERROR_CHANNEL_FAILURE          = -21;
immutable LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED   = -22;
immutable LIBSSH2_ERROR_CHANNEL_UNKNOWN          = -23;
immutable LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED  = -24;
immutable LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED  = -25;
immutable LIBSSH2_ERROR_CHANNEL_CLOSED           = -26;
immutable LIBSSH2_ERROR_CHANNEL_EOF_SENT         = -27;
immutable LIBSSH2_ERROR_SCP_PROTOCOL             = -28;
immutable LIBSSH2_ERROR_ZLIB                     = -29;
immutable LIBSSH2_ERROR_SOCKET_TIMEOUT           = -30;
immutable LIBSSH2_ERROR_SFTP_PROTOCOL            = -31;
immutable LIBSSH2_ERROR_REQUEST_DENIED           = -32;
immutable LIBSSH2_ERROR_METHOD_NOT_SUPPORTED     = -33;
immutable LIBSSH2_ERROR_INVAL                    = -34;
immutable LIBSSH2_ERROR_INVALID_POLL_TYPE        = -35;
immutable LIBSSH2_ERROR_PUBLICKEY_PROTOCOL       = -36;
immutable LIBSSH2_ERROR_EAGAIN                   = -37;
immutable LIBSSH2_ERROR_BUFFER_TOO_SMALL         = -38;
immutable LIBSSH2_ERROR_BAD_USE                  = -39;
immutable LIBSSH2_ERROR_COMPRESS                 = -40;
immutable LIBSSH2_ERROR_OUT_OF_BOUNDARY          = -41;
immutable LIBSSH2_ERROR_AGENT_PROTOCOL           = -42;
immutable LIBSSH2_ERROR_SOCKET_RECV              = -43;
immutable LIBSSH2_ERROR_ENCRYPT                  = -44;
immutable LIBSSH2_ERROR_BAD_SOCKET               = -45;
immutable LIBSSH2_ERROR_KNOWN_HOSTS              = -46;

/* this is a define to provide the old (<= 1.2.7) name */
alias LIBSSH2_ERROR_BANNER_NONE = LIBSSH2_ERROR_BANNER_RECV;

/* Global API */
immutable LIBSSH2_INIT_NO_CRYPTO      =  0x0001;

extern (C) {
nothrow {

/*
 * libssh2_init()
 *
 * Initialize the libssh2 functions.  This typically initialize the
 * crypto library.  It uses a global state, and is not thread safe --
 * you must make sure this function is not called concurrently.
 *
 * Flags can be:
 * 0:                              Normal initialize
 * LIBSSH2_INIT_NO_CRYPTO:         Do not initialize the crypto library (ie.
 *                                 OPENSSL_add_cipher_algoritms() for OpenSSL
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
int libssh2_init(int flags);

/*
 * libssh2_exit()
 *
 * Exit the libssh2 functions and free's all memory used internal.
 */
void libssh2_exit();

/*
 * libssh2_free()
 *
 * Deallocate memory allocated by earlier call to libssh2 functions.
 */
void libssh2_free(LIBSSH2_SESSION *session, void *ptr);

/*
 * libssh2_session_supported_algs()
 *
 * Fills algs with a list of supported acryptographic algorithms. Returns a
 * non-negative number (number of supported algorithms) on success or a
 * negative number (an eror code) on failure.
 *
 * NOTE: on success, algs must be deallocated (by calling libssh2_free) when
 * not needed anymore
 */
int libssh2_session_supported_algs(LIBSSH2_SESSION* session,
                                   int method_type,
                                   const char*** algs);

/* Session API */
LIBSSH2_SESSION*
libssh2_session_init_ex(LIBSSH2_ALLOC_FUNC   my_alloc,
                        LIBSSH2_FREE_FUNC    my_free,
                        LIBSSH2_REALLOC_FUNC my_realloc, 
                        void* _abstract);

void** libssh2_session_abstract(LIBSSH2_SESSION* session);

void* libssh2_session_callback_set(LIBSSH2_SESSION* session,
                                   int cbtype, void* callback);
int libssh2_session_banner_set(LIBSSH2_SESSION* session,
                               const char *banner);
int libssh2_banner_set(LIBSSH2_SESSION* session,
                       const char* banner);

int libssh2_session_startup(LIBSSH2_SESSION *session, int sock);
int libssh2_session_handshake(LIBSSH2_SESSION* session,
                              libssh2_socket_t sock);
int libssh2_session_disconnect_ex(LIBSSH2_SESSION* session,
                                  int reason,
                                  const char *description,
                                  const char *lang);

int libssh2_session_free(LIBSSH2_SESSION* session);

char* libssh2_hostkey_hash(LIBSSH2_SESSION *session, int hash_type);

char* libssh2_session_hostkey(LIBSSH2_SESSION* session,
                              size_t* len, int* type);

int libssh2_session_method_pref(LIBSSH2_SESSION* session,
                                int method_type,
                                const char* prefs);
char* libssh2_session_methods(LIBSSH2_SESSION* session,
                              int method_type);
int libssh2_session_last_error(LIBSSH2_SESSION* session, char** errmsg,
                               int* errmsg_len, int want_buf);
int libssh2_session_last_errno(LIBSSH2_SESSION* session);
int libssh2_session_block_directions(LIBSSH2_SESSION* session);

int libssh2_session_flag(LIBSSH2_SESSION* session, int flag, int value);
char* libssh2_session_banner_get(LIBSSH2_SESSION* session);

/* Userauth API */
char* libssh2_userauth_list(LIBSSH2_SESSION* session,
                            const char* username,
                            uint username_len);
int libssh2_userauth_authenticated(LIBSSH2_SESSION* session);

int libssh2_userauth_password_ex(LIBSSH2_SESSION* session,
                                 const char* username,
                                 uint username_len,
                                 const char* password,
                                 uint password_len,
                                 LIBSSH2_PASSWD_CHANGEREQ_FUNC passwd_change_cb);

int libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION* session,
                                           const char* username,
                                           uint username_len,
                                           const char *publickey,
                                           const char *privatekey,
                                           const char *passphrase);

int libssh2_userauth_publickey(LIBSSH2_SESSION* session,
                               const char* username,
                               const char* pubkeydata,
                               size_t pubkeydata_len,
                               LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC sign_callback,
                               void** _abstract);

int libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION* session,
                                           const char* username,
                                           uint username_len,
                                           const char* publickey,
                                           const char* privatekey,
                                           const char* passphrase,
                                           const char* hostname,
                                           uint hostname_len,
                                           const char* local_username,
                                           uint local_username_len);

/*
 * response_callback is provided with filled by library prompts array,
 * but client must allocate and fill individual responses. Responses
 * array is already allocated. Responses data will be freed by libssh2
 * after callback return, but before subsequent callback invokation.
 */
int libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION* session,
                                             const char* username,
                                             uint username_len,
                                             LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC response_callback);

int libssh2_poll(LIBSSH2_POLLFD* fds, uint nfds, long timeout);

/* Channel API */
immutable LIBSSH2_CHANNEL_WINDOW_DEFAULT  = (2*1024*1024);
immutable LIBSSH2_CHANNEL_PACKET_DEFAULT  = 32768;
immutable LIBSSH2_CHANNEL_MINADJUST       = 1024;

/* Extended Data Handling */
immutable LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL      = 0;
immutable LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE      = 1;
immutable LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE       = 2;

immutable SSH_EXTENDED_DATA_STDERR = 1;

/* Returned by any function that would block during a read/write opperation */
immutable LIBSSH2CHANNEL_EAGAIN = LIBSSH2_ERROR_EAGAIN;

LIBSSH2_CHANNEL*
libssh2_channel_open_ex(LIBSSH2_SESSION* session, const char* channel_type,
                        uint channel_type_len,
                        uint window_size, uint packet_size,
                        const char* message, uint message_len);

LIBSSH2_CHANNEL*
libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION* session, const char* host,
                                int port, const char* shost, int sport);

LIBSSH2_LISTENER*
libssh2_channel_forward_listen_ex(LIBSSH2_SESSION* session, const char* host,
                                  int port, int* bound_port, int queue_maxsize);

int libssh2_channel_forward_cancel(LIBSSH2_LISTENER* listener);

LIBSSH2_CHANNEL* libssh2_channel_forward_accept(LIBSSH2_LISTENER* listener);

int libssh2_channel_setenv_ex(LIBSSH2_CHANNEL* channel,
                              const char* varname,
                              uint varname_len,
                              const char* value,
                              uint value_len);

int libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel,
                                   const char* term,
                                   uint term_len,
                                   const char* modes,
                                   uint modes_len,
                                   int width, int height,
                                   int width_px, int height_px);

int libssh2_channel_request_pty_size_ex(LIBSSH2_CHANNEL*channel,
                                        int width, int height,
                                        int width_px,
                                        int height_px);

int libssh2_channel_x11_req_ex(LIBSSH2_CHANNEL* channel,
                               int single_connection,
                               const char* auth_proto,
                               const char* auth_cookie,
                               int screen_number);

int libssh2_channel_process_startup(LIBSSH2_CHANNEL* channel,
                                    const char* request,
                                    uint request_len,
                                    const char* message,
                                    uint message_len);

ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL* channel,
                                int stream_id, char *buf,
                                size_t buflen);

int libssh2_poll_channel_read(LIBSSH2_CHANNEL* channel, int extended);

// This may be a recipe for disaster as win32 has long equal to int
// Maybe change types
ulong libssh2_channel_window_read_ex(LIBSSH2_CHANNEL* channel,
                                     ulong* read_avail,
                                     ulong* window_size_initial);

/* libssh2_channel_receive_window_adjust is DEPRECATED, do not use! */
ulong libssh2_channel_receive_window_adjust(LIBSSH2_CHANNEL* channel,
                                            ulong adjustment,
                                            char force);

int libssh2_channel_receive_window_adjust2(LIBSSH2_CHANNEL* channel,
                                           ulong adjustment,
                                           char force,
                                           uint* storewindow);

ssize_t libssh2_channel_write_ex(LIBSSH2_CHANNEL* channel,
                                 int stream_id, const char* buf,
                                 size_t buflen);

ulong libssh2_channel_window_write_ex(LIBSSH2_CHANNEL* channel,
                                      ulong* window_size_initial);

void libssh2_session_set_blocking(LIBSSH2_SESSION* session, int blocking);
int  libssh2_session_get_blocking(LIBSSH2_SESSION* session);

void libssh2_channel_set_blocking(LIBSSH2_CHANNEL* channel, int blocking);

void libssh2_session_set_timeout(LIBSSH2_SESSION* session, long timeout);
long libssh2_session_get_timeout(LIBSSH2_SESSION* session);

/* libssh2_channel_handle_extended_data is DEPRECATED, do not use! */
void libssh2_channel_handle_extended_data(LIBSSH2_CHANNEL *channel, int ignore_mode);
int  libssh2_channel_handle_extended_data2(LIBSSH2_CHANNEL *channel, int ignore_mode);

/* libssh2_channel_ignore_extended_data() is defined below for BC with version
 * 0.1
 *
 * Future uses should use libssh2_channel_handle_extended_data() directly if
 * LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE is passed, extended data will be read
 * (FIFO) from the standard data channel
 */
/* DEPRECATED */
void libssh2_channel_ignore_extended_data(LIBSSH2_CHANNEL* channel, int ignore)
{
  libssh2_channel_handle_extended_data(channel,
                                       (ignore) ?
                                       LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE :
                                       LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL );
}

immutable LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA     = -1;
immutable LIBSSH2_CHANNEL_FLUSH_ALL               = -2;
int libssh2_channel_flush_ex(LIBSSH2_CHANNEL* channel, int streamid);

int libssh2_channel_get_exit_status(LIBSSH2_CHANNEL* channel);
int libssh2_channel_get_exit_signal(LIBSSH2_CHANNEL* channel,
                                    char** exitsignal,
                                    size_t* exitsignal_len,
                                    char** errmsg,
                                    size_t* errmsg_len,
                                    char** langtag,
                                    size_t* langtag_len);
int libssh2_channel_send_eof(LIBSSH2_CHANNEL* channel);
int libssh2_channel_eof(LIBSSH2_CHANNEL* channel);
int libssh2_channel_wait_eof(LIBSSH2_CHANNEL* channel);
int libssh2_channel_close(LIBSSH2_CHANNEL* channel);
int libssh2_channel_wait_closed(LIBSSH2_CHANNEL* channel);
int libssh2_channel_free(LIBSSH2_CHANNEL* channel);

version (Windows)
{
  alias stat_t = struct_stat;
}

LIBSSH2_CHANNEL* libssh2_scp_recv(LIBSSH2_SESSION* session,
                                  const char* path,
                                  stat_t* sb);

LIBSSH2_CHANNEL* libssh2_scp_send_ex(LIBSSH2_SESSION*session,
                                     const char *path, int mode,
                                     size_t size, long mtime,
                                     long atime);
LIBSSH2_CHANNEL*
libssh2_scp_send64(LIBSSH2_SESSION* session, const char* path, int mode,
                   libssh2_int64_t size, time_t mtime, time_t atime);

int libssh2_base64_decode(LIBSSH2_SESSION* session, char** dest,
                          uint *dest_len, const char *src, uint src_len);

char* libssh2_version(int req_version_num);

immutable HAVE_LIBSSH2_KNOWNHOST_API = 0x010101; /* since 1.1.1 */
immutable HAVE_LIBSSH2_VERSION_API   = 0x010100; /* libssh2_version since 1.1 */

struct libssh2_knownhost 
{
    uint magic;  /* magic stored by the library */
    void* node; /* handle to the internal representation of this host */
    char* name; /* this is NULL if no plain text host name exists */
    char* key;  /* key in base64/printable format */
    int typemask;
}

/*
 * libssh2_knownhost_init
 *
 * Init a collection of known hosts. Returns the pointer to a collection.
 *
 */
LIBSSH2_KNOWNHOSTS* libssh2_knownhost_init(LIBSSH2_SESSION* session);

/*
 * libssh2_knownhost_add
 *
 * Add a host and its associated key to the collection of known hosts.
 *
 * The 'type' argument specifies on what format the given host and keys are:
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - SHA1(<salt> <host>) base64-encoded!
 * custom - another hash
 *
 * If 'sha1' is selected as type, the salt must be provided to the salt
 * argument. This too base64 encoded.
 *
 * The SHA-1 hash is what OpenSSH can be told to use in known_hosts files.  If
 * a custom type is used, salt is ignored and you must provide the host
 * pre-hashed when checking for it in the libssh2_knownhost_check() function.
 *
 * The keylen parameter may be omitted (zero) if the key is provided as a
 * NULL-terminated base64-encoded string.
 */

/* host format (2 bits) */
immutable LIBSSH2_KNOWNHOST_TYPE_MASK    = 0xffff;
immutable LIBSSH2_KNOWNHOST_TYPE_PLAIN   = 1;
immutable LIBSSH2_KNOWNHOST_TYPE_SHA1    = 2; /* always base64 encoded */
immutable LIBSSH2_KNOWNHOST_TYPE_CUSTOM  = 3;

/* key format (2 bits) */
immutable LIBSSH2_KNOWNHOST_KEYENC_MASK     = (3<<16);
immutable LIBSSH2_KNOWNHOST_KEYENC_RAW      = (1<<16);
immutable LIBSSH2_KNOWNHOST_KEYENC_BASE64   = (2<<16);

/* type of key (2 bits) */
immutable LIBSSH2_KNOWNHOST_KEY_MASK     = (7<<18);
immutable LIBSSH2_KNOWNHOST_KEY_SHIFT    = 18;
immutable LIBSSH2_KNOWNHOST_KEY_RSA1     = (1<<18);
immutable LIBSSH2_KNOWNHOST_KEY_SSHRSA   = (2<<18);
immutable LIBSSH2_KNOWNHOST_KEY_SSHDSS   = (3<<18);
immutable LIBSSH2_KNOWNHOST_KEY_UNKNOWN  = (7<<18);

int libssh2_knownhost_add(LIBSSH2_KNOWNHOSTS* hosts,
                          const char* host,
                          const char* salt,
                          const char* key, size_t keylen, int typemask,
                          libssh2_knownhost** store);

/*
 * libssh2_knownhost_addc
 *
 * Add a host and its associated key to the collection of known hosts.
 *
 * Takes a comment argument that may be NULL.  A NULL comment indicates
 * there is no comment and the entry will end directly after the key
 * when written out to a file.  An empty string "" comment will indicate an
 * empty comment which will cause a single space to be written after the key.
 *
 * The 'type' argument specifies on what format the given host and keys are:
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - SHA1(<salt> <host>) base64-encoded!
 * custom - another hash
 *
 * If 'sha1' is selected as type, the salt must be provided to the salt
 * argument. This too base64 encoded.
 *
 * The SHA-1 hash is what OpenSSH can be told to use in known_hosts files.  If
 * a custom type is used, salt is ignored and you must provide the host
 * pre-hashed when checking for it in the libssh2_knownhost_check() function.
 *
 * The keylen parameter may be omitted (zero) if the key is provided as a
 * NULL-terminated base64-encoded string.
 */

int libssh2_knownhost_addc(LIBSSH2_KNOWNHOSTS* hosts,
                           const char* host,
                           const char* salt,
                           const char* key, size_t keylen,
                           const char* comment, size_t commentlen, int typemask,
                           libssh2_knownhost** store);

/*
 * libssh2_knownhost_check
 *
 * Check a host and its associated key against the collection of known hosts.
 *
 * The type is the type/format of the given host name.
 *
 * plain  - ascii "hostname.domain.tld"
 * custom - prehashed base64 encoded. Note that this cannot use any salts.
 *
 *
 * 'knownhost' may be set to NULL if you don't care about that info.
 *
 * Returns:
 *
 * LIBSSH2_KNOWNHOST_CHECK_* values, see below
 *
 */

immutable LIBSSH2_KNOWNHOST_CHECK_MATCH    = 0;
immutable LIBSSH2_KNOWNHOST_CHECK_MISMATCH = 1;
immutable LIBSSH2_KNOWNHOST_CHECK_NOTFOUND = 2;
immutable LIBSSH2_KNOWNHOST_CHECK_FAILURE  = 3;

int libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                            const char* host, const char* key, size_t keylen,
                            int typemask,
                            libssh2_knownhost** knownhost);

/* this function is identital to the above one, but also takes a port
   argument that allows libssh2 to do a better check */
int libssh2_knownhost_checkp(LIBSSH2_KNOWNHOSTS* hosts,
                             const char* host, int port,
                             const char* key, size_t keylen,
                             int typemask,
                             libssh2_knownhost** knownhost);

/*
 * libssh2_knownhost_del
 *
 * Remove a host from the collection of known hosts. The 'entry' struct is
 * retrieved by a call to libssh2_knownhost_check().
 *
 */
int libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS *hosts, libssh2_knownhost* entry);

/*
 * libssh2_knownhost_free
 *
 * Free an entire collection of known hosts.
 *
 */
void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS* hosts);

/*
 * libssh2_knownhost_readline()
 *
 * Pass in a line of a file of 'type'. It makes libssh2 read this line.
 *
 * LIBSSH2_KNOWNHOST_FILE_OPENSSH is the only supported type.
 *
 */
int libssh2_knownhost_readline(LIBSSH2_KNOWNHOSTS* hosts, const char* line, size_t len, int type);

/*
 * libssh2_knownhost_readfile
 *
 * Add hosts+key pairs from a given file.
 *
 * Returns a negative value for error or number of successfully added hosts.
 *
 * This implementation currently only knows one 'type' (openssh), all others
 * are reserved for future use.
 */

immutable LIBSSH2_KNOWNHOST_FILE_OPENSSH = 1;

int libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS* hosts, const char* filename, int type);

/*
 * libssh2_knownhost_writeline()
 *
 * Ask libssh2 to convert a known host to an output line for storage.
 *
 * Note that this function returns LIBSSH2_ERROR_BUFFER_TOO_SMALL if the given
 * output buffer is too small to hold the desired output.
 *
 * This implementation currently only knows one 'type' (openssh), all others
 * are reserved for future use.
 *
 */
int libssh2_knownhost_writeline(LIBSSH2_KNOWNHOSTS* hosts,
                                libssh2_knownhost* known,
                                char* buffer, size_t buflen,
                                size_t* outlen, /* the amount of written data */
                                int type);

/*
 * libssh2_knownhost_writefile
 *
 * Write hosts+key pairs to a given file.
 *
 * This implementation currently only knows one 'type' (openssh), all others
 * are reserved for future use.
 */

int libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS* hosts, const char* filename, int type);

/*
 * libssh2_knownhost_get()
 *
 * Traverse the internal list of known hosts. Pass NULL to 'prev' to get
 * the first one. Or pass a poiner to the previously returned one to get the
 * next.
 *
 * Returns:
 * 0 if a fine host was stored in 'store'
 * 1 if end of hosts
 * [negative] on errors
 */
int libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS* hosts,
                          libssh2_knownhost** store,
                          libssh2_knownhost* prev);

immutable HAVE_LIBSSH2_AGENT_API = 0x010202; /* since 1.2.2 */

struct libssh2_agent_publickey 
{
    uint magic;              /* magic stored by the library */
    void* node;     /* handle to the internal representation of key */
    char* blob;           /* public key blob */
    size_t blob_len;               /* length of the public key blob */
    char* comment;                 /* comment in printable format */
}

/*
 * libssh2_agent_init
 *
 * Init an ssh-agent handle. Returns the pointer to the handle.
 *
 */
LIBSSH2_AGENT* libssh2_agent_init(LIBSSH2_SESSION* session);

/*
 * libssh2_agent_connect()
 *
 * Connect to an ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
int libssh2_agent_connect(LIBSSH2_AGENT* agent);

/*
 * libssh2_agent_list_identities()
 *
 * Request an ssh-agent to list identities.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
int libssh2_agent_list_identities(LIBSSH2_AGENT* agent);

/*
 * libssh2_agent_get_identity()
 *
 * Traverse the internal list of public keys. Pass NULL to 'prev' to get
 * the first one. Or pass a poiner to the previously returned one to get the
 * next.
 *
 * Returns:
 * 0 if a fine public key was stored in 'store'
 * 1 if end of public keys
 * [negative] on errors
 */
int libssh2_agent_get_identity(LIBSSH2_AGENT* agent,
                               libssh2_agent_publickey** store,
                               libssh2_agent_publickey* prev);

/*
 * libssh2_agent_userauth()
 *
 * Do publickey user authentication with the help of ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
int libssh2_agent_userauth(LIBSSH2_AGENT* agent,
                           const char* username,
                           libssh2_agent_publickey* identity);

/*
 * libssh2_agent_disconnect()
 *
 * Close a connection to an ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
int libssh2_agent_disconnect(LIBSSH2_AGENT* agent);

/*
 * libssh2_agent_free()
 *
 * Free an ssh-agent handle.  This function also frees the internal
 * collection of public keys.
 */
void libssh2_agent_free(LIBSSH2_AGENT* agent);


/*
 * libssh2_keepalive_config()
 *
 * Set how often keepalive messages should be sent.  WANT_REPLY
 * indicates whether the keepalive messages should request a response
 * from the server.  INTERVAL is number of seconds that can pass
 * without any I/O, use 0 (the default) to disable keepalives.  To
 * avoid some busy-loop corner-cases, if you specify an interval of 1
 * it will be treated as 2.
 *
 * Note that non-blocking applications are responsible for sending the
 * keepalive messages using libssh2_keepalive_send().
 */
void libssh2_keepalive_config (LIBSSH2_SESSION* session,
                               int want_reply,
                               uint interval);

/*
 * libssh2_keepalive_send()
 *
 * Send a keepalive message if needed.  SECONDS_TO_NEXT indicates how
 * many seconds you can sleep after this call before you need to call
 * it again.  Returns 0 on success, or LIBSSH2_ERROR_SOCKET_SEND on
 * I/O errors.
 */
int libssh2_keepalive_send (LIBSSH2_SESSION* session, int* seconds_to_next);

/* NOTE NOTE NOTE
   libssh2_trace() has no function in builds that aren't built with debug
   enabled
 */
int libssh2_trace(LIBSSH2_SESSION* session, int bitmask);
immutable LIBSSH2_TRACE_TRANS     = (1<<1);
immutable LIBSSH2_TRACE_KEX       = (1<<2);
immutable LIBSSH2_TRACE_AUTH      = (1<<3);
immutable LIBSSH2_TRACE_CONN      = (1<<4);
immutable LIBSSH2_TRACE_SCP       = (1<<5);
immutable LIBSSH2_TRACE_SFTP      = (1<<6);
immutable LIBSSH2_TRACE_ERROR     = (1<<7);
immutable LIBSSH2_TRACE_PUBLICKEY = (1<<8);
immutable LIBSSH2_TRACE_SOCKET    = (1<<9);

alias void function(LIBSSH2_SESSION*, void*, const char*, size_t) libssh2_trace_handler_func;
int libssh2_trace_sethandler(LIBSSH2_SESSION* session, void* context,
                             libssh2_trace_handler_func callback);
} // nothrow
} // extern (C)

/*
 * Implementation of convenience functions
 */
LIBSSH2_SESSION* libssh2_session_init() { return libssh2_session_init_ex(null, null, null, null); }

int libssh2_session_disconnect(LIBSSH2_SESSION* session, const char* description)
{
  return libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, description, "");
}

int libssh2_userauth_password(LIBSSH2_SESSION* session, const char* username, 
                              const char* password)
{
  return libssh2_userauth_password_ex(session, username, strlen(username), password, strlen(password), null);
}

int libssh2_userauth_publickey_fromfile(LIBSSH2_SESSION* session, 
                                        const char* username, 
                                        const char* publickey,
                                        const char* privatekey, 
                                        const char* passphrase) 
{
  return libssh2_userauth_publickey_fromfile_ex(session, username, strlen(username), publickey, privatekey, passphrase);
}

int libssh2_userauth_hostbased_fromfile(LIBSSH2_SESSION* session, 
                                        const char* username,
                                        const char* publickey,
                                        const char* privatekey,
                                        const char* passphrase,
                                        const char* hostname,
                                        const char* local_username)
{
  return libssh2_userauth_hostbased_fromfile_ex (session, username, strlen(username), publickey, privatekey, passphrase, 
                                                 hostname, strlen(hostname), local_username, strlen(local_username));
}

int libssh2_userauth_keyboard_interactive(LIBSSH2_SESSION* session,
                                          const char* username,
                                          LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC response_callback)
{
  return libssh2_userauth_keyboard_interactive_ex(session, username, strlen(username), response_callback);
}

LIBSSH2_CHANNEL*
libssh2_channel_open_session(LIBSSH2_SESSION* session, const char* channel_type,
                             uint channel_type_len, uint window_size, 
                             uint packet_size, const char* message)
{
  return libssh2_channel_open_ex(session, "session", strlen("session"),
                                 LIBSSH2_CHANNEL_WINDOW_DEFAULT,
                                 LIBSSH2_CHANNEL_PACKET_DEFAULT, null, 0);
}

LIBSSH2_CHANNEL*
libssh2_channel_direct_tcpip(LIBSSH2_SESSION* session, const char* host, int port)
{
  return libssh2_channel_direct_tcpip_ex(session, host, port, "127.0.0.1", 22);
}

LIBSSH2_LISTENER*
libssh2_channel_forward_listen(LIBSSH2_SESSION* session, int port)
{
  return libssh2_channel_forward_listen_ex(session, null, port, null, 16);
}

int libssh2_channel_setenv(LIBSSH2_CHANNEL* channel,
                           const char* varname,
                           const char* value)
{
  return libssh2_channel_setenv_ex(channel, varname, strlen(varname), value, strlen(value));
}


int libssh2_channel_request_pty(LIBSSH2_CHANNEL *channel,
                                const char* term)
{
  return libssh2_channel_request_pty_ex(channel, term, strlen(term), null, 0,
                                        LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT,
                                        LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX);
}

int libssh2_channel_request_pty_size(LIBSSH2_CHANNEL*channel,
                                     int width, int height)
{
  return libssh2_channel_request_pty_size_ex(channel, width, height, 0, 0);
}

int libssh2_channel_x11_req(LIBSSH2_CHANNEL* channel,
                            int screen_number)
{
  return libssh2_channel_x11_req_ex(channel, 0, null, null, screen_number);
}

int libssh2_channel_shell(LIBSSH2_CHANNEL* channel)
{
  return libssh2_channel_process_startup(channel, "shell", strlen("shell"), null, 0);
}

int libssh2_channel_exec(LIBSSH2_CHANNEL* channel, const char* command)
{
  return libssh2_channel_process_startup(channel, "exec", strlen("shell"), command, strlen(command));
}

int libssh2_channel_subsystem(LIBSSH2_CHANNEL* channel, const char* subsystem)
{
  return libssh2_channel_process_startup(channel, "subsystem", strlen("subsystem"), subsystem, strlen(subsystem));
}

ssize_t libssh2_channel_read(LIBSSH2_CHANNEL* channel, char *buf, size_t buflen)
{
  return libssh2_channel_read_ex(channel, 0, buf, buflen);
}

ssize_t libssh2_channel_read_stderr(LIBSSH2_CHANNEL* channel, char *buf, size_t buflen)
{
  return libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, buflen);
}

ulong libssh2_channel_window_read(LIBSSH2_CHANNEL* channel)
{
  return libssh2_channel_window_read_ex(channel, null, null);
}

ssize_t libssh2_channel_write(LIBSSH2_CHANNEL* channel, const char* buf, size_t buflen)
{
  return libssh2_channel_write_ex(channel, 0, buf, buflen);
}

ssize_t libssh2_channel_write_stderr(LIBSSH2_CHANNEL* channel, const char* buf, size_t buflen)
{
  return libssh2_channel_write_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, buflen);
}

ulong libssh2_channel_window_write(LIBSSH2_CHANNEL* channel)
{
  return libssh2_channel_window_write_ex(channel, null);
}

int libssh2_channel_flush(LIBSSH2_CHANNEL* channel)
{
  return libssh2_channel_flush_ex(channel, 0);
}

int libssh2_channel_flush_stderr(LIBSSH2_CHANNEL* channel)
{
  return libssh2_channel_flush_ex(channel, SSH_EXTENDED_DATA_STDERR);
}

// TODO There was a libssh2_int64_t instead of size_t for path. But that does
//      not make sense if ..._send_ex takes size_t as argument for 32bit program
LIBSSH2_CHANNEL*
libssh2_scp_send(LIBSSH2_SESSION* session, const char* path, int mode,
                 size_t size)
{
  return libssh2_scp_send_ex(session, path, mode, size, 0, 0);
}