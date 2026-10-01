#ifndef CURL_CONFIG_H
#define CURL_CONFIG_H

/***************************************************************************
 * curl_config.h for Android NDK (arm64-v8a, API 21+)
 ***************************************************************************/

/* --- 平台与头文件 --- */
#define STDC_HEADERS 1
#define HAVE_UNISTD_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STDINT_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_WAIT_H 1
#define HAVE_NETDB_H 1
#define HAVE_NET_IF_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_NETINET_UDP_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_LINUX_TCP_H 1
#define HAVE_POLL_H 1
#define HAVE_PTHREAD_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_LOCALE_H 1
#define HAVE_LIBGEN_H 1
#define HAVE_PWD_H 1
#define HAVE_DIRENT_H 1
#define HAVE_UTIME_H 1
#define HAVE_IFADDRS_H 1
#define HAVE_STDBOOL_H 1
#define HAVE_STDATOMIC_H 1
#define HAVE_SYS_EVENTFD_H 1

/* --- 类型大小 (arm64) --- */
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_OFF_T 8
#define SIZEOF_CURL_OFF_T 8
#define SIZEOF_SIZE_T 8
#define SIZEOF_TIME_T 8
#define SIZEOF_CURL_SOCKET_T 4

/* --- 函数可用性 --- */
#define HAVE_GETTIMEOFDAY 1
#define HAVE_SELECT 1
#define HAVE_SOCKET 1
#define HAVE_RECV 1
#define HAVE_SEND 1
#define HAVE_SENDMSG 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETADDRINFO_THREADSAFE 1
#define HAVE_FREEADDRINFO 1
#define HAVE_GETHOSTNAME 1
#define HAVE_GETPEERNAME 1
#define HAVE_GETSOCKNAME 1
#define HAVE_GETIFADDRS 1
#define HAVE_IF_NAMETOINDEX 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_FCNTL 1
#define HAVE_FCNTL_O_NONBLOCK 1
#define HAVE_IOCTL_FIONBIO 1
#define HAVE_IOCTL_SIOCGIFADDR 1
#define HAVE_SETSOCKOPT_SO_NONBLOCK 1
#define HAVE_POLL_FINE 1
#define HAVE_PIPE 1
#define HAVE_EVENTFD 1
#define HAVE_SOCKETPAIR 1
#define HAVE_SIGACTION 1
#define HAVE_SIGINTERRUPT 1
#define HAVE_SIGNAL 1
#define HAVE_SNPRINTF 1
#define HAVE_STRCASECMP 1
#define HAVE_STRDUP 1
#define HAVE_STRERROR_R 1
#define HAVE_GLIBC_STRERROR_R 1
#undef HAVE_GLIBC_STRERROR_R
#define HAVE_POSIX_STRERROR_R 1

#define HAVE_STRTOK_R 1
#define HAVE_STRTOLL 1
#define HAVE_MEMRCHR 1
#define HAVE_FSEEKO 1
#define HAVE_FTRUNCATE 1
#define HAVE_SETLOCALE 1
#define HAVE_SETRLIMIT 1
#define HAVE_GETRLIMIT 1
#define HAVE_GETEUID 1
#define HAVE_GETPWUID 1
#define HAVE_GMTIME_R 1
#define HAVE_ALARM 1
#define HAVE_BASENAME 1
#define HAVE_FNMATCH 1
#define HAVE_CLOCK_GETTIME_MONOTONIC 1
#define HAVE_SCHED_YIELD 1
#define HAVE_UTIME 1
#define HAVE_UTIMES 1
#define HAVE_OPENDIR 1
#define HAVE_READDIR 1
#define HAVE_CLOSESOCKET 0  /* Windows only */

/* --- struct / typedef --- */
#define HAVE_STRUCT_TIMEVAL 1
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1
#define HAVE_SA_FAMILY_T 1
#define HAVE_BOOL_T 1
#define HAVE_LONGLONG 1
#define HAVE_SUSECONDS_T 1
#define HAVE_ATOMIC 1
#define HAVE_MSG_NOSIGNAL 1

/* --- recv/send 原型 (Android/BSD) --- */
#define RECV_TYPE_ARG1 int
#define RECV_TYPE_ARG2 void *
#define RECV_TYPE_ARG3 size_t
#define RECV_TYPE_ARG4 int
#define RECV_TYPE_RETV ssize_t

#define SEND_TYPE_ARG1 int
#undef SEND_QUAL_ARG2
#define SEND_TYPE_ARG2 const void *


#define SEND_TYPE_ARG3 size_t
#define SEND_TYPE_ARG4 int
#define SEND_TYPE_RETV ssize_t


/* --- SSL 后端: OpenSSL --- */
#define CURL_USE_OPENSSL 1
#define USE_OPENSSL 1
#define HAVE_OPENSSL_SSL_H 1
#define HAVE_OPENSSL_ERR_H 1
#define HAVE_OPENSSL_RSA_H 1
#define HAVE_OPENSSL_CRYPTO_H 1
#define HAVE_OPENSSL_PEM_H 1
#define HAVE_OPENSSL_X509_H 1
#define HAVE_OPENSSL_PKCS12_H 1
#define HAVE_OPENSSL_ENGINE_H 1
#define HAVE_OPENSSL_SRP 1
#define HAVE_SSL_SET0_WBIO 1
#define HAVE_OPENSSL_VERSION

/* --- 禁用不需要的协议/功能 (精简体积) --- */
#define CURL_DISABLE_LDAP 1
#define CURL_DISABLE_LDAPS 1
#define CURL_DISABLE_RTSP 1
#define CURL_DISABLE_DICT 1
#define CURL_DISABLE_TFTP 1
#define CURL_DISABLE_POP3 1
#define CURL_DISABLE_IMAP 1
#define CURL_DISABLE_SMTP 1
#define CURL_DISABLE_GOPHER 1
#define CURL_DISABLE_MQTT 1
#define CURL_DISABLE_SMB 1
#define CURL_DISABLE_FTP 1
#define CURL_DISABLE_TELNET 1
#define CURL_DISABLE_FILE 1
#define CURL_DISABLE_MIME 1
#define CURL_DISABLE_BINDLOCAL 1
#define CURL_DISABLE_NETRC 1
#define CURL_DISABLE_PARSEDATE 1
#define CURL_DISABLE_PROGRESS_METER 1
#define CURL_DISABLE_VERBOSE_STRINGS 1
#define CURL_DISABLE_ALTSVC 1
#define CURL_DISABLE_HSTS 1
#define CURL_DISABLE_COOKIES 1
#define CURL_DISABLE_BASIC_AUTH 1
#define CURL_DISABLE_BEARER_AUTH 1
#define CURL_DISABLE_DIGEST_AUTH 1
#define CURL_DISABLE_KERBEROS_AUTH 1
#define CURL_DISABLE_NEGOTIATE_AUTH 1
#define CURL_DISABLE_AWS 1
#define CURL_DISABLE_FORM_API 1
#define CURL_DISABLE_GETOPTIONS 1
#define CURL_DISABLE_HEADERS_API 1
#define CURL_DISABLE_LIBCURL_OPTION 1
#define CURL_DISABLE_SOCKETPAIR 1
#define CURL_DISABLE_DOH 1

/* --- 其他 --- */
#define CURL_CA_BUNDLE "/system/etc/security/cacerts/ca-certificates.crt"
#define CURL_CA_PATH "/system/etc/security/cacerts"
#define USE_IPV6 1
#define USE_THREADS_POSIX 1
#define USE_UNIX_SOCKETS 1
#define VERSION "8.5.0"
#define OS "Android"

/* Windows / 其他平台无关 */
#undef USE_WIN32_CRYPTO
#undef USE_WIN32_LDAP
#undef USE_WINDOWS_SSPI
#undef USE_SCHANNEL
#undef HAVE_CLOSESOCKET
#undef HAVE_IOCTLSOCKET
#undef HAVE_SETMODE
#undef HAVE_EXTRA_STRICMP_H
#undef HAVE_STRCMPI
#undef HAVE_STRICMP


#endif /* CURL_CONFIG_H */
