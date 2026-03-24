/**
 * remote_transport.c
 * TCP + TLS 1.2 (SChannel) transport. Uses only Windows APIs (Ws2_32, Secur32).
 */
#include "pch.h"
#include "remote_transport.h"
#include "remote_log.h"
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <security.h>
#include <schnlsp.h>
#include <stdio.h>
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof((a)[0]))
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")

#define TLS_MAX_PACKET (16384 + 512)

typedef struct transport_state {
    SOCKET sock;
    CredHandle cred_handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;
    int used;
    int available;
    char* decrypted;
    char incoming[TLS_MAX_PACKET];
} transport_state_t;

remote_transport_handle_t remote_transport_connect(const char* host, unsigned short port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        remote_log("transport: WSAStartup failed");
        return NULL;
    }

    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char port_str[8];
    sprintf_s(port_str, sizeof(port_str), "%u", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        remote_log("transport: getaddrinfo(%s:%s) failed", host, port_str);
        WSACleanup();
        return NULL;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        WSACleanup();
        return NULL;
    }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        remote_log("transport: TCP connect failed");
        closesocket(s);
        freeaddrinfo(res);
        WSACleanup();
        return NULL;
    }
    freeaddrinfo(res);

    transport_state_t* t = (transport_state_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(transport_state_t));
    if (!t) {
        closesocket(s);
        WSACleanup();
        return NULL;
    }
    t->sock = s;

    SCHANNEL_CRED cred = { 0 };
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2;

    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &t->cred_handle, NULL) != SEC_E_OK) {
        HeapFree(GetProcessHeap(), 0, t);
        closesocket(s);
        WSACleanup();
        return NULL;
    }

    t->received = t->used = t->available = 0;
    t->decrypted = NULL;
    CtxtHandle* pctx = NULL;
    for (;;) {
        SecBuffer inbufs[2] = { 0 };
        inbufs[0].BufferType = SECBUFFER_TOKEN;
        inbufs[0].pvBuffer = t->incoming;
        inbufs[0].cbBuffer = t->received;
        inbufs[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbufs[1] = { 0 };
        outbufs[0].BufferType = SECBUFFER_TOKEN;
        SecBufferDesc indesc = { SECBUFFER_VERSION, 2, inbufs };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, 1, outbufs };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS st = InitializeSecurityContextA(&t->cred_handle, pctx, (SEC_CHAR*)host, flags, 0, 0, pctx ? &indesc : NULL, 0, &t->context, &outdesc, &flags, NULL);
        pctx = &t->context;

        if (inbufs[1].BufferType == SECBUFFER_EXTRA) {
            MoveMemory(t->incoming, t->incoming + (t->received - inbufs[1].cbBuffer), inbufs[1].cbBuffer);
            t->received = inbufs[1].cbBuffer;
        } else {
            t->received = 0;
        }

        if (st == SEC_E_OK)
            break;
        if (st == SEC_I_INCOMPLETE_CREDENTIALS || (st != SEC_I_CONTINUE_NEEDED && st != SEC_E_INCOMPLETE_MESSAGE)) {
            remote_log("transport: TLS handshake failed, status 0x%X", (unsigned)st);
            DeleteSecurityContext(&t->context);
            FreeCredentialsHandle(&t->cred_handle);
            HeapFree(GetProcessHeap(), 0, t);
            closesocket(s);
            WSACleanup();
            return NULL;
        }
        if (st == SEC_I_CONTINUE_NEEDED && outbufs[0].pvBuffer) {
            int rem = outbufs[0].cbBuffer;
            char* ptr = (char*)outbufs[0].pvBuffer;
            while (rem > 0) {
                int sent = send(t->sock, ptr, rem, 0);
                if (sent <= 0) break;
                ptr += sent;
                rem -= sent;
            }
            FreeContextBuffer(outbufs[0].pvBuffer);
            if (rem != 0) {
                DeleteSecurityContext(&t->context);
                FreeCredentialsHandle(&t->cred_handle);
                HeapFree(GetProcessHeap(), 0, t);
                closesocket(s);
                WSACleanup();
                return NULL;
            }
        }
        if (t->received >= (int)sizeof(t->incoming)) {
            DeleteSecurityContext(&t->context);
            FreeCredentialsHandle(&t->cred_handle);
            HeapFree(GetProcessHeap(), 0, t);
            closesocket(s);
            WSACleanup();
            return NULL;
        }
        int r = recv(t->sock, t->incoming + t->received, (int)(sizeof(t->incoming) - t->received), 0);
        if (r <= 0) {
            DeleteSecurityContext(&t->context);
            FreeCredentialsHandle(&t->cred_handle);
            HeapFree(GetProcessHeap(), 0, t);
            closesocket(s);
            WSACleanup();
            return NULL;
        }
        t->received += r;
    }

    if (QueryContextAttributesA(&t->context, SECPKG_ATTR_STREAM_SIZES, &t->sizes) != SEC_E_OK) {
        DeleteSecurityContext(&t->context);
        FreeCredentialsHandle(&t->cred_handle);
        HeapFree(GetProcessHeap(), 0, t);
        closesocket(s);
        WSACleanup();
        return NULL;
    }
    return (remote_transport_handle_t)t;
}

static int do_send(transport_state_t* t, const unsigned char* data, unsigned int len) {
    while (len > 0) {
        int chunk = (int)(len < (unsigned int)t->sizes.cbMaximumMessage ? len : (unsigned int)t->sizes.cbMaximumMessage);
        char enc[TLS_MAX_PACKET];
        if (t->sizes.cbHeader + chunk + t->sizes.cbTrailer > TLS_MAX_PACKET)
            return 0;
        SecBuffer bufs[3] = { 0 };
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = enc;
        bufs[0].cbBuffer = t->sizes.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = enc + t->sizes.cbHeader;
        bufs[1].cbBuffer = chunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = enc + t->sizes.cbHeader + chunk;
        bufs[2].cbBuffer = t->sizes.cbTrailer;
        memcpy(bufs[1].pvBuffer, data, chunk);
        SecBufferDesc desc = { SECBUFFER_VERSION, 3, bufs };
        if (EncryptMessage(&t->context, 0, &desc, 0) != SEC_E_OK)
            return 0;
        int total = t->sizes.cbHeader + chunk + t->sizes.cbTrailer;
        int sent = 0;
        while (sent < total) {
            int n = send(t->sock, enc + sent, total - sent, 0);
            if (n <= 0) return 0;
            sent += n;
        }
        data += chunk;
        len -= chunk;
    }
    return 1;
}

int remote_transport_send(remote_transport_handle_t h, const unsigned char* data, unsigned int len) {
    if (!h || !data) return 0;
    return do_send((transport_state_t*)h, data, len);
}

static int do_recv_byte(transport_state_t* t, unsigned char* buf, unsigned int len) {
    transport_state_t* s = t;
    unsigned int copied = 0;
    while (copied < len) {
        if (s->decrypted && s->available > 0) {
            unsigned int take = (len - copied) < (unsigned int)s->available ? (len - copied) : (unsigned int)s->available;
            memcpy(buf + copied, s->decrypted, take);
            copied += take;
            s->decrypted += take;
            s->available -= (int)take;
            if (s->available == 0) {
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->decrypted = NULL;
            }
            continue;
        }
        if (s->received > 0) {
            SecBuffer bufs[4] = { 0 };
            bufs[0].BufferType = SECBUFFER_DATA;
            bufs[0].pvBuffer = s->incoming;
            bufs[0].cbBuffer = s->received;
            SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
            SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
            if (sec == SEC_E_OK) {
                if (bufs[1].BufferType == SECBUFFER_DATA) {
                    s->decrypted = bufs[1].pvBuffer;
                    s->available = bufs[1].cbBuffer;
                    s->used = s->received - (bufs[3].BufferType == SECBUFFER_EXTRA ? bufs[3].cbBuffer : 0);
                }
                continue;
            }
            if (sec == SEC_I_CONTEXT_EXPIRED)
                return 0;
            if (sec != SEC_E_INCOMPLETE_MESSAGE)
                return 0;
        }
        if (s->received >= TLS_MAX_PACKET) return 0;
        int r = recv(s->sock, s->incoming + s->received, TLS_MAX_PACKET - s->received, 0);
        if (r <= 0) return 0;
        s->received += r;
    }
    return 1;
}

int remote_transport_recv(remote_transport_handle_t h, unsigned char* buf, unsigned int len) {
    if (!h || !buf) return 0;
    return do_recv_byte((transport_state_t*)h, buf, len);
}

int remote_transport_poll_read(remote_transport_handle_t h, unsigned int timeout_ms) {
    if (!h) return -1;
    transport_state_t* t = (transport_state_t*)h;

    if (t->available > 0) return 1; /* already decrypted bytes pending */
    if (t->received > 0) return 1;  /* encrypted bytes buffered, DecryptMessage may consume */

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(t->sock, &rfds);

    struct timeval tv;
    tv.tv_sec = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);

    int r = select(0, &rfds, NULL, NULL, &tv);
    if (r > 0 && FD_ISSET(t->sock, &rfds)) return 1;
    if (r == 0) return 0;
    return -1;
}

void remote_transport_close(remote_transport_handle_t h) {
    if (!h) return;
    transport_state_t* t = (transport_state_t*)h;
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer inb = { sizeof(type), SECBUFFER_TOKEN, &type };
    SecBufferDesc ind = { SECBUFFER_VERSION, 1, &inb };
    ApplyControlToken(&t->context, &ind);
    SecBuffer outb = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outd = { SECBUFFER_VERSION, 1, &outb };
    DWORD fl = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&t->cred_handle, &t->context, NULL, fl, 0, 0, &outd, 0, NULL, &outd, &fl, NULL) == SEC_E_OK && outb.pvBuffer) {
        int rem = outb.cbBuffer;
        char* p = (char*)outb.pvBuffer;
        while (rem > 0) { int d = send(t->sock, p, rem, 0); if (d <= 0) break; p += d; rem -= d; }
        FreeContextBuffer(outb.pvBuffer);
    }
    shutdown(t->sock, SD_BOTH);
    closesocket(t->sock);
    DeleteSecurityContext(&t->context);
    FreeCredentialsHandle(&t->cred_handle);
    HeapFree(GetProcessHeap(), 0, t);
    WSACleanup();
}
