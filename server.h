// Copyright (c) 2012 dndx (idndx.com)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef SERVER_H_
#define SERVER_H_

#include <stdint.h>

#define SHADOW_MAJOR_VERSION 0
#define SHADOW_MINOR_VERSION 1
#define WELCOME_MESSAGE "Shadowsocks Version:" TOSTR(SHADOW_MAJOR_VERSION) "." TOSTR(SHADOW_MINOR_VERSION) \
                        " libuv(" TOSTR(UV_VERSION_MAJOR) "." TOSTR(UV_VERSION_MINOR) ")"\
                        " Written by Dndx(idndx.com)"
#define USAGE "Shadowsocks Version:" TOSTR(SHADOW_MAJOR_VERSION) "." TOSTR(SHADOW_MINOR_VERSION) \
                        " libuv(" TOSTR(UV_VERSION_MAJOR) "." TOSTR(UV_VERSION_MINOR) ")"\
                        " Written by Dndx(idndx.com)\n"\
                        "Usage: %s [-l listen] [-p port] [-k keyfile] [-f pidfile]\n\n"\
                        "Options:\n"\
                        "  -l : Override the listening IP\n"\
                        "  -p : Override the listening port\n"\
                        "  -k : Override the listening password\n"\
                        "  -f : Override the pidfile path\n\n"
                        
#define ADDRTYPE_IPV4 1
#define ADDRTYPE_DOMAIN 3

typedef struct
{
	uv_tcp_t client;
	uv_tcp_t remote;
	struct sockaddr client_info;
	uint32_t remote_ip;   // Network order
	uint16_t remote_port; // Network order
	unsigned char *handshake_buffer;
	size_t buffer_len; // Also use as pending cound after handshake
} server_ctx;

static void client_handshake_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf);
static uv_buf_t client_handshake_alloc_cb(uv_handle_t* handle, size_t suggested_size);
static void after_write_cb(uv_write_t* req, int status);
static uv_buf_t established_alloc_cb(uv_handle_t* handle, size_t suggested_size);

#endif /* !SERVER_H_ */
