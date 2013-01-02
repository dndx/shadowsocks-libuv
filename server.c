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

#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>
#include "encrypt.h"
#include "utils.h"
#include "server.h"

unsigned char encrypt_table[TABLE_SIZE], decrypt_table[TABLE_SIZE];

static void established_free_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	free(ctx);
}

// Close remote and free ctx
static void client_established_shutdown_complete(uv_shutdown_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;
	HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, established_free_cb);
	free(req);
}

// Close client and free ctx
static void remote_established_shutdown_complete(uv_shutdown_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;
	HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->remote, established_free_cb);
	free(req);
}

// Shutdown client
static void remote_established_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	uv_read_stop((uv_stream_t *)(void *)&ctx->client);
	uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
	req->data = ctx;
	int n = uv_shutdown(req, (uv_stream_t *)(void *)&ctx->client, client_established_shutdown_complete);
	if (n) {
		LOGE("Shutdown client side write stream failed!");
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, established_free_cb);
		free(req);
	}
}

// Close client then close remote
static void client_established_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	uv_read_stop((uv_stream_t *)(void *)&ctx->remote);
	uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
	req->data = ctx;
	int n = uv_shutdown(req, (uv_stream_t *)(void *)&ctx->remote, remote_established_shutdown_complete);
	if (n) {
		LOGE("Shutdown remote side write stream failed!");
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->remote, established_free_cb);
		free(req);
	}
}

static void remote_established_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
	int n;
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) { // EOF
		if (buf.len) // If buf is set, we need to free it
			free(buf.base);
		LOGI("Remote EOF, Closing");
		HANDLE_CLOSE((uv_handle_t*)stream, remote_established_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf.base);
		return;
	}

	shadow_encrypt((unsigned char *)buf.base, encrypt_table, nread);

	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!req) {
		HANDLE_CLOSE((uv_handle_t*)stream, remote_established_close_cb);
		FATAL("malloc() failed!");
	}
	req->data = buf.base;
	buf.len = nread;
	n = uv_write(req, (uv_stream_t *)(void *)&ctx->client, &buf, 1, after_write_cb);
	if (n) {
		LOGE("Write to client failed!");
		free(req);
		HANDLE_CLOSE((uv_handle_t*)stream, remote_established_close_cb);
		return;
	}
	if (ctx->buffer_len == MAX_PENDING_PER_CONN - 1) { // buffer_len used as pending write request counter
		uv_read_stop(stream);
	}
	ctx->buffer_len++;
}

static void after_write_cb(uv_write_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->handle->data;
	if (status) {
		if (uv_last_error(req->handle->loop).code != UV_ECANCELED) {
			if ((uv_tcp_t *)req->handle == &ctx->client) {
				HANDLE_CLOSE((uv_handle_t *)req->handle, client_established_close_cb);
			} else {
				HANDLE_CLOSE((uv_handle_t *)req->handle, remote_established_close_cb);
			}
		}
		free(req->data); // Free buffer
		free(req);
		return;
	}

	if ((uv_tcp_t *)req->handle == &ctx->client && !uv_is_closing((uv_handle_t *)(void *)&ctx->remote)) {
		if (ctx->buffer_len <= MAX_PENDING_PER_CONN) {
			int n = uv_read_start((uv_stream_t *)(void *)&ctx->remote, established_alloc_cb, remote_established_read_cb);
			if (n) {
				SHOW_UV_ERROR(ctx->client.loop);
				free(req->data); // Free buffer
				free(req);
				return;
			}
		}
		ctx->buffer_len--;
	}

	free(req->data); // Free buffer
	free(req);
}

static void client_established_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
	int n;
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) { // EOF
		if (buf.len) // If buf is set, we need to free it
			free(buf.base);
		LOGI("Client EOF, Closing");
		HANDLE_CLOSE((uv_handle_t*)stream, client_established_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf.base);
		return;
	}

	shadow_decrypt((unsigned char *)buf.base, decrypt_table, nread);

	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!req) {
		HANDLE_CLOSE((uv_handle_t*)stream, client_established_close_cb);
		FATAL("malloc() failed!");
	}
	req->data = buf.base;
	buf.len = nread;
	n = uv_write(req, (uv_stream_t *)(void *)&ctx->remote, &buf, 1, after_write_cb);
	if (n) {
		LOGE("Write to remote failed!");
		free(req);
		HANDLE_CLOSE((uv_handle_t*)stream, client_established_close_cb);
		return;
	}

	// LOGI("Writed to remote");
}

static uv_buf_t established_alloc_cb(uv_handle_t* handle, size_t suggested_size)
{
	#ifdef BUFFER_LIMIT
	void *buf = malloc(BUFFER_LIMIT);
	#else
	void *buf = malloc(suggested_size);
	#endif /* BUFFER_LIMIT */
	if (!buf) {
		FATAL("malloc() failed!");
	}
	#ifdef BUFFER_LIMIT
	return uv_buf_init(buf, BUFFER_LIMIT);
	#else
	return uv_buf_init(buf, suggested_size);
	#endif /* BUFFER_LIMIT */
}

// Failed during handshake
static void handshake_client_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	if (ctx->handshake_buffer) {
		free(ctx->handshake_buffer);
		ctx->handshake_buffer = NULL;
	}
	free(ctx);
}

static void connect_to_remote_cb(uv_connect_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;
	free(req);
	if (status) {
		SHOW_UV_ERROR(ctx->client.loop);
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
		return;
	}

	LOGI("Connected to remote server");

	uv_buf_t buf;
	buf.base = (char *)ctx->handshake_buffer;
	buf.len = HANDSHAKE_BUFFER_SIZE;

	shadow_encrypt((unsigned char *)buf.base, encrypt_table, ctx->buffer_len);

	client_established_read_cb((uv_stream_t *)(void *)&ctx->client, ctx->buffer_len, buf); // Deal with ramaining data, only once
	ctx->handshake_buffer = NULL;
	ctx->buffer_len = 0;
	int n = uv_read_start((uv_stream_t *)(void *)&ctx->client, established_alloc_cb, client_established_read_cb);
	if (n) {
		SHOW_UV_ERROR(ctx->client.loop);
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
		return;
	}
	n = uv_read_start((uv_stream_t *)(void *)&ctx->remote, established_alloc_cb, remote_established_read_cb);
	if (n) {
		SHOW_UV_ERROR(ctx->client.loop);
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
		return;
	}
}

static void client_handshake_domain_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	server_ctx *ctx = (server_ctx *)resolver->data;
	if (status) {
		if (uv_last_error(ctx->client.loop).code == UV_ENOENT) {
			LOGI("Resolve error, NXDOMAIN");
		} else {
			SHOW_UV_ERROR(ctx->client.loop);
		}
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, handshake_client_close_cb);
		uv_freeaddrinfo(res);
		free(resolver);
		return;
	}

	ctx->remote_ip = ((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr;
	int n = uv_read_start((uv_stream_t *)(void *)&ctx->client, client_handshake_alloc_cb, client_handshake_read_cb);
	if (n) {
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, handshake_client_close_cb);
		SHOW_UV_ERROR(ctx->client.loop);
	}

	uv_freeaddrinfo(res);
	free(resolver);
}

static void client_handshake_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
	int n;
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) {
		if (buf.len) // If buf is set, we need to free it
			free(buf.base);
		HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf.base);
		return;
	}

	memcpy(ctx->handshake_buffer + ctx->buffer_len, buf.base, buf.len);
	shadow_decrypt(ctx->handshake_buffer + ctx->buffer_len, decrypt_table, buf.len);

	ctx->buffer_len += nread;

	if (!ctx->handshake_buffer) {
		FATAL("Should no call this anmore");
	}
	free(buf.base);

	if (!ctx->remote_ip) {
		if (ctx->buffer_len < 2) // Not interpretable
			return;
		uint8_t addrtype = ctx->handshake_buffer[0];
		if (addrtype == ADDRTYPE_IPV4) {
			if (ctx->buffer_len < 5)
				return;
			ctx->remote_ip = *((uint32_t *)(ctx->handshake_buffer + 1));
			SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 5, HANDSHAKE_BUFFER_SIZE);
			ctx->buffer_len -= 5;
			// TODO: Print out
		} else if (addrtype == ADDRTYPE_DOMAIN) {
			uint8_t domain_len = ctx->handshake_buffer[1];
			if (!domain_len) { // Domain length is zero
				LOGE("Domain length is zero");
				HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
				return;
			}
			if (ctx->buffer_len < domain_len + 2)
				return;
			char domain[domain_len+1];
			domain[domain_len] = 0;
			memcpy(domain, ctx->handshake_buffer+2, domain_len);
			struct addrinfo hints;
    		hints.ai_family = AF_INET; // IPv4 Only
    		hints.ai_socktype = SOCK_STREAM;
    		hints.ai_protocol = IPPROTO_TCP;
    		hints.ai_flags = 0;
			uv_getaddrinfo_t *resolver = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));
			if (!resolver) {
				HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
				FATAL("malloc() failed!");
			}
			resolver->data = ctx; // We need to locate back the stream
			LOGI("Domain is: %s", domain);
			n = uv_getaddrinfo(stream->loop, resolver, client_handshake_domain_resolved, domain, NULL, &hints);
			if (n) {
				SHOW_UV_ERROR(stream->loop);
				HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
				free(resolver);
				return;
			}
			SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 2+domain_len, HANDSHAKE_BUFFER_SIZE);
			ctx->buffer_len -= 2 + domain_len;
			uv_read_stop(stream); // Pause the reading process, wait for resolve result
			return;
		}
	} // !ctx->remote_ip

	if (!ctx->remote_port) {
		if (ctx->buffer_len < 2) // Not interpretable
			return;
		ctx->remote_port = *((uint16_t *)ctx->handshake_buffer);
		if (!ctx->remote_port) {
			LOGE("Remote port is zero");
			HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
			return;
		}
		SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 2, HANDSHAKE_BUFFER_SIZE);
		ctx->buffer_len -= 2;
		// Try connect now
		n = uv_tcp_init(stream->loop, &ctx->remote);
		if (n)
			SHOW_UV_ERROR_AND_EXIT(stream->loop);
		uv_connect_t *req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!req) {
			HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
			FATAL("malloc() failed!");
		}
		req->data = ctx;
		struct sockaddr_in remote_addr;
		memset(&remote_addr, 0, sizeof(remote_addr));
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_addr.s_addr = ctx->remote_ip;
		remote_addr.sin_port = ctx->remote_port;
		n = uv_tcp_connect(req, &ctx->remote, remote_addr, connect_to_remote_cb);
		if (n) {
			SHOW_UV_ERROR(stream->loop);
			HANDLE_CLOSE((uv_handle_t*)stream, handshake_client_close_cb);
			free(req);
			return;
		}
		uv_read_stop(stream); // We are done handshake
	}
}

static uv_buf_t client_handshake_alloc_cb(uv_handle_t* handle, size_t suggested_size)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	void *buf = malloc(HANDSHAKE_BUFFER_SIZE - ctx->buffer_len);
	if (!buf) {
		HANDLE_CLOSE(handle, handshake_client_close_cb);
		FATAL("malloc() failed!");
	}
	return uv_buf_init(buf, HANDSHAKE_BUFFER_SIZE - ctx->buffer_len);
}

static void connect_cb(uv_stream_t* listener, int status)
{
	int n;

	if (status) {
		SHOW_UV_ERROR(listener->loop);
		return;
	}

	server_ctx *ctx = calloc(1, sizeof(server_ctx));
	ctx->client.data = ctx;
	ctx->remote.data = ctx;

	ctx->handshake_buffer = calloc(1, HANDSHAKE_BUFFER_SIZE);
	if (!ctx || !ctx->handshake_buffer)
		SHOW_UV_ERROR_AND_EXIT(listener->loop);

	n = uv_tcp_init(listener->loop, &ctx->client);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(listener->loop);

	n = uv_accept(listener, (uv_stream_t *)(void *)&ctx->client);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(listener->loop);

	n = uv_tcp_nodelay(&ctx->client, 1);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(listener->loop);

	n = uv_read_start((uv_stream_t *)(void *)&ctx->client, client_handshake_alloc_cb, client_handshake_read_cb);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(listener->loop);
}

int main(int argc, char const *argv[])
{
	LOGI(WELCOME_MESSAGE);
	make_tables((unsigned char *)PASSWORD, encrypt_table, decrypt_table);
	LOGI("Encrypt and decrypt table generated");
	
	int n;
	uv_loop_t *loop = uv_default_loop();
	uv_tcp_t listener;

	struct sockaddr_in addr = uv_ip4_addr(SERVER_LISTEN, SERVER_PORT);

	n = uv_tcp_init(loop, &listener);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(loop);

	n = uv_tcp_bind(&listener, addr);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(loop);

	n = uv_listen((uv_stream_t*)(void *)&listener, 5, connect_cb);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(loop);
	LOGI("Listening on " SERVER_LISTEN ":" TOSTR(SERVER_PORT));

	return uv_run(loop);
}
