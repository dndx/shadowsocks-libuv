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

#ifndef UTILS_H_
#define UTILS_H_
#include <stddef.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define STR(x) #x
#define TOSTR(x) STR(x)

#define LOGI(format, ...) do {\
						  time_t now = time(NULL);\
						  char timestr[20];\
						  strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
                          fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, ##__VA_ARGS__);}\
                          while(0)
#define LOGE(format, ...) do {\
						  time_t now = time(NULL);\
						  char timestr[20];\
						  strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
                          fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format " on File: %s Line: %s\n", timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));}\
                          while(0)
#define LOGCONN(stream, message) do {\
                            struct sockaddr_storage remote_addr;\
                            memset(&remote_addr, 0, sizeof(remote_addr));\
                            int namelen = sizeof(remote_addr);\
                            if (uv_tcp_getpeername((stream), (struct sockaddr *)&remote_addr, &namelen))\
                                break;\
                            char *ip_str = sockaddr_to_str(&remote_addr);\
                            if (!ip_str)\
                              FATAL("unknown address type");\
                            LOGI(message, ip_str);\
                            free(ip_str);\
                        } while (0)
#define FATAL(format, ...) do {\
						  time_t now = time(NULL);\
						  char timestr[20];\
						  strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
                          fprintf(stderr, "\e[01;31m %s FATAL: \e[0m" format " on File: %s Line: %s\n", timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));exit(1);}\
                          while(0)
#define SHOW_UV_ERROR(loop) do {LOGE("libuv error: %s", uv_strerror(uv_last_error(loop)));} while (0)
#define SHOW_UV_ERROR_AND_EXIT(loop) do {SHOW_UV_ERROR(loop);LOGE("Fatal error, terminating... ");exit(1);} while (0)
//#define POINT_TO_STRUCT(field_ptr, field_name, struct_name) ((struct_name *)((char *)(field_ptr) - offsetof(struct_name, field_name)))
#define SHIFT_BYTE_ARRAY_TO_LEFT(arr, offset, array_size) memmove((arr), (arr) + (offset), (array_size) - (offset))
#define SHOW_BUFFER(buf, len) do {\
                              for (int i=0; i<len; i++)\
                              	putchar(buf[i]);\
                              } while (0)
#define HANDLE_CLOSE(handle, callback) do {\
                                       if (!(uv_is_closing((uv_handle_t *)(void *)&ctx->remote) || uv_is_closing((uv_handle_t *)(void *)&ctx->client)))\
                                       	   uv_close((uv_handle_t *)handle, callback);\
                                       	} while (0)

char *sockaddr_to_str(struct sockaddr_storage *addr);
void setup_signal_handler(uv_loop_t *loop);

#endif /* !UTILS_H_ */
