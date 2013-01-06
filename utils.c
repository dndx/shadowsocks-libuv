#include "config.h"
#include "utils.h"
#include <signal.h>
#include <uv.h>

// Convert IPv4 or IPv6 sockaddr to string, DO NOT forget to free the buffer after use!
char *sockaddr_to_str(struct sockaddr_storage *addr)
{
	char *result;
	if (addr->ss_family == AF_INET) { // IPv4
		result = (char *)malloc(INET_ADDRSTRLEN);
		if (!result)
			FATAL("malloc() failed!");
		int n = uv_ip4_name((struct sockaddr_in*)addr, result, INET_ADDRSTRLEN);
		if (n) {
			free(result);
			result = NULL;
		}
	} else if (addr->ss_family == AF_INET6) { // IPv4
		result = (char *)malloc(INET6_ADDRSTRLEN);
		if (!result)
			FATAL("malloc() failed!");
		int n = uv_ip6_name((struct sockaddr_in6*)addr, result, INET6_ADDRSTRLEN);
		if (n) {
			free(result);
			result = NULL;
		}
	} else {
		result =  NULL;
	}
	return result;
}

void signal_cb(uv_signal_t* handle, int signum)
{
	extern struct encryptor crypto;

	if (uv_signal_stop(handle))
		SHOW_UV_ERROR_AND_EXIT(handle->loop);
	free(handle);
	LOGI("Ctrl+C Pressed");

	if (crypto.encrypt_table) {
		free(crypto.encrypt_table);
		free(crypto.decrypt_table);
	} else {
		free(crypto.key);
	}

	uv_loop_delete(uv_default_loop()); // Make Valgrind Happy

	exit(0);
}

void setup_signal_handler(uv_loop_t *loop)
{
	signal(SIGPIPE, SIG_IGN);
	
	uv_signal_t *hup = (uv_signal_t *)malloc(sizeof(uv_signal_t));
	if (!hup)
		FATAL("malloc() failed!");

	int n = uv_signal_init(loop, hup);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(loop);

	n = uv_signal_start(hup, signal_cb, SIGINT);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(loop);
}
