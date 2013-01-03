#ifndef CONFIG_H_
#define CONFIG_H_
#include "utils.h"

// This is the IP address server will be used to accept new connection
#define SERVER_LISTEN "0.0.0.0"

// This is the port server will be used to accept new connection
#define SERVER_PORT 8888

// This is the password used for encrypt/decrypt, should be the same as your client
#define PASSWORD "foobar!"

// This is the path shadowsocks will write it's pid to
#define PID_FILE "/tmp/shadowsocks.pid"

// This is the time format for log, see strftime(3) for more information
#define TIME_FORMAT "%F %T"

// This is the buffer size (in byte) used during handshake, generally you DO NOT need to change this unless you have a good reason to do so
// This buffer will be freed right after handshake is complete
#define HANDSHAKE_BUFFER_SIZE 512

// This is the buffer size (in byte) that will be used during receive data, if you are not sure, just leave it
#define BUFFER_LIMIT 65536

// This is the number of max allowed pending write to client request, if you are running out of memory (which is very unlikely), you may want to decrease this a little
// The max possible memory usage of this program is BUFFER_LIMIT * MAX_PENDING_PER_CONN * Concurrent connection number, but this is kind of situation almost impossible to happen
// In most case, increase this value will better your performance
#define MAX_PENDING_PER_CONN 100

// This is the interval (in seconds) the operation system will be used to check whether the connection is still alive
// If you think you do not need it, you can comment next line to turn it off
#define KEEPALIVE_TIMEOUT 120

#endif /* !CONFIG_H_ */
