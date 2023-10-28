#ifndef CLIENT_H
#define CLIENT_H

#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <lib/threadpool.h>

#define CLIENT_BUF_LEN 65536

#define CLIENT_PING_INTERVAL 60 // Iterations

#define CLIENT_HELP_MSG \
	"Commands:\n\
	help - Display's the help message\n\
	info - Request all connected users in server address book\n\
	list - List all connected users in local address book\n\
	ping - Ping all connected users\n\
	ping <ip:port> - Ping a specific user/server\n\
	msg <ip:port> <message> - Send a message to a user\n\
	join <ip:port> <username> - Join a server\n\
	connect <ip:port> - Connect to a user\n\
	disconnect <ip:port> - Disconnect from a user\n"

#define HELP_COMMAND "help"
#define INFO_COMMAND "info"
#define LIST_COMMAND "list"
#define PING_COMMAND "ping"
#define MSG_COMMAND "msg"
#define JOIN_COMMAND "join"
#define CONNECT_COMMAND "connect"
#define DISCONNECT_COMMAND "disconnect"

typedef struct {
	int socket;
	bool running;
	AddrBook *addr_book;
	Threadpool *threadpool;
	char name[256];
	struct sockaddr_in server_addr;
} ChatClient;

typedef struct {
	size_t len;
	int socket;
	bool *running;
	AddrBook *addr_book;
	char buffer[CLIENT_BUF_LEN];
	struct sockaddr_in ext_addr;
	struct sockaddr_in server_addr;
	char name[256];
} ClientThreadData;

typedef struct {
	int socket;
	ChatMessage *msg;
} PingData;

int client_init(ChatClient *client, char *env_file, char *username, char *address);

int client_run(ChatClient *client);

void client_free(ChatClient *client);

#endif // CLIENT_H