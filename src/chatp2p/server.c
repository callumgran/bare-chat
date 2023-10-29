#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>

#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <chatp2p/server.h>
#include <lib/env_parser.h>
#include <lib/logger.h>
#include <lib/threadpool.h>

static void check_quit(void *arg)
{
	ChatServer *server = (ChatServer *)arg;

	while (getc(stdin) != 'q')
		;

	shutdown(server->socket, SHUT_RDWR);
	close(server->socket);
	LOG_INFO("Quitting...\n");

	server->running = false;
}

static void set_nonblocking(int socket)
{
	int flags = fcntl(socket, F_GETFL, 0);

	flags |= O_NONBLOCK;

	fcntl(socket, F_SETFL, flags);
}

static void chat_msg_join_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
								  AddrBook *addrs, int socket)
{
	if (addr_book_contains(addrs, client_addr)) {
		LOG_INFO("Client already in address book");
		return;
	}

	addr_book_push_back(addrs, client_addr, msg->body);

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	ChatMessage response = { 0 };
	response.header.server_key = SERVER_KEY;
	response.header.type = CHAT_MESSAGE_TYPE_JOIN_RESPONSE;
	response.header.len = 0;
	response.body = NULL;

	chat_msg_send(&response, socket, client_addr);

	LOG_INFO("Client %s with nickname %s joined the server", addr_str, msg->body);
}

static void chat_msg_leave_handler(struct sockaddr_in *client_addr,
								   AddrBook *addrs, int socket)
{
	if (!addr_book_contains(addrs, client_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);
	
	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	chat_msg_send_text("Goodbye!", socket, client_addr);

	LOG_INFO("Client %s with nickname %s left the server", addr_str, entry->name);
	addr_book_remove(addrs, client_addr);
}

static void chat_msg_error_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
								   AddrBook *addrs, int socket)
{
	// TODO: This will be how clients handle error messages
	(void)addrs;
	(void)socket;
	(void)client_addr;
	(void)msg;
}

static void chat_msg_info_handler(struct sockaddr_in *client_addr,
								  AddrBook *addrs, int socket)
{
	if (!addr_book_contains(addrs, client_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	char buf[4096] = { 0 };

	if (addrs->size == 1) {
		strncpy(buf, "Address book is empty.", sizeof(buf));
	} else {
		bool ret = addr_book_to_string(buf, addrs, client_addr);

		if (!ret) {
			LOG_ERR("Could not convert address book to string");
			return;
		}
	}

	LOG_INFO("Sending address book to client");
	chat_msg_send_text(buf, socket, client_addr);
}

static void chat_msg_ping_handler(struct sockaddr_in *client_addr,
								  AddrBook *addrs, int socket)
{
	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);

	if (entry == NULL) {
		LOG_ERR("Unknown client %s tried to ping you!", addr_str);
		LOG_INFO("Check your OPSEC, you might be getting attacked!");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &entry->last_seen);

	LOG_INFO("Received PING message from %s : %s", entry->name, addr_str);

	ChatMessage pong = { 0 };
	pong.header.server_key = SERVER_KEY;
	pong.header.type = CHAT_MESSAGE_TYPE_PONG;
	pong.header.len = 0;
	pong.body = NULL;

	chat_msg_send(&pong, socket, client_addr);

	LOG_INFO("Sent PONG message to client %s", addr_str);
}


static void chat_msg_unknown_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
									 AddrBook *addrs, int socket)
{
	// TODO: Find out if this is necessary
	(void)addrs;
	(void)socket;
	(void)client_addr;
	(void)msg;
}

static void chat_msg_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
							 AddrBook *addrs, int socket)
{
	if (msg->header.server_key != SERVER_KEY) {
		LOG_ERR("Received message with invalid server key");
		return;
	}

	if (msg->header.type < CHAT_MESSAGE_TYPE_COUNT)
		LOG_INFO("Handling message of type: %s", CHAT_MESSAGE_TYPE_STRINGS[msg->header.type]);

	switch (msg->header.type) {
	case CHAT_MESSAGE_TYPE_TEXT:
		LOG_ERR("Received TEXT message from client, server doesn't receive TEXT messages");
		break;
	case CHAT_MESSAGE_TYPE_JOIN:
		chat_msg_join_handler(msg, client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_JOIN_RESPONSE:
		LOG_ERR("Received JOIN_RESPONSE message from client, server doesn't send JOIN messages to clients");
		break;
	case CHAT_MESSAGE_TYPE_LEAVE:
		chat_msg_leave_handler(client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_CONNECT:
		LOG_ERR("Received CONNECT message from client, server doesn't connect to clients");
		break;
	case CHAT_MESSAGE_TYPE_CONNECT_RESPONSE:
		LOG_ERR("Received CONNECT_RESPONSE message from client, server doesn't connect to clients");
		break;
	case CHAT_MESSAGE_TYPE_DISCONNECT:
		LOG_ERR("Received DISCONNECT message from client, server doesn't disconnect from clients");
		break;
	case CHAT_MESSAGE_TYPE_ERROR:
		chat_msg_error_handler(msg, client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_INFO:
		chat_msg_info_handler(client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_PING:
		chat_msg_ping_handler(client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_PONG:
		LOG_ERR("Received PONG message from client, server doesn't send PING messages");
		break;
	case CHAT_MESSAGE_TYPE_UNKNOWN:
	default:
		chat_msg_unknown_handler(msg, client_addr, addrs, socket);
		break;
	}
}

static void handle_msg(void *arg)
{
	ServerThreadData *data = (ServerThreadData *)arg;

	ChatMessage msg = { 0 };
	chat_msg_from_string(&msg, data->buffer, data->len);

	chat_msg_handler(&msg, &data->client_addr, data->addr_book, data->socket);

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	LOG_INFO("Completed request from: %s", addr_str);

	free(arg);
}

int server_init(ChatServer *server, char *env_file)
{
	EnvVars *env_vars = env_parse(env_file);

	server->socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (server->socket < 0) {
		LOG_ERR("Could not create socket");
		return -1;
	}

	int optname = SO_REUSEADDR;

	if (setsockopt(server->socket, SOL_SOCKET, optname, &(int){ 1 }, sizeof(int)) < 0) {
		LOG_ERR("Could not set socket options");
		return -1;
	}

	int port = atoi(env_get_val(env_vars, "SERVER_PORT"));

	struct sockaddr_in address = { 0 };
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(server->socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
		LOG_ERR("Could not bind socket");
		return -1;
	}

	int threads = atoi(env_get_val(env_vars, "SERVER_THREADS"));
	int queue_size = atoi(env_get_val(env_vars, "SERVER_QUEUE_SIZE"));

	server->threadpool = malloc(sizeof(Threadpool));
	threadpool_init(server->threadpool, threads, queue_size);

	server->addr_book = malloc(sizeof(AddrBook));
	addr_book_init(server->addr_book);

	env_vars_free(env_vars);

	return 0;
}

void server_free(ChatServer *server)
{
	threadpool_free(server->threadpool);
	addr_book_free(server->addr_book);
	free(server->threadpool);
	LOG_INFO("Server freed and closed.");
}

static bool check_fd(int nfds, int client_fd, fd_set *readfds)
{
	FD_ZERO(readfds);
	FD_SET(client_fd, readfds);
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	return select(nfds, readfds, NULL, NULL, &timeout) > 0;
}

int server_run(ChatServer *server)
{
	struct sockaddr_in client_address = { 0 };
	socklen_t len = sizeof(struct sockaddr_in);

	threadpool_start(server->threadpool);

	server->running = true;

	LOG_INFO("Server started, press 'q' to quit\n");

	submit_worker_task(server->threadpool, check_quit, (void *)server);

	set_nonblocking(server->socket);

	int nfds = server->socket + 1;
	fd_set readfds;

	set_nonblocking(nfds);
	char buffer[65536] = { 0 };

	while (server->running) {

		if (!check_fd(nfds, server->socket, &readfds))
			continue;

		memset(buffer, 0, sizeof(buffer));
		memset(&client_address, 0, sizeof(struct sockaddr_in));
		
		ssize_t recv_len = recvfrom(server->socket, buffer, sizeof(buffer), 0,
									(struct sockaddr *)&client_address, &len);

		if (recv_len > 0) {
			ServerThreadData *data = malloc(sizeof(ServerThreadData));
			data->running = &server->running;
			memcpy(data->buffer, buffer, sizeof(buffer));
			data->len = recv_len;
			memcpy(&data->client_addr, &client_address, sizeof(struct sockaddr_in));
			data->addr_book = server->addr_book;
			data->socket = server->socket;
			submit_worker_task(server->threadpool, handle_msg, (void *)data);
		}
	}

	LOG_INFO("Shutting down chatp2p server...");

	threadpool_stop(server->threadpool);
	server_free(server);
	return 0;
}
