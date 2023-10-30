#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <chatp2p/server.h>
#include <encrypt/encrypt.h>
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

	if (!addr_book_push_back(addrs, client_addr)) {
		LOG_ERR("Could not add client to address book");
		return;
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);

	if (entry == NULL) {
		LOG_ERR("Could not find client in address book");
		return;
	}

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	RSA *key = NULL;
	rsa_from_bytes(&key, (unsigned char *)msg->body, msg->header.len);

	if (key == NULL) {
		LOG_ERR("Could not convert client public key to RSA");
		return;
	}

	unsigned char buffer[48] = { 0 };
	memcpy(buffer, entry->key.key, sizeof(entry->key.key));
	memcpy(buffer + sizeof(entry->key.key), entry->key.init_vect, sizeof(entry->key.init_vect));

	char ret_buf[4096] = { 0 };
	int size =
		as_encrypt_data(key, (unsigned char *)buffer, sizeof(buffer), (unsigned char *)ret_buf);

	if (size < 0) {
		LOG_ERR("Could not encrypt data");
		return;
	}

	ChatMessage response = { 0 };
	chat_msg_init(&response, CHAT_MESSAGE_TYPE_JOIN_RESPONSE, size, SERVER_KEY, ret_buf);

	chat_msg_send(&response, socket, client_addr);

	LOG_INFO("Sending symmetric key to client %s", addr_str);
}

static void chat_msg_name_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
								  AddrBook *addrs)
{
	if (!addr_book_contains(addrs, client_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);

	if (entry == NULL) {
		LOG_ERR("Could not find client in address book");
		return;
	}

	char name[256] = { 0 };
	int size = s_decrypt_data(&entry->key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)name);
	
	if (size < 0) {
		LOG_ERR("Could not decrypt data");
		return;
	}
	
	LOG_INFO("Client %s set their name to %s", entry->name, name);

	memcpy(entry->name, name, strlen(name));

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, client_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	LOG_INFO("Client %s set their name to %s", addr_str, entry->name);
}

// TODO: Encrypt ???
static void chat_msg_leave_handler(struct sockaddr_in *client_addr, AddrBook *addrs, int socket)
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

// TODO: Read encryption and forward to client
static void chat_msg_connect_handler(const ChatMessage *msg, struct sockaddr_in *client_addr,
									 AddrBook *addrs, int socket)
{
	if (!addr_book_contains(addrs, client_addr)) {
		LOG_ERR("Client not in address book tried to connect to a client");
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);

	char *sender_name = entry->name;

	char buf[512] = { 0 };
	int size = s_decrypt_data(&entry->key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)buf);

	if (size < 0) {
		LOG_ERR("Could not decrypt data");
		return;
	}

	char *client_addr_str = strtok(buf, "|");
	char *sender_pub_key = buf + strlen(client_addr_str) + 1;

	struct sockaddr_in addr_in = { 0 };
	if (addr_from_string(&addr_in, client_addr_str) < 0) {
		LOG_ERR("Could not convert address to sockaddr_in");
		return;
	}

	if (!addr_book_contains(addrs, &addr_in)) {
		LOG_ERR("Client not in address book");
		return;
	}

	AddrEntry *client_entry = addr_book_find(addrs, &addr_in);

	char body[1024] = { 0 };
	ChatMessage response = { 0 };

	memcpy(body, sender_name, strlen(sender_name));
	body[strlen(sender_name)] = '|';
	addr_to_string(body + strlen(sender_name) + 1, client_addr);
	size_t body_len = strlen(sender_name) + 1 + strlen(client_addr_str);
	body[body_len] = '|';
	memcpy(body + body_len + 1, sender_pub_key, size - strlen(client_addr_str) - 1);

	int enc_size = s_encrypt_data(&client_entry->key, (unsigned char *)body, size + 2 + strlen(sender_name), (unsigned char *)body);

	chat_msg_init(&response, CHAT_MESSAGE_TYPE_CONNECT, enc_size, SERVER_KEY, body);

	chat_msg_send(&response, socket, &addr_in);
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

// TODO: Encrypt this message and forward to client
static void chat_msg_info_handler(struct sockaddr_in *client_addr, AddrBook *addrs, int socket)
{
	if (!addr_book_contains(addrs, client_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	AddrEntry *entry = addr_book_find(addrs, client_addr);

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

	char ret_buf[4096] = { 0 };
	int size = s_encrypt_data(&entry->key, (unsigned char *)buf, strlen(buf), (unsigned char *)ret_buf);

	if (size < 0) {
		LOG_ERR("Could not encrypt data");
		return;
	}

	ChatMessage response = { 0 };
	chat_msg_init(&response, CHAT_MESSAGE_TYPE_TEXT, size, SERVER_KEY, ret_buf);
	chat_msg_send(&response, socket, client_addr);

	LOG_INFO("Sending address book to client");
}

static void chat_msg_ping_handler(struct sockaddr_in *client_addr, AddrBook *addrs, int socket)
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
	chat_msg_init(&pong, CHAT_MESSAGE_TYPE_PONG, 0, SERVER_KEY, NULL);

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
		LOG_ERR(
			"Received JOIN_RESPONSE message from client, server doesn't send JOIN messages to clients");
		break;
	case CHAT_MESSAGE_TYPE_NAME:
		chat_msg_name_handler(msg, client_addr, addrs);
		break;
	case CHAT_MESSAGE_TYPE_LEAVE:
		chat_msg_leave_handler(client_addr, addrs, socket);
		break;
	case CHAT_MESSAGE_TYPE_CONNECT:
		chat_msg_connect_handler(msg, client_addr, addrs, socket);
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
		env_vars_free(env_vars);
		return -1;
	}

	int optname = SO_REUSEADDR;

	if (setsockopt(server->socket, SOL_SOCKET, optname, &(int){ 1 }, sizeof(int)) < 0) {
		LOG_ERR("Could not set socket options");
		env_vars_free(env_vars);
		return -1;
	}

	int port = atoi(env_get_val(env_vars, "SERVER_PORT"));

	struct sockaddr_in address = { 0 };
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(server->socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
		LOG_ERR("Could not bind socket");
		env_vars_free(env_vars);
		return -1;
	}

	int threads = atoi(env_get_val(env_vars, "SERVER_THREADS"));
	int queue_size = atoi(env_get_val(env_vars, "SERVER_QUEUE_SIZE"));

	server->threadpool = malloc(sizeof(Threadpool));
	threadpool_init(server->threadpool, threads, queue_size);

	server->addr_book = malloc(sizeof(AddrBook));
	addr_book_init(server->addr_book);

	char *private_key_path = env_get_val(env_vars, "PRIVATE_KEY_PATH");
	char *public_key_path = env_get_val(env_vars, "PUBLIC_KEY_PATH");

	if (!key_pair_init(&server->key_pair, public_key_path, private_key_path)) {
		LOG_ERR("Could not initialize key pair");
		env_vars_free(env_vars);
		return -1;
	}

	env_vars_free(env_vars);

	return 0;
}

void server_free(ChatServer *server)
{
	threadpool_free(server->threadpool);
	addr_book_free(server->addr_book);
	key_pair_free(&server->key_pair);
	free(server->addr_book);
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
			data->key_pair = &server->key_pair;
			submit_worker_task(server->threadpool, handle_msg, (void *)data);
		}
	}

	LOG_INFO("Shutting down chatp2p server...");

	threadpool_stop(server->threadpool);

	return 0;
}
