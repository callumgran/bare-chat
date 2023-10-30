/*
 *  Copyright (C) 2023 Callum Gran
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <client/client.h>
#include <encrypt/encrypt.h>
#include <fcntl.h>
#include <lib/env_parser.h>
#include <lib/logger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

static void set_nonblocking(int socket)
{
	int flags = fcntl(socket, F_GETFL, 0);

	flags |= O_NONBLOCK;

	fcntl(socket, F_SETFL, flags);
}

static void sleep_seconds(uint32_t sleep_time)
{
	struct timeval tv;
	tv.tv_sec = sleep_time;
	tv.tv_usec = 0;
	select(1, NULL, NULL, NULL, &tv);
}

static void print_help()
{
	printf("---------------------------------------------\n");
	printf("%s", CLIENT_HELP_MSG);
	printf("---------------------------------------------\n");
}

static void send_ping_to_addr(void *arg, void *data)
{
	AddrEntry *addr = arg;
	PingData *pd = data;
	char buf[20];
	addr_to_string(buf, &addr->addr);
	chat_msg_send(pd->msg, pd->socket, &addr->addr);
}

static void ping_loop(void *arg)
{
	ChatClient *data = (ChatClient *)arg;
	ChatMessage ping;
	chat_msg_init(&ping, CHAT_MESSAGE_TYPE_PING, 0, SERVER_KEY, NULL);

	uint32_t i = 0;

	while (data->running) {
		if (i++ < CLIENT_PING_INTERVAL && data->running) {
			sleep_seconds(1);
			continue;
		}

		i = 0;
		if (data->connected) {
			chat_msg_send(&ping, data->socket, &data->server_addr);
		}
		if (!addr_book_empty(data->addr_book)) {
			PingData pd = { 0 };
			pd.socket = data->socket;
			pd.msg = &ping;
			addr_book_foreach(data->addr_book, send_ping_to_addr, &pd);
		}
	}
}

static bool string_eq(const char *fst, const char *snd)
{
	int fst_len = strlen(fst);
	int snd_len = strlen(snd);
	return strncmp(fst, snd, fst_len < snd_len ? fst_len : snd_len) == 0;
}

static void handle_leave_command(ChatClient *data)
{
	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_LEAVE, 0, SERVER_KEY, NULL);
	chat_msg_send(&msg, data->socket, &data->server_addr);
	data->connected = false;
	LOG_INFO("Disconnected from server");
}

static void handle_info_command(ChatClient *data)
{
	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_INFO, 0, SERVER_KEY, NULL);
	chat_msg_send(&msg, data->socket, &data->server_addr);
}

static void check_client_connected(void *arg)
{
	bool *connected = arg;
	if (!*connected) {
		LOG_ERR("Connection failed, check server address and try again.");
	}
}

// TODO: Find correct buffer size
static void handle_join_command(ChatClient *data)
{
	char *addr = strtok(NULL, "\n");
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for join command");
		print_help();
		return;
	}

	if (addr_from_string(&data->server_addr, addr) < 0) {
		LOG_ERR("Invalid address for join command");
		print_help();
		return;
	}

	char public_key[512] = { 0 };

	ChatMessage msg = { 0 };
	if (data->key_pair.public_key == NULL) {
		LOG_ERR("Public key not initialized");
		return;
	}

	size_t len = rsa_to_bytes(data->key_pair.public_key, (unsigned char *)public_key);

	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_JOIN, len, SERVER_KEY, public_key);

	LOG_INFO("Sending join message to server...\n");
	LOG_INFO("Server addr: %s\n", inet_ntoa(data->server_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &data->server_addr);
	submit_worker_task_timeout(data->threadpool, check_client_connected, &data->connected,
							   CLIENT_JOIN_TIMEOUT);
}

// TODO fix all this naming lmao and buffer size
static void handle_connect_command(ChatClient *data)
{
	char *addr = strtok(NULL, "\n");
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for connect command");
		print_help();
		return;
	}

	struct sockaddr_in ext_addr = { 0 };
	if (addr_from_string(&ext_addr, addr) < 0) {
		LOG_ERR("Invalid address for connect command");
		print_help();
		return;
	}

	char body[INET_ADDRSTRLEN + 6 + 512];
	addr_to_string(body, &ext_addr);
	size_t addr_size = strlen(body);
	strcat(body, "|");
	size_t len = rsa_to_bytes(data->key_pair.public_key, (unsigned char *)(body + strlen(body)));

	char buffer[4096] = { 0 };
	int size = s_encrypt_data(&data->server_key, (unsigned char *)body, addr_size + len, (unsigned char *)buffer);

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_CONNECT, size, SERVER_KEY, buffer);

	LOG_INFO("Sending connect message to other user...\n");
	LOG_INFO("User addr: %s\n", inet_ntoa(ext_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &data->server_addr);

	// Send connect message to other user at the same time to utilize UDP hole punching
	ChatMessage ext_msg = { 0 };
	chat_msg_init(&ext_msg, CHAT_MESSAGE_TYPE_PING, 0, SERVER_KEY, NULL);
	chat_msg_send(&ext_msg, data->socket, &ext_addr);
}

static void handle_disconnect_command(ChatClient *data)
{
	char *addr = strtok(NULL, " ");
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for disconnect command");
		print_help();
		return;
	}

	struct sockaddr_in ext_addr = { 0 };
	if (addr_from_string(&ext_addr, addr) < 0) {
		LOG_ERR("Invalid address for disconnect command");
		print_help();
		return;
	}

	if (!addr_book_contains(data->addr_book, &ext_addr)) {
		LOG_ERR("Unknown client");
		return;
	}

	addr_book_remove(data->addr_book, &ext_addr);

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_DISCONNECT, 0, SERVER_KEY, NULL);
	LOG_INFO("Sending disconnect message to other user...\n");
	chat_msg_send(&msg, data->socket, &ext_addr);
	LOG_INFO("The other user should now be unable to send you messages");
}

static void handle_list_command(ChatClient *data)
{
	if (addr_book_empty(data->addr_book)) {
		LOG_INFO("Address book is empty");
		return;
	}

	char buffer[4096] = { 0 };

	addr_book_to_string(buffer, data->addr_book, NULL);
	LOG_INFO("%s", buffer);
}

static void handle_setname_command(ChatClient *data)
{
	char *name = strtok(NULL, "\n");
	if (name == NULL) {
		LOG_ERR("Invalid arguments for setname command");
		print_help();
		return;
	}

	memcpy(data->name, name, 256);
	LOG_INFO("Set name to %s", data->name);
}

static void handle_msg_command(ChatClient *data)
{
	char *addr = strtok(NULL, " ");
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for msg command");
		print_help();
		return;
	}

	char *msg = strtok(NULL, "\n");
	if (msg == NULL) {
		LOG_ERR("Invalid arguments for msg command");
		print_help();
		return;
	}

	AddrEntry *entry = NULL;
	struct sockaddr_in ext_addr = { 0 };
	if (addr_from_string(&ext_addr, addr) < 0) {
		entry = addr_book_find_by_name(data->addr_book, addr);
		if (entry == NULL) {
			LOG_ERR("Invalid usage of msg command or unknown client");
			print_help();
			return;
		}
		memcpy(&ext_addr, &entry->addr, sizeof(struct sockaddr_in));
	} else {
		entry = addr_book_find(data->addr_book, &ext_addr);
	}

	if (entry == NULL) {
		LOG_ERR("Unknown client, cannot send message.");
		return;
	}

	chat_msg_send_text_enc(msg, data->socket, &ext_addr, &entry->key);
}

static void handle_ping_command(ChatClient *data)
{
	char *addr = strtok(NULL, "\n");
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for ping command");
		print_help();
		return;
	}

	struct sockaddr_in ext_addr = { 0 };
	if (addr_from_string(&ext_addr, addr) < 0) {
		LOG_ERR("Invalid address for ping command");
		print_help();
		return;
	}

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_PING, 0, SERVER_KEY, NULL);

	LOG_INFO("Sending ping message to other address %s...\n", addr);
	chat_msg_send(&msg, data->socket, &ext_addr);
}

// Function name is hella retarded
static void disconnect_connection(void *data, void *arg)
{
	AddrEntry *entry = data;
	ChatClient *client = arg;

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_DISCONNECT, 0, SERVER_KEY, NULL);

	chat_msg_send(&msg, client->socket, &entry->addr);
	addr_book_remove(client->addr_book, &entry->addr);
}

static void handle_quit_command(ChatClient *data)
{
	if (!addr_book_empty(data->addr_book))
		addr_book_foreach(data->addr_book, disconnect_connection, data);
	if (data->connected)
		handle_leave_command(data);

	data->running = false;
}

static void user_command_loop(void *arg)
{
	ChatClient *data = (ChatClient *)arg;
	printf("Welcome to chatp2p client!\n");
	print_help();
	char buf[65536] = { 0 };
	while (data->running) {
		if (fgets(buf, sizeof(buf), stdin) != NULL) {
			char *command = strtok(buf, " ");
			if (command == NULL) {
				print_help();
				continue;
			}

			if (string_eq(command, HELP_COMMAND)) {
				print_help();
			} else if (string_eq(command, QUIT_COMMAND)) {
				handle_quit_command(data);
			} else if (string_eq(command, INFO_COMMAND)) {
				handle_info_command(data);
			} else if (string_eq(command, JOIN_COMMAND)) {
				handle_join_command(data);
			} else if (string_eq(command, LEAVE_COMMAND)) {
				handle_leave_command(data);
			} else if (string_eq(command, CONNECT_COMMAND)) {
				handle_connect_command(data);
			} else if (string_eq(command, DISCONNECT_COMMAND)) {
				handle_disconnect_command(data);
			} else if (string_eq(command, LIST_COMMAND)) {
				handle_list_command(data);
			} else if (string_eq(command, SETNAME_COMMAND)) {
				handle_setname_command(data);
			} else if (string_eq(command, MSG_COMMAND)) {
				handle_msg_command(data);
			} else if (string_eq(command, PING_COMMAND)) {
				handle_ping_command(data);
			} else {
				LOG_ERR("Unknown command: '%s'", command);
				print_help();
			}
		}
	}
}

// TODO: Find correct buffer size and fix naming
static void chat_msg_text_handler(const ChatMessage *msg, ClientThreadData *data)
{
	AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

	char *name = NULL;

	bool is_server = addr_eq(&data->ext_addr, &data->server_addr);

	SymmetricKey key = { 0 };

	if (entry == NULL && !is_server) {
		LOG_ERR("Unknown client tried to send you a message!");
		LOG_INFO("Check your OPSEC, you might be getting attacked!");
		return;
	} else if (is_server) {
		name = "Server";
		memcpy(key.key, data->server_key->key, 32);
		memcpy(key.init_vect, data->server_key->init_vect, 16);
	} else {
		name = entry->name;
		memcpy(key.key, entry->key.key, 32);
		memcpy(key.init_vect, entry->key.init_vect, 16);
	}

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	char text[65536] = { 0 };
	s_decrypt_data(&key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)text);

#ifdef __linux__
	if (!is_server) {
		char notification[1024] = { 0 };
		snprintf(notification, sizeof(notification), "notify-send \"New message!\" \"You have a new message from %s : %s!\"", name, addr_str);
		system(notification);
	}
#endif

	LOG_MSG("-------------------------------------------------------");
	LOG_MSG("Received message from %s : %s", name, addr_str);
	LOG_MSG("Message: %s", text);
	LOG_MSG("-------------------------------------------------------");
}

// TODO: Find correct buffer size and fix naming
static void chat_msg_connect_handler(const ChatMessage *msg, ClientThreadData *data)
{
	char buf[4096] = { 0 };
	int size = s_decrypt_data(data->server_key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)buf);

	char *name = strtok(buf, "|");
	char *addr = strtok(NULL, "|");
	char *public_key = buf + strlen(name) + strlen(addr) + 2;
	struct sockaddr_in ext_addr = { 0 };
	if (addr_from_string(&ext_addr, addr) < 0) {
		LOG_ERR("Invalid address for connect response");
		return;
	}

	if (addr_book_contains(data->addr_book, &ext_addr)) {
		LOG_INFO("Client already in address book");
		return;
	}

	if (!addr_book_push_back(data->addr_book, &ext_addr)) {
		LOG_ERR("Failed to add client to address book");
		return;
	}

	AddrEntry *entry = addr_book_find(data->addr_book, &ext_addr);
	memcpy(entry->name, name, 256);

	RSA *public_key_rsa = NULL;

	char buffer[4096] = { 0 };
	rsa_from_bytes(&public_key_rsa, (unsigned char *)public_key, size - strlen(name) - strlen(addr) - 2);

	char keyname[256 + sizeof(SymmetricKey)] = { 0 };
	memcpy(keyname, &entry->key, sizeof(SymmetricKey));
	memcpy(keyname + sizeof(SymmetricKey), data->name, strlen(data->name));

	int len = as_encrypt_data(public_key_rsa, (unsigned char *)keyname, sizeof(SymmetricKey) + strlen(data->name),
							  (unsigned char *)buffer);

	ChatMessage connect = { 0 };
	chat_msg_init(&connect, CHAT_MESSAGE_TYPE_CONNECT_RESPONSE, len, SERVER_KEY,
				  buffer);

	chat_msg_send(&connect, data->socket, &ext_addr);
}

// TODO: Find correct buffer size and fix the naming
static void chat_msg_connect_response_handler(const ChatMessage *msg, ClientThreadData *data)
{
	if (addr_book_contains(data->addr_book, &data->ext_addr)) {
		LOG_INFO("Client already in address book");
		return;
	}

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	if (!addr_book_push_back(data->addr_book, &data->ext_addr)) {
		LOG_ERR("Failed to add client to address book");
		return;
	}

	AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

	char buf[4096] = { 0 };
	int size = as_decrypt_data(data->key_pair->private_key, (unsigned char *)msg->body, msg->header.len, buf);

	memcpy(entry->key.key, buf, sizeof(entry->key.key));
	memcpy(entry->key.init_vect, buf + sizeof(entry->key.key), sizeof(entry->key.init_vect));
	memcpy(entry->name, buf + sizeof(SymmetricKey), size - sizeof(SymmetricKey));

	chat_msg_send_text_enc("Howdy new partner!", data->socket, &data->ext_addr, &entry->key);

	LOG_INFO(
		"Client %s with nickname %s received your connection request, you can now communicate by name :)",
		addr_str, entry->name);
}

static void chat_msg_disconnect_handler(ClientThreadData *data)
{
	if (!addr_book_contains(data->addr_book, &data->ext_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);
	LOG_INFO("Client %s with nickname %s closed their connection to you", addr_str, entry->name);
	addr_book_remove(data->addr_book, &data->ext_addr);
}

// TODO: Find correct buffer size and fix naming
static void chat_msg_join_response_handler(const ChatMessage *msg, ClientThreadData *data)
{
	char buf[4096] = { 0 };

	as_decrypt_data(data->key_pair->private_key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)buf);

	memcpy(data->server_key, buf, sizeof(SymmetricKey));

	char response[272] = { 0 };
	int size = s_encrypt_data(data->server_key, (unsigned char *)data->name, strlen(data->name), (unsigned char *)response);

	ChatMessage ret = { 0 };
	chat_msg_init(&ret, CHAT_MESSAGE_TYPE_NAME, size, SERVER_KEY, response);
	chat_msg_send(&ret, data->socket, &data->server_addr);

	*(data->connected) = true;
	LOG_INFO("Successfully connected to server");
}

static void chat_msg_ping_handler(ClientThreadData *data)
{
	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

	if (entry == NULL) {
		if (addr_eq(&data->ext_addr, &data->server_addr)) {
			LOG_ERR("Server tried to ping you! This is retarded and something is wrong!");
		}
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &entry->last_seen);

	ChatMessage pong = { 0 };
	chat_msg_init(&pong, CHAT_MESSAGE_TYPE_PONG, 0, SERVER_KEY, NULL);

	chat_msg_send(&pong, data->socket, &data->ext_addr);
}

// TODO: Find out if this is even needed
static void chat_msg_unknown_handler(const ChatMessage *msg, ClientThreadData *data)
{
	(void)msg;
	(void)data;
	LOG_ERR("Unknown message type");
}

// TODO: Find out if this is even needed
static void chat_msg_error_handler(const ChatMessage *msg, ClientThreadData *data)
{
	(void)msg;
	(void)data;
	// TODO: This will be how clients receive errors from the server
}

static void chat_msg_handler(const ChatMessage *msg, ClientThreadData *data)
{
	if (msg->header.server_key != SERVER_KEY) {
		LOG_ERR("Invalid key in message received");
		return;
	}

	if (msg->header.type >= CHAT_MESSAGE_TYPE_COUNT) {
		LOG_ERR("Invalid message type");
		return;
	}

	switch (msg->header.type) {
	case CHAT_MESSAGE_TYPE_TEXT:
		chat_msg_text_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_CONNECT:
		chat_msg_connect_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_CONNECT_RESPONSE:
		chat_msg_connect_response_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_DISCONNECT:
		chat_msg_disconnect_handler(data);
		break;
	case CHAT_MESSAGE_TYPE_JOIN_RESPONSE:
		chat_msg_join_response_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_ERROR:
		chat_msg_error_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_PING:
		chat_msg_ping_handler(data);
		break;
	case CHAT_MESSAGE_TYPE_PONG:
		break;
	case CHAT_MESSAGE_TYPE_UNKNOWN:
		chat_msg_unknown_handler(msg, data);
		break;
	default:
		chat_msg_unknown_handler(msg, data);
		break;
	}
}

static void handle_receive_msg(void *arg)
{
	ClientThreadData *data = (ClientThreadData *)arg;
	ChatMessage msg = { 0 };
	chat_msg_from_string(&msg, data->buffer, data->len);

	if (msg.header.server_key != SERVER_KEY) {
		LOG_ERR("Invalid key in message received");
		return;
	}

	chat_msg_handler(&msg, data);

	free(data);
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

int client_init(ChatClient *client, char *env_file)
{
	EnvVars *env_vars = env_parse(env_file);

	client->socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (client->socket < 0) {
		LOG_ERR("Could not create socket");
		env_vars_free(env_vars);
		return -1;
	}

	client->running = false;
	client->connected = false;
	memcpy(client->name, env_get_val(env_vars, "CLIENT_DEFAULT_NAME"), 256);

	int threads = atoi(env_get_val(env_vars, "CLIENT_THREADS"));
	int queue_size = atoi(env_get_val(env_vars, "CLIENT_QUEUE_SIZE"));

	client->threadpool = malloc(sizeof(Threadpool));
	threadpool_init(client->threadpool, threads, queue_size);

	client->addr_book = malloc(sizeof(AddrBook));
	addr_book_init(client->addr_book);

	char *private_key_path = env_get_val(env_vars, "PRIVATE_KEY_PATH");
	char *public_key_path = env_get_val(env_vars, "PUBLIC_KEY_PATH");

	if (!key_pair_init(&client->key_pair, public_key_path, private_key_path)) {
		LOG_ERR("Failed to initialize key pair");
		env_vars_free(env_vars);
		return -1;
	}

	env_vars_free(env_vars);

	return 0;
}

void client_free(ChatClient *client)
{
	threadpool_free(client->threadpool);
	addr_book_free(client->addr_book);
	key_pair_free(&client->key_pair);
	free(client->threadpool);
	free(client->addr_book);
	LOG_INFO("Client freed and closed.");
}

int client_run(ChatClient *client)
{
	struct sockaddr_in ext_addr = { 0 };
	socklen_t len = sizeof(struct sockaddr_in);

	threadpool_start(client->threadpool);

	client->running = true;
	set_nonblocking(client->socket);

	submit_worker_task(client->threadpool, ping_loop, (void *)client);
	submit_worker_task(client->threadpool, user_command_loop, (void *)client);

	int nfds = client->socket + 1;
	fd_set readfds;
	char buffer[65536] = { 0 };

	set_nonblocking(nfds);

	while (client->running) {
		if (!check_fd(nfds, client->socket, &readfds))
			continue;

		memset(buffer, 0, sizeof(buffer));
		memset(&ext_addr, 0, sizeof(struct sockaddr_in));

		ssize_t recv_len =
			recvfrom(client->socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&ext_addr, &len);

		if (recv_len > 0) {
			ClientThreadData *data = malloc(sizeof(ClientThreadData));
			data->running = &client->running;
			data->connected = &client->connected;
			memcpy(data->buffer, buffer, sizeof(buffer));
			data->len = recv_len;
			memcpy(&data->ext_addr, &ext_addr, sizeof(struct sockaddr_in));
			data->addr_book = client->addr_book;
			data->socket = client->socket;
			data->server_addr = client->server_addr;
			data->name = client->name;
			data->server_key = &client->server_key;
			data->key_pair = &client->key_pair;
			submit_worker_task(client->threadpool, handle_receive_msg, (void *)data);
		} else {
			LOG_ERR("recvfrom() failed for some reason");
		}
	}

	LOG_INFO("Shutting down chatp2p client...");

	threadpool_stop(client->threadpool);

	return 0;
}
