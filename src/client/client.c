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
	char buf[1024];
	addr_to_string(buf, &addr->addr);
	// LOG_INFO("Pinging to %s", buf);
	chat_msg_send(pd->msg, pd->socket, &addr->addr);
}

static void ping_loop(void *arg)
{
	ChatClient *data = (ChatClient *)arg;
	ChatMessage ping;
	ping.header.server_key = SERVER_KEY;
	ping.header.type = CHAT_MESSAGE_TYPE_PING;
	ping.header.len = 0;
	ping.body = NULL;
	uint32_t i = 61;

	while (data->running) {
		if (!data->connected) {
			sleep_seconds(1);
			continue;
		}

		if (i++ < CLIENT_PING_INTERVAL && data->running) {
			sleep_seconds(1);
			continue;
		}
		i = 0;
		chat_msg_send(&ping, data->socket, &data->server_addr);
		if (!addr_book_empty(data->addr_book)) {
			PingData pd = { 0 };
			pd.socket = data->socket;
			pd.msg = &ping;
			addr_book_foreach(data->addr_book, send_ping_to_addr, &pd);
		}
	}

	LOG_INFO("Quitting ping loop...");
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
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_LEAVE;
	msg.header.len = 0;
	msg.body = NULL;
	chat_msg_send(&msg, data->socket, &data->server_addr);
	data->connected = false;
	LOG_INFO("Disconnected from server");
}

static void handle_info_command(ChatClient *data)
{
	ChatMessage msg = { 0 };
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_INFO;
	msg.header.len = 0;
	msg.body = NULL;
	chat_msg_send(&msg, data->socket, &data->server_addr);
}

static void check_client_connected(void *arg)
{
	bool *connected = arg;
	if (!*connected) {
		LOG_ERR("Connection failed, check server address and try again.");
	}
}

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

	ChatMessage msg = { 0 };
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_JOIN;
	msg.header.len = strlen(data->name);
	msg.body = data->name;
	LOG_INFO("Sending join message to server...\n");
	LOG_INFO("Server addr: %s\n", inet_ntoa(data->server_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &data->server_addr);
	data->connected = false;
	submit_worker_task_timeout(data->threadpool, check_client_connected, &data->connected,
							   CLIENT_JOIN_TIMEOUT);
}

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

	ChatMessage msg = { 0 };
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_CONNECT;
	msg.header.len = strlen(data->name);
	msg.body = data->name;
	LOG_INFO("Sending connect message to other user...\n");
	LOG_INFO("User addr: %s\n", inet_ntoa(ext_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &ext_addr);
	LOG_INFO("The other user should now be able to send you messages");
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
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_DISCONNECT;
	msg.header.len = 0;
	msg.body = NULL;
	LOG_INFO("Sending disconnect message to other user...\n");
	LOG_INFO("User addr: %s\n", inet_ntoa(ext_addr.sin_addr));
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

	chat_msg_send_text(msg, data->socket, &ext_addr);
	// LOG_INFO("Message sent to %s", entry->name);
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
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_PING;
	msg.header.len = 0;
	msg.body = NULL;
	LOG_INFO("Sending ping message to other address %s...\n", addr);
	chat_msg_send(&msg, data->socket, &ext_addr);
}

static void disconnect_all_connections(void *data, void *arg)
{
	AddrEntry *entry = data;
	ChatClient *client = arg;

	ChatMessage msg = { 0 };
	msg.header.server_key = SERVER_KEY;
	msg.header.type = CHAT_MESSAGE_TYPE_DISCONNECT;
	msg.header.len = 0;
	msg.body = NULL;

	chat_msg_send(&msg, client->socket, &entry->addr);
	addr_book_remove(client->addr_book, &entry->addr);
}

static void user_command_loop(void *arg)
{
	ChatClient *data = (ChatClient *)arg;
	printf("Welcome to chatp2p client!\n");
	print_help();
	char buf[1024] = { 0 };
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
				if (!addr_book_empty(data->addr_book))
					addr_book_foreach(data->addr_book, disconnect_all_connections, data);
				if (data->connected)
					handle_leave_command(data);

				data->running = false;
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
				LOG_INFO("Set name to %s", data->name);
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

static void chat_msg_text_handler(const ChatMessage *msg, ClientThreadData *data)
{
	AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

	char *name = NULL;

	if (entry == NULL && !addr_eq(&data->ext_addr, &data->server_addr)) {
		LOG_ERR("Unknown client tried to send you a message!");
		LOG_INFO("Check your OPSEC, you might be getting attacked!");
		return;
	} else if (addr_eq(&data->ext_addr, &data->server_addr)) {
		name = "Server";
	} else {
		name = entry->name;
	}

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	LOG_MSG("-------------------------------------------------------");
	LOG_MSG("Received message from %s : %s", name, addr_str);
	LOG_MSG("Message: %s", msg->body);
	LOG_MSG("-------------------------------------------------------");
}

static void chat_msg_connect_handler(const ChatMessage *msg, ClientThreadData *data)
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

	// TODO: Add checks to make sure name of client is not to long etc, names should also be unique

	addr_book_push_back(data->addr_book, &data->ext_addr, msg->body);

	ChatMessage connect = { 0 };
	connect.header.server_key = SERVER_KEY;
	connect.header.type = CHAT_MESSAGE_TYPE_CONNECT_RESPONSE;
	connect.header.len = strlen(data->name);
	connect.body = data->name;

	chat_msg_send(&connect, data->socket, &data->ext_addr);
}

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

	addr_book_push_back(data->addr_book, &data->ext_addr, msg->body);

	chat_msg_send_text("Howdy new partner!", data->socket, &data->ext_addr);

	LOG_INFO(
		"Client %s with nickname %s received your connection request, you can now communicate by name :)",
		addr_str, msg->body);
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

static void chat_msg_join_response_handler(ClientThreadData *data)
{
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
		} else {
			LOG_ERR("Unknown client %s tried to ping you!", addr_str);
		}
		LOG_INFO("Check your OPSEC, you might be getting attacked!");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &entry->last_seen);

	// LOG_INFO("Received PING message from %s : %s", entry->name, addr_str);

	ChatMessage pong = { 0 };
	pong.header.server_key = SERVER_KEY;
	pong.header.type = CHAT_MESSAGE_TYPE_PONG;
	pong.header.len = 0;
	pong.body = NULL;

	chat_msg_send(&pong, data->socket, &data->ext_addr);

	// LOG_INFO("Sent PONG message to %s : %s", entry->name, addr_str);
}

static void chat_msg_unknown_handler(const ChatMessage *msg, ClientThreadData *data)
{
	(void)msg;
	(void)data;
	LOG_ERR("Unknown message type");
}

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
		chat_msg_join_response_handler(data);
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

	env_vars_free(env_vars);

	return 0;
}

void client_free(ChatClient *client)
{
	threadpool_free(client->threadpool);
	addr_book_free(client->addr_book);
	free(client->threadpool);
	free(client->addr_book);
	LOG_INFO("client freed and closed.");
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
			submit_worker_task(client->threadpool, handle_receive_msg, (void *)data);
		} else {
			LOG_ERR("recvfrom() failed for some reason");
		}
	}

	LOG_INFO("Shutting down chatp2p client...");

	threadpool_stop(client->threadpool);
	client_free(client);
	return 0;
}
