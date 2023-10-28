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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <client/client.h>
#include <lib/env_parser.h>
#include <lib/logger.h>
#include <fcntl.h>
#include <unistd.h>


static void check_quit(void *arg)
{
	ChatClient *client = (ChatClient *)arg;

	while (getc(stdin) != 'q')
		;

	shutdown(client->socket, SHUT_RDWR);
	close(client->socket);
	LOG_INFO("Quitting...\n");

	client->running = false;
}

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
	LOG_INFO("Pinging to %s", buf);
	chat_msg_send(pd->msg, pd->socket, &addr->addr);
}

static void ping_loop(void *arg)
{
	ClientThreadData *data = (ClientThreadData *)arg;
	ChatMessage ping;
	ping.header.server_key = SERVER_KEY;
	ping.header.type = CHAT_MESSAGE_TYPE_PING;
	ping.header.len = 0;
	ping.body = NULL;
	uint32_t i = 61;

	while (data->running) {
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

static bool string_eq(const char *fst, const void *snd)
{
	return strcmp(fst, snd) == 0;
}

static void user_command_loop(void *arg)
{
	ClientThreadData *data = (ClientThreadData *)arg;
	print_help();
	char buf[1024];
	size_t len = 0;
	ssize_t read_len = 0;
	while (data->running) {
		if (fprintf(stdout, ">") && (read_len = getline(&buf, &len, stdin)) != -1) {
			printf("Input: %s", buf);
			char *command = strtok(buf, " ");
			if (command == NULL) {
				print_help();
				continue;
			}

			if (string_eq(command, HELP_COMMAND)) {
				print_help();
			} else if (string_eq(command, INFO_COMMAND)) {
				ChatMessage msg = { 0 };
				msg.header.server_key = SERVER_KEY;
				msg.header.type = CHAT_MESSAGE_TYPE_INFO;
				msg.header.len = 0;
				msg.body = NULL;
				chat_msg_send(&msg, data->socket, &data->server_addr);
			} else {
				LOG_ERR("Unknown command: %s", command);
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

	LOG_INFO("-------------------------------------------------------");
	LOG_INFO("Received message from %s : %s", name, addr_str);
	LOG_INFO("Message: %s", msg->body);
	LOG_INFO("-------------------------------------------------------");
}

static void chat_msg_leave_handler(const ChatMessage *msg, ClientThreadData *data)
{
	if (!addr_book_contains(data->addr_book, &data->ext_addr)) {
		LOG_INFO("Client not in address book");
		return;
	}

	addr_book_remove(data->addr_book, &data->ext_addr);

	char addr_str[INET_ADDRSTRLEN];
	if (addr_to_string(addr_str, &data->ext_addr) < 0) {
		LOG_ERR("Could not convert address to string");
		return;
	}

	chat_msg_send_text("Goodbye!", data->socket, &data->ext_addr);

	LOG_INFO("Client %s with nickname %s closed their connection to you", addr_str, msg->body);
}

static void chat_msg_connect_handler(const ChatMessage *msg, ClientThreadData *data)
{
	// TODO: This will be how clients connect to each other through udp hole punching
}

static void chat_msg_error_handler(const ChatMessage *msg, ClientThreadData *data)
{
	// TODO: This will be how clients receive errors from the server
}

static void chat_msg_info_handler(const ChatMessage *msg, ClientThreadData *data)
{
	// TODO: This will be how clients receive info from the server (e.g. address book, server ip,
	// etc.)
}

static void chat_msg_ping_handler(const ChatMessage *msg, ClientThreadData *data)
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
	}


	LOG_INFO("Received PING message from %s : %s", entry->name, addr_str);

	ChatMessage pong = { 0 };
	pong.header.server_key = SERVER_KEY;
	pong.header.type = CHAT_MESSAGE_TYPE_PONG;
	pong.header.len = 0;
	pong.body = NULL;

	chat_msg_send(&pong, data->socket, &data->ext_addr);

	LOG_INFO("Sent PONG message to %s : %s", entry->name, addr_str);
}

static void chat_msg_pong_handler(const ChatMessage *msg, ClientThreadData *data)
{
	// TODO: This will be how clients respond to pings from the server
}

static void chat_msg_unknown_handler(const ChatMessage *msg, ClientThreadData *data)
{
	// TODO: This will be how clients handle unknown message types
}

static void chat_msg_handler(const ChatMessage *msg, ClientThreadData *data)
{
	if (msg->header.type < CHAT_MESSAGE_TYPE_COUNT)
		LOG_INFO("Handling message of type: %s", CHAT_MESSAGE_TYPE_STRINGS[msg->header.type]);

	switch (msg->header.type) {
	case CHAT_MESSAGE_TYPE_TEXT:
		chat_msg_text_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_JOIN:
		LOG_ERR("Client tried to join you, but you are not a server lmao!");
		break;
	case CHAT_MESSAGE_TYPE_LEAVE:
		chat_msg_leave_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_CONNECT:
		chat_msg_connect_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_ERROR:
		chat_msg_error_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_INFO:
		chat_msg_info_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_PING:
		chat_msg_ping_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_PONG:
		chat_msg_pong_handler(msg, data);
		break;
	case CHAT_MESSAGE_TYPE_UNKNOWN:
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

int client_init(ChatClient *client, char *env_file, char *username, char *address)
{
	EnvVars *env_vars = env_parse(env_file);

	client->socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (client->socket < 0) {
		LOG_ERR("Could not create socket");
		return -1;
	}

	if (strlen(username) > 256)
		LOG_ERR("Username too long, truncating to 256 characters");

	memcpy(client->name, username, 256);

	if (addr_from_string(&client->server_addr, address) < 0) {
		LOG_ERR("Could not convert address to string");
		return -1;
	}

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

	LOG_INFO("Client started, press 'q' to quit\n");

	submit_worker_task(client->threadpool, check_quit, (void *)client);

	ClientThreadData base_data = { 0 };
	base_data.running = &client->running;
	base_data.socket = client->socket;
	base_data.addr_book = client->addr_book;
	base_data.server_addr = client->server_addr;
	memcpy(base_data.name, client->name, 256);
	submit_worker_task(client->threadpool, ping_loop, (void *)&base_data);
	submit_worker_task(client->threadpool, user_command_loop, (void *)&base_data);

	set_nonblocking(client->socket);

	int nfds = client->socket + 1;
	fd_set readfds;
	char buffer[65536] = { 0 };

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
			memcpy(data->buffer, buffer, sizeof(buffer));
			data->len = recv_len;
			memcpy(&data->ext_addr, &ext_addr, sizeof(struct sockaddr_in));
			data->addr_book = client->addr_book;
			data->socket = client->socket;
			data->server_addr = client->server_addr;
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
