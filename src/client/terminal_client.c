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
#include <chatp2p/client.h>
#include <lib/logger.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CLIENT_HELP_MSG \
	"Commands:\n\
	help - Display's the help message\n\
	quit - Disconnect from all users and exit\n\
	info - Request all connected users in server address book\n\
	list - List all connected users in local address book\n\
	ping <ip:port> - Ping a specific user/server\n\
	setname <name> - Set your name\n\
	msg <ip:port> <message> - Send a message to a user\n\
	msg <name> <message> - Send a message to a user\n\
	join <ip:port> - Join a server\n\
	leave - Leave a server\n\
	connect <ip:port> - Connect to a user\n\
	disconnect <ip:port> - Disconnect from a user\n"

typedef enum {
	CLIENT_HELP,
	CLIENT_QUIT,
	CLIENT_INFO,
	CLIENT_LIST,
	CLIENT_PING,
	CLIENT_SETNAME,
	CLIENT_MSG,
	CLIENT_JOIN,
	CLIENT_LEAVE,
	CLIENT_CONNECT,
	CLIENT_DISCONNECT,
	CLIENT_COMMAND_COUNT
} EClientCommand;

char *CLIENT_COMMAND_STRINGS[CLIENT_COMMAND_COUNT] = {
	"help", "quit", "info",	 "list",	"ping",		  "setname",
	"msg",	"join", "leave", "connect", "disconnect",
};

static void check_client_connected(void *arg)
{
	bool *connected = arg;
	if (!*connected) {
		LOG_ERR("Connection failed, check server address and try again.");
	}
}

static void print_help()
{
	printf("---------------------------------------------\n");
	printf("%s", CLIENT_HELP_MSG);
	printf("---------------------------------------------\n");
}

static void handle_leave_command(ChatClient *data)
{
	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_LEAVE, 0, data->server_header_key, NULL);
	chat_msg_send(&msg, data->socket, &data->server_addr);
	data->connected = false;
	LOG_INFO("Disconnected from server");
}

static void handle_info_command(ChatClient *data)
{
	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_INFO, 0, data->server_header_key, NULL);
	chat_msg_send(&msg, data->socket, &data->server_addr);
}

static void handle_join_command(ChatClient *data, char *addr)
{
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

	unsigned char public_key[RSA_PUB_KEY_BYTES + 1] = { 0 };

	ChatMessage msg = { 0 };
	if (data->key_pair.public_key == NULL) {
		LOG_ERR("Public key not initialized");
		return;
	}

	size_t len = rsa_to_bytes(data->key_pair.public_key, public_key);

	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_JOIN, len, data->server_header_key, (char *)public_key);

	LOG_INFO("Sending join message to server...\n");
	LOG_INFO("Server addr: %s\n", inet_ntoa(data->server_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &data->server_addr);
	submit_worker_task_timeout(data->threadpool, check_client_connected, &data->connected,
							   CLIENT_JOIN_TIMEOUT);
}

// TODO fix all this naming lmao and buffer size
static void handle_connect_command(ChatClient *data, char *addr)
{
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

	char body[CHAT_CONNECT_MESSAGE_SIZE] = { 0 };
	addr_to_string(body, &ext_addr);
	body[strlen(body)] = '|';
	size_t len = rsa_to_bytes(data->key_pair.public_key, (unsigned char *)(body + strlen(body)));

	if (len == 0) {
		LOG_ERR("Failed to convert public key to bytes");
		return;
	}

	char enc_buf[737] = { 0 };
	int enc_size = s_encrypt_data(&data->server_key, (unsigned char *)body, strlen(body),
								  (unsigned char *)enc_buf);

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_CONNECT, enc_size, data->server_header_key, enc_buf);

	LOG_INFO("Sending connect message to other user...\n");
	LOG_INFO("User addr: %s\n", inet_ntoa(ext_addr.sin_addr));
	chat_msg_send(&msg, data->socket, &data->server_addr);

	// Send connect message to other user at the same time to utilize UDP hole punching
	ChatMessage ext_msg = { 0 };
	chat_msg_init(&ext_msg, CHAT_MESSAGE_TYPE_PING, 0, data->server_header_key, NULL);
	chat_msg_send(&ext_msg, data->socket, &ext_addr);
}

static void handle_disconnect_command(ChatClient *data, char *addr)
{
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
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_DISCONNECT, 0, data->server_header_key, NULL);
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

	char buffer[CHAT_MESSAGE_MAX_LEN] = { 0 };

	addr_book_to_string(buffer, data->addr_book, NULL);
	LOG_INFO("%s", buffer);
}

static void handle_setname_command(ChatClient *data, char *name)
{
	if (name == NULL) {
		LOG_ERR("Invalid arguments for setname command");
		print_help();
		return;
	}

	memset(data->name, 0, sizeof(data->name));
	strncpy(data->name, name, strlen(name));

	LOG_INFO("Set name to %s", data->name);
}

static void handle_msg_command(ChatClient *data, char *addr, char *msg)
{
	if (addr == NULL) {
		LOG_ERR("Invalid arguments for msg command");
		print_help();
		return;
	}

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

	chat_msg_send_text_enc(msg, data->socket, &ext_addr, &entry->key, data->server_header_key);
}

static void handle_ping_command(ChatClient *data, char *addr)
{
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
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_PING, 0, data->server_header_key, NULL);

	LOG_INFO("Sending ping message to other address %s...\n", addr);
	chat_msg_send(&msg, data->socket, &ext_addr);
}

// Function name is hella retarded
static void disconnect_connection(void *data, void *arg)
{
	AddrEntry *entry = data;
	ChatClient *client = arg;

	ChatMessage msg = { 0 };
	chat_msg_init(&msg, CHAT_MESSAGE_TYPE_DISCONNECT, 0, client->server_header_key, NULL);

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

char *command_completion_generator(const char *text, int state)
{
	static int list_index, len;
	char *name;

	if (state == 0) {
		list_index = 0;
		len = strlen(text);
	}

	while (list_index < CLIENT_COMMAND_COUNT) {
		name = CLIENT_COMMAND_STRINGS[list_index];
		list_index++;

		if (strncmp(name, text, len) == 0) {
			return strdup(name);
		}
	}

	return NULL;
}

char **command_tab_completion(const char *text, int start, int end)
{
	(void)start;
	(void)end;
	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, command_completion_generator);
}

static bool string_eq(const char *fst, const char *snd)
{
	int fst_len = strlen(fst);
	int snd_len = strlen(snd);
	return strncmp(fst, snd, fst_len < snd_len ? fst_len : snd_len) == 0;
}

static void user_command_loop(void *arg)
{
	ChatClient *data = (ChatClient *)arg;
	printf("Welcome to chatp2p client!\n");
	char *save_ptr = NULL;
	rl_attempted_completion_function = command_tab_completion;
	rl_bind_key('\t', rl_complete);
	char *command_buffer = NULL;
	print_help();

	while (data->running) {
		command_buffer = readline("bare-chat> ");
		if (!command_buffer) {
			continue;
		}

		if (strlen(command_buffer) == 0) {
			free(command_buffer);
			continue;
		}

		add_history(command_buffer);

		char *command = strtok_r(command_buffer, " ", &save_ptr);

		if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_HELP])) {
			print_help();
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_QUIT])) {
			handle_quit_command(data);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_INFO])) {
			handle_info_command(data);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_JOIN])) {
			char *addr = strtok_r(NULL, "\n", &save_ptr);
			handle_join_command(data, addr);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_LEAVE])) {
			handle_leave_command(data);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_CONNECT])) {
			char *addr = strtok_r(NULL, "\n", &save_ptr);
			handle_connect_command(data, addr);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_DISCONNECT])) {
			char *addr = strtok_r(NULL, "\n", &save_ptr);
			handle_disconnect_command(data, addr);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_LIST])) {
			handle_list_command(data);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_SETNAME])) {
			char *name = strtok_r(NULL, "\n", &save_ptr);
			handle_setname_command(data, name);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_MSG])) {
			char *addr = strtok_r(NULL, " ", &save_ptr);
			char *msg = strtok_r(NULL, "\n", &save_ptr);
			handle_msg_command(data, addr, msg);
		} else if (string_eq(command, CLIENT_COMMAND_STRINGS[CLIENT_PING])) {
			char *addr = strtok_r(NULL, "\n", &save_ptr);
			handle_ping_command(data, addr);
		} else {
			LOG_ERR("Unknown command: '%s'", command);
			print_help();
		}

		free(command_buffer);
	}
}

static bool chat_recv_text_handler(void *data)
{
	void **args = data;
	char *name = args[0];
	char *addr_str = args[1];
	char *dec_out = args[2];
	bool *is_server = args[3];

#ifdef __linux__
	if (!*is_server) {
		char notification[1024] = { 0 };
		snprintf(notification, sizeof(notification), "notify-send \"New message from %s|%s!\"",
				 name, addr_str);
		system(notification);
	}
#endif

	printf("\033[0;32m ");
	printf("-------------------------------------------------------\n");
	printf("Received message from %s : %s\n", name, addr_str);
	printf("Message: %s\n", dec_out);
	printf("-------------------------------------------------------\n");
	printf("\033[0m ");

	return true;
}

static void chat_recv_funcs_init(void)
{
	extra_message_handlers[CHAT_MESSAGE_TYPE_TEXT] = chat_recv_text_handler;
	// Todo add more handlers for other message types if needed
}

int main(void)
{
	// Init extra handlers
	chat_recv_funcs_init();

	ChatClient client;
	if (client_init(&client, ".env") == -1) {
		LOG_ERR("Failed to initialize server, exiting...");
		return -1;
	}

	if (client_run(&client, user_command_loop) == -1) {
		LOG_ERR("Failed to run server, exiting...");
		client_free(&client);
		return -1;
	}

	client_free(&client);

	return 0;
}