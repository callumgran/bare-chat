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
#ifndef CHAT_MESSAGE_H
#define CHAT_MESSAGE_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define SERVER_KEY 696969
#define CHAT_MESSAGE_MAX_LEN UINT16_MAX - 1

typedef enum {
	CHAT_MESSAGE_TYPE_TEXT = 0, // Used for sending text messages to other clients
	CHAT_MESSAGE_TYPE_JOIN, // Used for when a client joins the server
	CHAT_MESSAGE_TYPE_JOIN_RESPONSE, // Used for when a client joins in response to a join message
	CHAT_MESSAGE_TYPE_NAME, // Used for when a client changes their name
	CHAT_MESSAGE_TYPE_LEAVE, // Used for when a client leaves the server
	CHAT_MESSAGE_TYPE_CONNECT, // Used for when a client connects to a peer
	CHAT_MESSAGE_TYPE_CONNECT_RESPONSE, // Used for when a client connects in response to a connect
										// message
	CHAT_MESSAGE_TYPE_DISCONNECT, // Used for when a client disconnects from a peer
	CHAT_MESSAGE_TYPE_ERROR, // Used for sending errors to the client
	CHAT_MESSAGE_TYPE_INFO, // Used for sending info about the server
	CHAT_MESSAGE_TYPE_PING, // Used for pinging the server
	CHAT_MESSAGE_TYPE_PONG, // Used for responding to pings
	CHAT_MESSAGE_TYPE_UNKNOWN, // Used for unknown message types
	CHAT_MESSAGE_TYPE_COUNT // Used for counting the number of message types
} ChatMessageType;

/*
	Chat message packet is a udp package with the following header format:

	Chat message type (2 bytes)
	Message length (2 bytes)
	Server key (4 bytes)
	Body (x * 1 byte)

	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |         Chat Message Type     |         Message Length        |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                          Server Key                           |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 |                         Message Body                          |
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct chat_msg_header_t {
	uint16_t type;
	uint16_t len;
	uint32_t server_key;
} __attribute__((packed));

typedef struct chat_msg_t {
	struct chat_msg_header_t header;
	char *body;
} ChatMessage;

extern char *CHAT_MESSAGE_TYPE_STRINGS[CHAT_MESSAGE_TYPE_COUNT];

void chat_msg_init(ChatMessage *msg, ChatMessageType type, uint16_t len, uint32_t server_key,
				   char *body);

ssize_t chat_msg_from_string(ChatMessage *msg, const char *buffer, size_t len);

ssize_t chat_msg_to_string(const ChatMessage *msg, char *buffer, size_t len);

int chat_msg_header_to_string(char *buffer, const struct chat_msg_header_t *header);

void chat_msg_free(ChatMessage *msg);

void chat_msg_send(ChatMessage *msg, int socket, const struct sockaddr_in *client_addr);

void chat_msg_send_text(char *text, int socket, const struct sockaddr_in *client_addr);

#endif // CHAT_MESSAGE_H
