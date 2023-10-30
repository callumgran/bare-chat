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
#include <chatp2p/chat_msg.h>
#include <lib/logger.h>
#include <encrypt/encrypt.h>
#include <string.h>

char *CHAT_MESSAGE_TYPE_STRINGS[CHAT_MESSAGE_TYPE_COUNT] = { "CHAT_MESSAGE_TYPE_TEXT",
															 "CHAT_MESSAGE_TYPE_JOIN",
															 "CHAT_MESSAGE_TYPE_JOIN_RESPONSE",
															 "CHAT_MESSAGE_TYPE_NAME",
															 "CHAT_MESSAGE_TYPE_LEAVE",
															 "CHAT_MESSAGE_TYPE_CONNECT",
															 "CHAT_MESSAGE_TYPE_CONNECT_RESPONSE",
															 "CHAT_MESSAGE_TYPE_DISCONNECT",
															 "CHAT_MESSAGE_TYPE_ERROR",
															 "CHAT_MESSAGE_TYPE_INFO",
															 "CHAT_MESSAGE_TYPE_PING",
															 "CHAT_MESSAGE_TYPE_PONG",
															 "CHAT_MESSAGE_TYPE_UNKNOWN" };

void chat_msg_header_init(struct chat_msg_header_t *header, ChatMessageType type, uint16_t len,
						  uint32_t server_key)
{
	if (header == NULL)
		return;

	header->type = type;
	header->len = len;
	header->server_key = server_key;
}

void chat_msg_init(ChatMessage *msg, ChatMessageType type, uint16_t len, uint32_t server_key,
				   char *body)
{
	if (msg == NULL)
		return;

	chat_msg_header_init(&msg->header, type, len, server_key);
	msg->body = body;
}

int chat_msg_header_to_string(char *buffer, const struct chat_msg_header_t *header)
{
	return sprintf(buffer, "Chat message header:\n\tType: %s\n\tLength: %d\n\tServer key: %d\n",
				   CHAT_MESSAGE_TYPE_STRINGS[header->type], header->len, header->server_key);
}

ssize_t chat_msg_from_string(ChatMessage *msg, const char *buffer, size_t len)
{
	if (buffer == NULL || msg == NULL)
		return -1;

	if (len < sizeof(struct chat_msg_header_t))
		return -1;

	ssize_t idx = 0;
	memcpy(&msg->header.type, buffer + idx, sizeof(uint16_t));
	msg->header.type = ntohs(msg->header.type);
	idx += sizeof(uint16_t);
	memcpy(&msg->header.len, buffer + idx, sizeof(uint16_t));
	msg->header.len = ntohs(msg->header.len);
	idx += sizeof(uint16_t);
	memcpy(&msg->header.server_key, buffer + idx, sizeof(uint32_t));
	msg->header.server_key = ntohl(msg->header.server_key);
	idx += sizeof(uint32_t);

	// Check if the message length is valid
	if (len < sizeof(struct chat_msg_header_t) + msg->header.len)
		return -1;

	if (msg->header.len == 0) {
		msg->body = NULL;
		return idx;
	}

	msg->body = malloc(msg->header.len);
	memcpy(msg->body, buffer + idx, msg->header.len);
	idx += msg->header.len;

	return idx;
}

ssize_t chat_msg_to_string(const ChatMessage *msg, char *buffer, size_t len)
{
	if (buffer == NULL || msg == NULL) {
		LOG_ERR("Invalid arguments");
		return -1;
	}

	if (len < sizeof(struct chat_msg_header_t) + msg->header.len) {
		LOG_ERR("Buffer too small");
		return -1;
	}

	uint16_t type = htons(msg->header.type);
	uint16_t h_len = htons(msg->header.len);
	uint32_t server_key = htonl(msg->header.server_key);

	ssize_t idx = 0;
	memcpy(buffer + idx, &type, sizeof(uint16_t));
	idx += sizeof(uint16_t);
	memcpy(buffer + idx, &h_len, sizeof(uint16_t));
	idx += sizeof(uint16_t);
	memcpy(buffer + idx, &server_key, sizeof(uint32_t));
	idx += sizeof(uint32_t);

	if (msg->body == NULL)
		return idx;
	
	memcpy(buffer + idx, msg->body, msg->header.len);
	idx += msg->header.len;

	return idx;
}

void chat_msg_free(ChatMessage *msg)
{
	if (msg == NULL)
		return;

	free(msg->body);
	msg->body = NULL;
}

void chat_msg_send(ChatMessage *msg, int socket, const struct sockaddr_in *addr)
{
	if (msg == NULL || addr == NULL)
		return;

	char buffer[CHAT_MESSAGE_MAX_LEN];
	ssize_t len = chat_msg_to_string(msg, buffer, CHAT_MESSAGE_MAX_LEN);

	if (len < 0) {
		LOG_ERR("Failed to convert message to string");
		return;
	}

	if (sendto(socket, buffer, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
		LOG_ERR("Failed to send message.");
		return;
	}
}

void chat_msg_send_text_enc(char *text, int socket, const struct sockaddr_in *addr, SymmetricKey *key)
{
	if (addr == NULL)
		return;

	char buffer[CHAT_MESSAGE_MAX_LEN];

	ChatMessage msg = { 0 };
	int len = 0;
	msg.body = NULL;
	if (text != NULL) {
		msg.body = buffer;
		len = s_encrypt_data(key, text, strlen(text), msg.body);
	}
	msg.header.type = CHAT_MESSAGE_TYPE_TEXT;
	msg.header.server_key = SERVER_KEY;
	msg.header.len = len;

	chat_msg_send(&msg, socket, addr);
}

void chat_msg_send_text(char *text, int socket, const struct sockaddr_in *addr)
{
	if (addr == NULL)
		return;

	ChatMessage msg = { 0 };
	msg.header.type = CHAT_MESSAGE_TYPE_TEXT;
	msg.header.len = text == NULL ? 0 : strlen(text);
	msg.header.server_key = SERVER_KEY;
	msg.body = text;

	chat_msg_send(&msg, socket, addr);
}