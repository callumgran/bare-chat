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

#ifndef CHAT_ERROR_H
#define CHAT_ERROR_H

typedef enum {
	CHAT_BAD_ADDRESS,
	CHAT_NO_ENTRY,
	CHAT_DECRYPT_ERROR,
	CHAT_INVALID_CONNECT_MSG,
	CHAT_ALREADY_CONNECTED,
	CHAT_ADDR_BOOK_ERROR,
	CHAT_CONNECTION_DENIED,
	CHAT_BAD_PING,
    CHAT_INVALID_SERVER_KEY,
    CHAT_INVALID_MESSAGE_TYPE,
	CHAT_ERROR_COUNT
} ChatErrorType;

typedef void MessageErrorHandler(void *data);

extern MessageErrorHandler *message_error_handlers[CHAT_ERROR_COUNT];

void chat_handle_message_error(ChatErrorType type, void *data);

#endif // CHAT_ERROR_H