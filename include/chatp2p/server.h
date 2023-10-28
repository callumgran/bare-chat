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

#ifndef SERVER_H
#define SERVER_H

#include <chatp2p/address_book.h>
#include <lib/logger.h>
#include <lib/threadpool.h>

#define SERVER_BUF_LEN 4096

typedef struct {
	int socket;
	bool running;
	AddrBook *addr_book;
	Threadpool *threadpool;
} ChatServer;

typedef struct {
	size_t len;
	int socket;
	bool *running;
	AddrBook *addr_book;
	char buffer[SERVER_BUF_LEN];
	struct sockaddr_in client_addr;
} ServerThreadData;

int server_init(ChatServer *server, char *env_file);

int server_run(ChatServer *server);

void server_free(ChatServer *server);

#endif // SERVER_H