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

#ifndef CLIENT_H
#define CLIENT_H

#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <encrypt/encrypt.h>
#include <lib/threadpool.h>

#define CLIENT_PING_INTERVAL 30 // Iterations
#define CLIENT_JOIN_TIMEOUT 5 // Seconds

typedef struct {
    int socket;
    bool connected;
    bool running;
    AddrBook *addr_book;
    Threadpool *threadpool;
    char name[256];
    struct sockaddr_in server_addr;
    SymmetricKey server_key;
    KeyPair key_pair;
    uint32_t server_header_key;
} ChatClient;

typedef struct {
    size_t len;
    int socket;
    bool *running;
    bool *connected;
    AddrBook *addr_book;
    char buffer[CHAT_MESSAGE_MAX_LEN];
    struct sockaddr_in ext_addr;
    struct sockaddr_in server_addr;
    char *name;
    SymmetricKey *server_key;
    KeyPair *key_pair;
    uint32_t server_header_key;
} ClientThreadData;

typedef struct {
    int socket;
    ChatMessage *msg;
} PingData;

typedef bool MessageRecvExtraHandler(void *data);

extern MessageRecvExtraHandler *extra_message_handlers[CHAT_MESSAGE_TYPE_COUNT];

int client_init(ChatClient *client, char *env_file);

int client_run(ChatClient *client, worker_thread_func *user_command_loop_func);

void client_free(ChatClient *client);

#endif // CLIENT_H