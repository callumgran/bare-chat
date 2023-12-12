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
#include <chatp2p/client.h>
#include <chatp2p/error.h>
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

MessageRecvExtraHandler *extra_message_handlers[CHAT_MESSAGE_TYPE_COUNT] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

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

static void send_ping_to_addr(void *arg, void *data)
{
    AddrEntry *addr = arg;
    PingData *pd = data;
    char buf[IP_PORT_MAX_LEN] = { 0 };
    addr_to_string(buf, &addr->addr);
    chat_msg_send(pd->msg, pd->socket, &addr->addr);
}

static void ping_loop(void *arg)
{
    ChatClient *data = (ChatClient *)arg;
    ChatMessage ping;
    chat_msg_init(&ping, CHAT_MESSAGE_TYPE_PING, 0, data->server_header_key, NULL);

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

// TODO: Find correct buffer size and fix naming
static void chat_msg_text_handler(ChatMessage *msg, ClientThreadData *data)
{
    AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

    char *name = NULL;

    bool is_server = addr_eq(&data->ext_addr, &data->server_addr);

    SymmetricKey key = { 0 };

    if (entry == NULL && !is_server) {
        chat_handle_message_error(CHAT_NO_ENTRY, NULL);
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

    char addr_str[IP_PORT_MAX_LEN] = { 0 };
    if (addr_to_string(addr_str, &data->ext_addr) < 0) {
        chat_handle_message_error(CHAT_BAD_ADDRESS, NULL);
        return;
    }

    char dec_out[CHAT_MESSAGE_MAX_LEN] = { 0 };
    s_decrypt_data(&key, (unsigned char *)msg->body, msg->header.len, (unsigned char *)dec_out);

    if (extra_message_handlers[CHAT_MESSAGE_TYPE_TEXT] != NULL) {
        void *args[4] = { name, addr_str, dec_out, &is_server };
        extra_message_handlers[CHAT_MESSAGE_TYPE_TEXT]((void *)args);
    }
}

// TODO: Find correct buffer size and fix naming
static void chat_msg_connect_handler(ChatMessage *msg, ClientThreadData *data)
{
    char buf[CHAT_CONNECT_MESSAGE_SIZE] = { 0 };
    int size = s_decrypt_data(data->server_key, (unsigned char *)msg->body, msg->header.len,
                              (unsigned char *)buf);

    if (size < 0) {
        chat_handle_message_error(CHAT_DECRYPT_ERROR, NULL);
        return;
    }

    char *save_ptr = NULL;

    char *name = strtok_r(buf, "|", &save_ptr);
    char *addr = strtok_r(NULL, "|", &save_ptr);
    char *public_key = strtok_r(NULL, "", &save_ptr);

    if (name == NULL || addr == NULL || public_key == NULL) {
        chat_handle_message_error(CHAT_INVALID_CONNECT_MSG, NULL);
        return;
    }

    struct sockaddr_in ext_addr = { 0 };
    if (addr_from_string(&ext_addr, addr) < 0) {
        chat_handle_message_error(CHAT_BAD_ADDRESS, NULL);
        return;
    }

    if (addr_book_contains(data->addr_book, &ext_addr)) {
        chat_handle_message_error(CHAT_ALREADY_CONNECTED, NULL);
        return;
    }

    if (extra_message_handlers[CHAT_MESSAGE_TYPE_CONNECT] != NULL) {
        void *args[3] = { name, addr, public_key };
        bool ret = extra_message_handlers[CHAT_MESSAGE_TYPE_CONNECT]((void *)args);
        if (!ret) {
            chat_handle_message_error(CHAT_CONNECTION_DENIED, NULL);
            return;
        }
    }

    if (!addr_book_push_back(data->addr_book, &ext_addr)) {
        chat_handle_message_error(CHAT_ADDR_BOOK_ERROR, NULL);
        return;
    }

    AddrEntry *entry = addr_book_find(data->addr_book, &ext_addr);
    memset(entry->name, 0, sizeof(entry->name));
    strncpy(entry->name, name, strlen(name));

    RSA *public_key_rsa = NULL;

    char buffer[737] = { 0 };
    rsa_from_bytes(&public_key_rsa, (unsigned char *)public_key, strlen(public_key));

    char keyname[NAME_MAX_LEN + sizeof(SymmetricKey)] = { 0 };
    memcpy(keyname, entry->key.key, 32);
    memcpy(keyname + 32, entry->key.init_vect, 16);
    memcpy(keyname + sizeof(SymmetricKey), data->name, strlen(data->name));

    int len = as_encrypt_data(public_key_rsa, (unsigned char *)keyname,
                              sizeof(SymmetricKey) + strlen(data->name), (unsigned char *)buffer);

    ChatMessage connect = { 0 };
    chat_msg_init(&connect, CHAT_MESSAGE_TYPE_CONNECT_RESPONSE, len, data->server_header_key,
                  buffer);

    chat_msg_send(&connect, data->socket, &ext_addr);
}

// TODO: Find correct buffer size and fix the naming
static void chat_msg_connect_response_handler(ChatMessage *msg, ClientThreadData *data)
{
    if (addr_book_contains(data->addr_book, &data->ext_addr)) {
        chat_handle_message_error(CHAT_ALREADY_CONNECTED, NULL);
        return;
    }

    char addr_str[IP_PORT_MAX_LEN] = { 0 };
    if (addr_to_string(addr_str, &data->ext_addr) < 0) {
        chat_handle_message_error(CHAT_BAD_ADDRESS, NULL);
        return;
    }

    if (!addr_book_push_back(data->addr_book, &data->ext_addr)) {
        chat_handle_message_error(CHAT_ADDR_BOOK_ERROR, NULL);
        return;
    }

    AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

    char buf[NAME_MAX_LEN + sizeof(SymmetricKey)] = { 0 };
    int size = as_decrypt_data(data->key_pair->private_key, (unsigned char *)msg->body,
                               msg->header.len, (unsigned char *)buf);

    memset(entry->name, 0, sizeof(entry->name));
    memset(entry->key.key, 0, sizeof(entry->key.key));
    memset(entry->key.init_vect, 0, sizeof(entry->key.init_vect));

    memcpy(entry->key.key, buf, 32);
    memcpy(entry->key.init_vect, buf + 32, 16);
    memcpy(entry->name, buf + sizeof(SymmetricKey), size - sizeof(SymmetricKey));

    if (extra_message_handlers[CHAT_MESSAGE_TYPE_CONNECT_RESPONSE] != NULL) {
        void *args[] = { entry->name, addr_str };
        extra_message_handlers[CHAT_MESSAGE_TYPE_CONNECT_RESPONSE]((void *)args);
    }

    // Add some reply to the user so they know they connected successfully
}

static void chat_msg_disconnect_handler(ClientThreadData *data)
{
    if (!addr_book_contains(data->addr_book, &data->ext_addr)) {
        chat_handle_message_error(CHAT_NO_ENTRY, NULL);
        return;
    }

    char addr_str[IP_PORT_MAX_LEN] = { 0 };
    if (addr_to_string(addr_str, &data->ext_addr) < 0) {
        chat_handle_message_error(CHAT_BAD_ADDRESS, NULL);
        return;
    }

    AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

    if (extra_message_handlers[CHAT_MESSAGE_TYPE_DISCONNECT] != NULL) {
        extra_message_handlers[CHAT_MESSAGE_TYPE_DISCONNECT]((void *)entry->name);
    }

    addr_book_remove(data->addr_book, &data->ext_addr);
}

static void chat_msg_join_response_handler(ChatMessage *msg, ClientThreadData *data)
{
    unsigned char buf[sizeof(SymmetricKey)] = { 0 };

    int dec_size = as_decrypt_data(data->key_pair->private_key, (unsigned char *)msg->body,
                                   msg->header.len, buf);

    memcpy(data->server_key->key, buf, 32);
    memcpy(data->server_key->init_vect, buf + 32, 16);

    char response[272] = { 0 };
    int size = s_encrypt_data(data->server_key, (unsigned char *)data->name, strlen(data->name),
                              (unsigned char *)response);

    ChatMessage ret = { 0 };
    chat_msg_init(&ret, CHAT_MESSAGE_TYPE_NAME, size, data->server_header_key, response);
    chat_msg_send(&ret, data->socket, &data->server_addr);

    *(data->connected) = true;

    // TODO: Find out what should be sent to the handler
    if (extra_message_handlers[CHAT_MESSAGE_TYPE_JOIN_RESPONSE] != NULL) {
        extra_message_handlers[CHAT_MESSAGE_TYPE_JOIN_RESPONSE](NULL);
    }
}

static void chat_msg_ping_handler(ClientThreadData *data)
{
    char addr_str[IP_PORT_MAX_LEN] = { 0 };
    if (addr_to_string(addr_str, &data->ext_addr) < 0) {
        LOG_ERR("Could not convert address to string");
        return;
    }

    AddrEntry *entry = addr_book_find(data->addr_book, &data->ext_addr);

    if (entry == NULL) {
        chat_handle_message_error(CHAT_BAD_PING, NULL);
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &entry->last_seen);

    if (extra_message_handlers[CHAT_MESSAGE_TYPE_PING] != NULL) {
        extra_message_handlers[CHAT_MESSAGE_TYPE_PING]((void *)entry->name);
    }

    ChatMessage pong = { 0 };
    chat_msg_init(&pong, CHAT_MESSAGE_TYPE_PONG, 0, data->server_header_key, NULL);
    chat_msg_send(&pong, data->socket, &data->ext_addr);
}

// TODO: Find out if this is even needed
static void chat_msg_unknown_handler(ChatMessage *msg, ClientThreadData *data)
{
    (void)msg;
    (void)data;
    // TODO: This will be how clients handle unknown messages
}

// TODO: Find out if this is even needed
static void chat_msg_error_handler(ChatMessage *msg, ClientThreadData *data)
{
    (void)msg;
    (void)data;
    // TODO: This will be how clients receive errors from the server
}

static void chat_msg_handler(ChatMessage *msg, ClientThreadData *data)
{
    if (msg->header.server_key != data->server_header_key) {
        chat_handle_message_error(CHAT_INVALID_SERVER_KEY, NULL);
        return;
    }

    if (msg->header.type >= CHAT_MESSAGE_TYPE_COUNT) {
        chat_handle_message_error(CHAT_INVALID_MESSAGE_TYPE, NULL);
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

    chat_msg_handler(&msg, data);

    if (msg.body != NULL)
        free(msg.body);

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

    char *name = env_get_val(env_vars, "CLIENT_DEFAULT_NAME");
    if (name == NULL) {
        LOG_ERR("Failed to get default name from env file");
        env_vars_free(env_vars);
        return -1;
    }

    memset(client->name, 0, sizeof(client->name));
    memcpy(client->name, name, strlen(name));
    client->name[strlen(name)] = '\0';

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

    client->server_header_key = atoi(env_get_val(env_vars, "SERVER_HEADER_KEY"));

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

int client_run(ChatClient *client, worker_thread_func *user_command_loop_func)
{
    struct sockaddr_in ext_addr = { 0 };
    socklen_t len = sizeof(struct sockaddr_in);

    threadpool_start(client->threadpool);

    client->running = true;
    set_nonblocking(client->socket);

    submit_worker_task(client->threadpool, ping_loop, (void *)client);
    submit_worker_task(client->threadpool, user_command_loop_func, (void *)client);

    int nfds = client->socket + 1;
    fd_set readfds;
    char buffer[CHAT_MESSAGE_MAX_LEN] = { 0 };

    set_nonblocking(nfds);

    while (client->running) {
        if (!check_fd(nfds, client->socket, &readfds))
            continue;

        memset(buffer, 0, CHAT_MESSAGE_MAX_LEN);
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
            data->server_header_key = client->server_header_key;
            submit_worker_task(client->threadpool, handle_receive_msg, (void *)data);
        } else {
            LOG_ERR("recvfrom() failed for some reason");
        }
    }

    LOG_INFO("Shutting down chatp2p client...");

    threadpool_stop(client->threadpool);

    return 0;
}
