#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <chatp2p/address_book.h>
#include <chatp2p/chat_msg.h>
#include <lib/logger.h>
#define PING_INTERVAL 1

static int g_clientfd;
static struct sockaddr_in g_server;
static AddrBook *g_peers;

static void send_ping_to_addr(void *arg, void *data)
{
	AddrEntry *addr = arg;
	ChatMessage *msg = data;
	char buf[1024];
	addr_to_string(buf, &addr->addr);
	LOG_INFO("Pinging to %s", buf);
	chat_msg_send(msg, g_clientfd, &addr->addr);
}

void *ping_loop()
{
	ChatMessage ping;
	ping.header.server_key = SERVER_KEY;
	ping.header.type = CHAT_MESSAGE_TYPE_PING;
	ping.header.len = 0;
	ping.body = NULL;
	unsigned int i = 0;

	while (true) {
		if (i++ < PING_INTERVAL) {
			sleep(1);
			continue;
		}
		i = 0;
		chat_msg_send(&ping, g_clientfd, &g_server);
		if (g_peers != NULL)
			addr_book_foreach(g_peers, send_ping_to_addr, &ping);
	}

	LOG_INFO("Quitting keepalive_loop");
	return NULL;
}

void on_message(struct sockaddr_in from, ChatMessage msg)
{
	if (addr_eq(&g_server, &from)) {
		LOG_INFO("Server sent message");
		switch (msg.header.type) {
		case CHAT_MESSAGE_TYPE_PONG:
			char buf[1024];
			addr_to_string(buf, &from);
			LOG_INFO("PONG from %s", buf);
			break;
		default:
			break;
		}
	} else {
		switch (msg.header.type) {
		case CHAT_MESSAGE_TYPE_PONG:
			char buf[1024];
			addr_to_string(buf, &from);
			LOG_INFO("PONG from %s", buf);
			break;
		default:
			break;
		}
	}
}

void *receive_loop()
{
	struct sockaddr_in peer;
	socklen_t addrlen;
	char buf[65536];
	int nfds;
	fd_set readfds;
	struct timeval timeout;

	nfds = g_clientfd + 1;

	while (true) {
		FD_ZERO(&readfds);
		FD_SET(g_clientfd, &readfds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		int ret = select(nfds, &readfds, NULL, NULL, &timeout);
		if (ret < 1) {
			continue;
		}

		addrlen = sizeof(peer);
		memset(&peer, 0, addrlen);
		memset(buf, 0, 65536);
		int rd_size = recvfrom(g_clientfd, buf, 65536, 0, (struct sockaddr *)&peer, &addrlen);

		if (rd_size == -1) {
			LOG_ERR("Receive failed");
			continue;
		} else if (rd_size == 0) {
			LOG_ERR("Invalid message received");
			continue;
		}

		ChatMessage msg = { 0 };
		chat_msg_from_string(&msg, buf, rd_size);
		if (msg.header.server_key != SERVER_KEY || msg.body == NULL) {
			LOG_ERR("Invalid message received");
			continue;
		}
		on_message(peer, msg);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s server:port\n", argv[0]);
		return 1;
	}
	int ret;
	pthread_t keepalive_pid, receive_pid, console_pid;

	addr_from_string(&g_server, argv[1]);

	addr_book_init(g_peers);

	g_clientfd = socket(AF_INET, SOCK_DGRAM, 0);

	LOG_INFO("setting server to %s", argv[1]);

	ret = pthread_create(&keepalive_pid, NULL, &ping_loop, NULL);
	ret = pthread_create(&receive_pid, NULL, &receive_loop, NULL);

	pthread_join(receive_pid, NULL);
	pthread_join(keepalive_pid, NULL);

	close(g_clientfd);
	addr_book_free(g_peers);
	return 0;
}