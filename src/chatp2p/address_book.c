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
#include <lib/logger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


bool addr_eq(const struct sockaddr_in *addr1, const struct sockaddr_in *addr2)
{
	if (addr1 == NULL || addr2 == NULL)
		return false;

	return addr1->sin_family == addr2->sin_family && addr1->sin_port == addr2->sin_port &&
		   addr1->sin_addr.s_addr == addr2->sin_addr.s_addr;
}

int addr_to_string(char *buffer, const struct sockaddr_in *addr)
{
	if (buffer == NULL || addr == NULL)
		return -1;

	char ip[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN) == NULL)
		return -1;

	return sprintf(buffer, "%s:%d", ip, ntohs(addr->sin_port));
}

int addr_from_string(struct sockaddr_in *addr, const char *buffer)
{
	if (addr == NULL || buffer == NULL)
		return -1;

	char ip[INET_ADDRSTRLEN];
	uint16_t port;

	if (sscanf(buffer, "%[^:]:%hu", ip, &port) != 2)
		return -1;

	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1)
		return -1;

	addr->sin_port = htons(port);
	addr->sin_family = AF_INET;

	return 0;
}

int addr_from_ip_port(struct sockaddr_in *addr, const char *ip, uint16_t port)
{
	if (addr == NULL || ip == NULL)
		return -1;

	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1)
		return -1;

	addr->sin_port = htons(port);
	addr->sin_family = AF_INET;

	return 0;
}

bool addr_book_init(AddrBook *addr_book)
{
	if (addr_book == NULL)
		return false;

	addr_book->head = NULL;
	addr_book->tail = NULL;
	addr_book->size = 0;

	return true;
}

bool addr_book_free(AddrBook *addr_book)
{
	if (addr_book == NULL)
		return false;

	AddrEntry *node = addr_book->head;
	AddrEntry *next;

	while (node != NULL) {
		next = node->next;
		free(node);
		node = next;
	}

	return true;
}

bool addr_book_empty(const AddrBook *addr_book)
{
	if (addr_book == NULL)
		return false;

	return !addr_book->size;
}

bool addr_update_time(AddrBook *addr_book, const struct sockaddr_in *addr)
{
	if (addr_book == NULL || addr == NULL)
		return false;

	AddrEntry *node = addr_book->head;

	while (node != NULL) {
		if (addr_eq(&node->addr, addr)) {
			clock_gettime(CLOCK_MONOTONIC_RAW, &node->last_seen);
			return true;
		}

		node = node->next;
	}

	return false;
}

bool addr_book_push_back(AddrBook *addr_book, struct sockaddr_in *addr)
{
	if (addr_book == NULL || addr == NULL)
		return false;

	AddrEntry *node = malloc(sizeof(AddrEntry));

	if (node == NULL)
		return false;

	memcpy(&node->addr, addr, sizeof(struct sockaddr_in));
	strncpy(node->name, "loading", 255);
	symmetric_key_init(&node->key);
	clock_gettime(CLOCK_MONOTONIC_RAW, &node->last_seen);
	node->prev = addr_book->tail;
	node->next = NULL;

	if (addr_book->tail != NULL)
		addr_book->tail->next = node;

	addr_book->tail = node;

	if (addr_book->head == NULL)
		addr_book->head = node;

	addr_book->size++;

	return true;
}

bool addr_book_remove(AddrBook *addr_book, const struct sockaddr_in *addr)
{
	if (addr_book == NULL || addr == NULL)
		return NULL;

	AddrEntry *node = addr_book->head;

	while (node != NULL) {
		if (addr_eq(&node->addr, addr)) {
			if (node->prev != NULL)
				node->prev->next = node->next;

			if (node->next != NULL)
				node->next->prev = node->prev;

			if (addr_book->head == node)
				addr_book->head = node->next;

			if (addr_book->tail == node)
				addr_book->tail = node->prev;

			free(node);

			addr_book->size--;

			return true;
		}

		node = node->next;
	}

	return false;
}


bool addr_book_contains(const AddrBook *addr_book, const struct sockaddr_in *addr)
{
	if (addr_book == NULL || addr == NULL)
		return false;

	AddrEntry *node = addr_book->head;

	while (node != NULL) {
		if (addr_eq(&node->addr, addr))
			return true;

		node = node->next;
	}

	return false;
}

AddrEntry *addr_book_find(const AddrBook *addr_book, const struct sockaddr_in *addr)
{
	if (addr_book == NULL || addr == NULL)
		return NULL;

	AddrEntry *node = addr_book->head;

	while (node != NULL) {
		if (addr_eq(&node->addr, addr))
			return node;

		node = node->next;
	}

	return NULL;
}

AddrEntry *addr_book_find_by_name(const AddrBook *addr_book, const char *name)
{
	if (addr_book == NULL || name == NULL)
		return NULL;

	AddrEntry *node = addr_book->head;

	while (node != NULL) {
		if (strcmp(node->name, name) == 0)
			return node;

		node = node->next;
	}

	return NULL;
}

bool addr_book_to_string(char *buffer, AddrBook *addr_book, const struct sockaddr_in *client_addr)
{
	if (buffer == NULL || addr_book == NULL)
		return false;

	AddrEntry *node = addr_book->head;
	int offset = 0;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);

	offset += sprintf(buffer + offset, "Address Book:\n");
	while (node != NULL) {
		// Remove nodes that haven't been seen in 5 minutes from the address book
		if (now.tv_sec - node->last_seen.tv_sec > 300) {
			if (node->prev != NULL)
				node->prev->next = node->next;

			if (node->next != NULL)
				node->next->prev = node->prev;

			if (addr_book->head == node)
				addr_book->head = node->next;

			if (addr_book->tail == node)
				addr_book->tail = node->prev;

			AddrEntry *tmp = node;

			node = node->next;

			addr_book->size--;

			free(tmp);
		}

		if (client_addr != NULL) {
			if (addr_eq(&node->addr, client_addr)) {
				node = node->next;
				continue;
			}
		}

		char addr_str[INET_ADDRSTRLEN + 10];
		addr_to_string(addr_str, &node->addr);

		offset += sprintf(buffer + offset, "%s: %s\n", node->name, addr_str);

		node = node->next;
	}

	return true;
}

static void addr_book_start(AddrBookIter *iter, AddrBook *list)
{
	iter->curr = list->head;
}

static void addr_book_next(AddrBookIter *iter)
{
	iter->curr = iter->curr->next;
}

static bool addr_book_has_next(AddrBookIter *iter)
{
	return iter->curr != NULL;
}

void *addr_book_get(AddrBookIter *iter)
{
	return iter->curr;
}

void addr_book_foreach(AddrBook *dll, void (*exec)(void *, void *), void *args)
{
	AddrBookIter iter;
	addr_book_start(&iter, dll);

	while (addr_book_has_next(&iter)) {
		exec(addr_book_get(&iter), args);
		addr_book_next(&iter);
	}
}