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
#ifndef ADDRESS_BOOK_H
#define ADDRESS_BOOK_H

#include <encrypt/encrypt.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define SEC_TO_NS(sec) ((sec)*1000000000)
#define MAX_GONE_TIME_NS SEC_TO_NS(300)
#define IP_PORT_MAX_LEN 22 // Maximum length of an ip address and port string
#define NAME_MAX_LEN 256 // Maximum length of a client name

typedef struct address_book_entry_t {
	struct sockaddr_in addr;
	char name[NAME_MAX_LEN];
	struct timespec last_seen;
	struct address_book_entry_t *prev;
	struct address_book_entry_t *next;
	SymmetricKey key;
} AddrEntry;

typedef struct address_book_t {
	AddrEntry *head;
	AddrEntry *tail;
	size_t size;
} AddrBook;

typedef struct {
	AddrEntry *curr;
} AddrBookIter;

int addr_to_string(char *buffer, const struct sockaddr_in *addr);

int addr_from_string(struct sockaddr_in *addr, const char *buffer);

int addr_from_ip_port(struct sockaddr_in *addr, const char *ip, uint16_t port);

bool addr_eq(const struct sockaddr_in *addr1, const struct sockaddr_in *addr2);

bool addr_book_init(AddrBook *list);
bool addr_book_free(AddrBook *list);

bool addr_book_empty(const AddrBook *list);

bool addr_book_push_back(AddrBook *list, struct sockaddr_in *addr);

bool addr_book_remove(AddrBook *list, const struct sockaddr_in *addr);

bool addr_book_contains(const AddrBook *list, const struct sockaddr_in *addr);

AddrEntry *addr_book_find(const AddrBook *list, const struct sockaddr_in *addr);

AddrEntry *addr_book_find_by_name(const AddrBook *list, const char *name);

bool addr_book_to_string(char *buffer, AddrBook *list, const struct sockaddr_in *client_addr);

void addr_book_foreach(AddrBook *dll, void (*exec)(void *, void *), void *args);

#endif // ADDRESS_BOOK_H