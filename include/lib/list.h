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

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define LIST_STARTING_CAPACITY 32
#define LIST_ITEM_NOT_FOUND __SIZE_MAX__

typedef struct list_t {
    uint8_t *items;
    size_t t_size;
    size_t size;
    size_t capacity;
} List;

typedef int compare_fn_t(const void *, const void *);

bool list_init(List *list, size_t t_size);
bool list_init_prealloc(List *list, size_t t_size, size_t capacity);
bool list_free(List *list);

bool list_empty(const List *list);

size_t list_index_of(List *list, const void *item, compare_fn_t *cmp);

bool list_append(List *list, void *item);

void *list_get(List *list, size_t idx);
bool list_contains(List *list, const void *item, compare_fn_t *cmp);

bool list_remove(List *list, size_t idx);
bool list_remove_item(List *list, const void *item, compare_fn_t *cmp);
bool list_remove_all(List *list);

bool list_sort(List *list, compare_fn_t *cmp);

#endif