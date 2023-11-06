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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <lib/list.h>

static bool increase_capacity(List *list)
{
	if (list->size == list->capacity) {
		list->capacity *= 2;
		list->items = realloc(list->items, list->capacity * list->t_size);
		if (list->items == NULL)
			return false;
	}

	return true;
}

bool list_init(List *list, size_t t_size)
{
	if (list == NULL)
		return false;

	if (t_size == 0)
		return false;

	list->t_size = t_size;
	list->size = 0;
	list->capacity = LIST_STARTING_CAPACITY;
	list->items = malloc(list->capacity * list->t_size);

	if (list->items == NULL)
		return false;

	return true;
}

bool list_init_prealloc(List *list, size_t t_size, size_t capacity)
{
	if (list == NULL)
		return false;

	list->t_size = t_size;
	list->size = 0;
	list->capacity = capacity;
	list->items = malloc(list->capacity * list->t_size);

	if (list->items == NULL)
		return false;

	return true;
}

bool list_free(List *list)
{
	if (list == NULL || list->items == NULL)
		return false;

	free(list->items);

	return true;
}

bool list_empty(const List *list)
{
	if (list == NULL)
		return false;

	return !list->size;
}

size_t list_index_of(List *list, const void *item, compare_fn_t *cmp)
{
	if (list == NULL || item == NULL || list->items == NULL)
		return LIST_ITEM_NOT_FOUND;

	for (size_t i = 0; i < list->size; i++) {
		if (cmp(list->items + i * list->t_size, item) == 0) {
			return i;
		}
	}

	return LIST_ITEM_NOT_FOUND;
}

void *list_get(List *list, size_t idx)
{
	if (list == NULL || list->items == NULL)
		return NULL;

	if (idx >= list->size)
		return NULL;

	return list->items + idx * list->t_size;
}

bool list_contains(List *list, const void *item, compare_fn_t *cmp)
{
	if (list == NULL || item == NULL || list->items == NULL)
		return false;

	return list_index_of(list, item, cmp) != LIST_ITEM_NOT_FOUND;
}

bool list_append(List *list, void *item)
{
	if (list == NULL || item == NULL || list->items == NULL)
		return false;

	if (increase_capacity(list) == false)
		return false;

	memcpy(list->items + list->size * list->t_size, item, list->t_size);

	++list->size;

	return true;
}

bool list_remove(List *list, size_t idx)
{
	if (list == NULL || list->items == NULL)
		return false;

	if (idx >= list->size)
		return false;

	for (size_t i = idx; i < list->size - 1; i++)
		memcpy(list->items + i * list->t_size, list->items + (i + 1) * list->t_size, list->t_size);

	--list->size;

	return true;
}

bool list_remove_item(List *list, const void *item, compare_fn_t *cmp)
{
	if (list == NULL || item == NULL || cmp == NULL || list->items == NULL)
		return false;

	size_t ret;

	if ((ret = list_index_of(list, item, cmp)) == LIST_ITEM_NOT_FOUND)
		return false;

	return list_remove(list, ret);
}

bool list_remove_all(List *list)
{
	if (list == NULL || list->items == NULL)
		return false;

	list->size = 0;
	list->capacity = LIST_STARTING_CAPACITY;
	list->items = realloc(list->items, list->capacity * list->t_size);

	return true;
}

bool list_sort(List *list, compare_fn_t *cmp)
{
	if (list == NULL || cmp == NULL || list->items == NULL)
		return false;

	if (list->size == 0)
		return false;

	if (list->size == 1)
		return true;

	qsort(list->items, list->size, list->t_size, cmp);

	return true;
}