/*
 *  Copyright (C) 2022-2023 Callum Gran
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

#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct queue_t {
    uint8_t *items;
    size_t t_size;
    size_t size;
    size_t capacity;
    size_t start;
    size_t end;
} Queue;

bool queue_init(Queue *queue, size_t capacity, size_t t_size);
bool queue_free(Queue *queue);

bool queue_empty(const Queue *queue);
bool queue_full(const Queue *queue);

bool queue_push(Queue *queue, void *item);
bool queue_pop(Queue *queue, void *dest);
bool queue_get(const Queue *queue, void *dest);

#endif