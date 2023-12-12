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

#include <lib/queue.h>

bool queue_init(Queue *queue, size_t capacity, size_t t_size)
{
    if (queue == NULL)
        return false;

    if (capacity == 0 || t_size == 0)
        return false;

    queue->start = 0;
    queue->end = 0;
    queue->size = 0;
    queue->capacity = capacity;
    queue->t_size = t_size;
    queue->items = malloc(queue->capacity * queue->t_size);

    if (queue->items == NULL)
        return false;

    return true;
}

bool queue_free(Queue *queue)
{
    if (queue == NULL || queue->items == NULL)
        return false;

    free(queue->items);

    return true;
}

bool queue_empty(const Queue *queue)
{
    if (queue == NULL)
        return false;

    return !queue->size;
}

bool queue_full(const Queue *queue)
{
    if (queue == NULL)
        return false;

    return queue->size == queue->capacity;
}

bool queue_push(Queue *queue, void *item)
{
    if (queue == NULL || item == NULL || queue->items == NULL)
        return false;

    if (queue_full(queue))
        return false;

    memcpy(queue->items + queue->end * queue->t_size, item, queue->t_size);
    queue->end = (queue->end + 1) % queue->capacity;
    ++queue->size;
    return true;
}

bool queue_pop(Queue *queue, void *dest)
{
    if (queue == NULL || queue->items == NULL || dest == NULL)
        return false;

    if (queue_empty(queue))
        return false;

    void *ret = memcpy(dest, queue->items + queue->start * queue->t_size, queue->t_size);

    if (ret == NULL)
        return false;

    queue->start = (queue->start + 1) % queue->capacity;
    --queue->size;

    return true;
}

bool queue_get(const Queue *queue, void *dest)
{
    if (queue == NULL || queue->items == NULL || dest == NULL)
        return false;

    if (queue_empty(queue))
        return false;

    void *ret = memcpy(dest, queue->items + queue->start * queue->t_size, queue->t_size);

    if (ret == NULL)
        return false;

    return true;
}