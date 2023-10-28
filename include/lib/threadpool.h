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

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include <lib/queue.h>

typedef void worker_thread_func(void *arg);

typedef struct {
	worker_thread_func *func;
	void *arg;
	int sleep_time;
} ThreadPoolTask;

typedef struct {
	bool cond_predicate;
	pthread_mutex_t cond_lock;
	pthread_cond_t cond_variable;
} Condition;

typedef struct {
	int max_threads;
	Queue *task_queue;
	Condition *cond_var;
	pthread_t *threads;
} Threadpool;

void threadpool_init(Threadpool *threadpool, int max_threads, int queue_size);

void threadpool_free(Threadpool *threadpool);

void threadpool_start(Threadpool *threadpool);

bool submit_worker_task(Threadpool *threadpool, worker_thread_func func, void *arg);

bool submit_worker_task_timeout(Threadpool *threadpool, worker_thread_func func, void *arg,
								int timeout);

void threadpool_stop(Threadpool *threadpool);

#endif