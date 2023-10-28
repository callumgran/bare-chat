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

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/logger.h>
#include <lib/threadpool.h>

void threadpool_init(Threadpool *threadpool, int max_threads, int queue_size)
{
	Queue *queue = (Queue *)(malloc(sizeof(Queue)));
	if (!queue_init(queue, queue_size, sizeof(ThreadPoolTask))) {
		free(queue);
		LOG_ERR("Failed to initialize threadpool queue");
		return;
	}

	threadpool->task_queue = queue;

	threadpool->max_threads = max_threads;
	threadpool->threads = (pthread_t *)(malloc(max_threads * sizeof(pthread_t)));

	threadpool->cond_var = (Condition *)(malloc(sizeof(Condition)));
	threadpool->cond_var->cond_predicate = true;
	pthread_mutex_init(&threadpool->cond_var->cond_lock, NULL);
	pthread_cond_init(&threadpool->cond_var->cond_variable, NULL);
}

void threadpool_stop(Threadpool *workers)
{
	pthread_mutex_lock(&workers->cond_var->cond_lock);
	workers->cond_var->cond_predicate = false;
	pthread_cond_broadcast(&workers->cond_var->cond_variable);
	pthread_mutex_unlock(&workers->cond_var->cond_lock);
	for (int i = 0; i < workers->max_threads; i++)
		pthread_join(*(workers->threads + i), NULL);
}

void threadpool_free(Threadpool *workers)
{
	queue_free(workers->task_queue);
	free(workers->task_queue);

	free(workers->threads);

	pthread_mutex_destroy(&workers->cond_var->cond_lock);
	pthread_cond_destroy(&workers->cond_var->cond_variable);

	free(workers->cond_var);
}

static void *start_worker_thread(void *arg)
{
	Threadpool *data = (Threadpool *)arg;
	while (true) {
		ThreadPoolTask item = (ThreadPoolTask){ 0 };
		pthread_mutex_lock(&data->cond_var->cond_lock);
		while (queue_empty(data->task_queue) && data->cond_var->cond_predicate)
			pthread_cond_wait(&data->cond_var->cond_variable, &data->cond_var->cond_lock);
		bool ret = queue_pop(data->task_queue, &item);
		pthread_cond_signal(&data->cond_var->cond_variable);
		pthread_mutex_unlock(&data->cond_var->cond_lock);

		if (ret && data->cond_var->cond_predicate) {
			usleep(item.sleep_time);
			item.func(item.arg);
		} else {
			pthread_exit(NULL);
		}
	}
}

void threadpool_start(Threadpool *workers)
{
	for (int i = 0; i < workers->max_threads; i++)
		pthread_create(workers->threads + i, NULL, start_worker_thread, workers);
}

static bool submit_task(Threadpool *workers, ThreadPoolTask *task)
{
	pthread_mutex_lock(&workers->cond_var->cond_lock);
	bool ret = queue_push(workers->task_queue, (void *)task);
	while (!ret) {
		pthread_cond_wait(&workers->cond_var->cond_variable, &workers->cond_var->cond_lock);
		ret = queue_push(workers->task_queue, (void *)task);
	}
	pthread_mutex_unlock(&workers->cond_var->cond_lock);
	pthread_cond_signal(&workers->cond_var->cond_variable);
	return ret;
}

bool submit_worker_task(Threadpool *workers, worker_thread_func func, void *arg)
{
	ThreadPoolTask task = (ThreadPoolTask){ 0 };
	task.func = func;
	task.arg = arg;
	task.sleep_time = 0;
	return submit_task(workers, &task);
}

bool submit_worker_task_timeout(Threadpool *workers, worker_thread_func func, void *arg,
								int timeout)
{
	ThreadPoolTask task = (ThreadPoolTask){ 0 };
	task.func = func;
	task.arg = arg;
	task.sleep_time = timeout;
	return submit_task(workers, &task);
}