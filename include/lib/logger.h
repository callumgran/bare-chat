/*
 *  Copyright (C) 2023 Nicolai Brand
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

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

#define LOG_INFO(...)                         \
	({                                        \
		fprintf(stdout, "\033[0;33m[LOG]: "); \
		fprintf(stdout, __VA_ARGS__);         \
		fprintf(stdout, "\033[0m\n");         \
	})

#define LOG_ERR(...)                          \
	({                                        \
		fprintf(stderr, "\033[0;31m[ERR]: "); \
		fprintf(stderr, __VA_ARGS__);         \
		fprintf(stderr, "\033[0m\n");         \
	})

#endif