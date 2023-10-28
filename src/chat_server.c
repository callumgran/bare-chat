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

#include <chatp2p/server.h>
#include <lib/logger.h>

int main(void)
{
	ChatServer server;
	if (server_init(&server, ".env") == -1) {
		LOG_ERR("Failed to initialize server, exiting...");
		return -1;
	}

	if (server_run(&server) == -1) {
		LOG_ERR("Failed to run server, exiting...");
		server_free(&server);
		return -1;
	}

	server_free(&server);

	return 0;
}