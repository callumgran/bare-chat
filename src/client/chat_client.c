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

#include <client/client.h>
#include <lib/logger.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		LOG_ERR("Usage: %s <username> <address>", argv[0]);
		return -1;
	}
	char *username = argv[1];
	char *address = argv[2];
	ChatClient client;
	if (client_init(&client, ".env", username, address) == -1) {
		LOG_ERR("Failed to initialize server, exiting...");
		return -1;
	}

	if (client_run(&client) == -1) {
		LOG_ERR("Failed to run server, exiting...");
		client_free(&client);
		return -1;
	}

	client_free(&client);

	return 0;
}