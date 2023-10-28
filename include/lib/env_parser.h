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

#ifndef ENV_PARSER_H
#define ENV_PARSER_H

typedef struct {
	char *key;
	char *value;
} EnvVar;

typedef struct {
	EnvVar *vars;
	int num_vars;
} EnvVars;

EnvVars *env_parse(const char *env);

char *env_get_val(EnvVars *env_vars, const char *key);

void env_vars_free(EnvVars *env_vars);

#endif // ENV_PARSER_H