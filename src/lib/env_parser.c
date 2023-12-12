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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_ENV_VARS 256

#include "lib/env_parser.h"
#include "lib/logger.h"

EnvVars *env_parse(const char *env)
{
    if (env == NULL) {
        LOG_ERR(".env is NULL");
        return NULL;
    }

    EnvVars *env_vars = malloc(sizeof(EnvVars));

    env_vars->vars = malloc(MAX_ENV_VARS * sizeof(EnvVar));

    env_vars->num_vars = 0;

    if (env_vars == NULL) {
        LOG_ERR("Failed to allocate memory for EnvVars");
        return NULL;
    }

    FILE *env_file = fopen(env, "r");

    if (env_file == NULL) {
        LOG_ERR("Failed to open .env file");
        return NULL;
    }

    int num_vars = 0;
    char line[1024];

    while (fgets(line, sizeof(line), env_file) != NULL) {
        if (line[0] == '#')
            continue;

        char *key_sep = strchr(line, '=');
        char *key = strndup(line, key_sep - line);

        if (key == NULL) {
            LOG_ERR("Failed to allocate memory for key");
            env_vars_free(env_vars);
            return NULL;
        }

        char *val_sep = strchr(line, '\n');
        if (val_sep == NULL) {
            val_sep = strchr(line, '\0');
        }
        char *value = strndup(key_sep + 1, val_sep - key_sep - 1);

        if (value == NULL) {
            LOG_ERR("Failed to allocate memory for value");
            env_vars_free(env_vars);
            return NULL;
        }

        env_vars->vars[num_vars].key = key;
        env_vars->vars[num_vars].value = value;
        num_vars++;
    }

    fclose(env_file);

    env_vars->num_vars = num_vars;
    env_vars->vars = realloc(env_vars->vars, num_vars * sizeof(EnvVar));

    return env_vars;
}

char *env_get_val(EnvVars *env_vars, const char *key)
{
    if (env_vars == NULL) {
        LOG_ERR("EnvVars is NULL");
        return NULL;
    }

    if (key == NULL) {
        LOG_ERR("Key is NULL");
        return NULL;
    }

    for (int i = 0; i < env_vars->num_vars; i++) {
        if (strcmp(env_vars->vars[i].key, key) == 0) {
            return env_vars->vars[i].value;
        }
    }

    return NULL;
}

void env_vars_free(EnvVars *env_vars)
{
    if (env_vars == NULL) {
        LOG_ERR("EnvVars is NULL");
        return;
    }

    for (int i = 0; i < env_vars->num_vars; i++) {
        free(env_vars->vars[i].key);
        free(env_vars->vars[i].value);
    }

    free(env_vars->vars);
    free(env_vars);
}