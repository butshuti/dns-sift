#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h> 
#include <err.h>
#include "config_parser.h"

void parse_next_nameserver(char *attrs, struct string_ll **ret)
{
	char *next = NULL, *attribute = NULL;
	static struct string_ll *tmp = NULL;
	if(!tmp){
		tmp = *ret;
	}
	if(!strtok_r(attrs, " ", &next))
	{
		return;
	}
	while( (attribute = strtok_r(NULL, " ", &next)) != NULL)
	{
		int idx = 0;
		while(isprint(attribute[idx++]));
		if(idx <= strlen(attribute)){
			attribute[idx-1] = '\0';
		}
		struct string_ll *next_entry = malloc(sizeof(struct string_ll));
		if(!next_entry){
			err(-1, "parse_next_nameserver: ");
		}
		next_entry->val = strdup(attribute);
		next_entry->next = NULL;
		if(*ret == NULL){
			*ret = next_entry;
		}else{
			tmp->next = next_entry;
		}
		tmp = next_entry;
	}
}

void parse_nameservers(char *conf_file, struct string_ll **nameservers)
{
	FILE *in;
	char buf[1024];
	memset(buf, 0, 1024);
	char *pos = buf, *next_line;
	*nameservers = NULL;
	if((in = fopen(conf_file, "r")) != NULL)
	{
		while (fgets(pos, sizeof(buf), in))
		{
			/* Skip whitespaces*/
			while (*pos == ' '  || *pos == '\f' || *pos == '\t' || *pos == '\v')pos++;
			/* Skip comments or end of line */
			if (*pos == '#' || *pos == '\r' || *pos == '\n')continue;
			if((next_line = strstr(pos, "nameserver")) == pos)
			{
				parse_next_nameserver(next_line, nameservers);
			}
		}
		fclose(in);	
	}else{
		fprintf(stderr, "Could not open config file %s (ERROR: %s)\n", conf_file, strerror(errno));
	}
}
