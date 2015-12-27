struct string_ll {
	char *val;
	struct string_ll *next;
};

void parse_next_nameserver(char *attrs, struct string_ll **ret);
void parse_nameservers(char *conf_file, struct string_ll **nameservers);
