#include <sys/stat.h>
#include <stdint.h>
 
struct upstream {
	uint32_t address;
	struct upstream *next;
};

typedef struct {
	struct upstream *list;
	time_t last_refreshed;
	struct stat last_config_change;
} upstreams_list;

int is_configured_upstream(uint32_t address);
int is_black_upstream(uint32_t address);
int upstream_score(uint32_t address);
