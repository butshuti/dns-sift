#include <string.h>
#include "domain_utils.h"

#define MAX_STR_LEN 256

void reverse(char *string)
{
	if(!string)return;
    int length = strlen(string) ;
    if(length >= MAX_STR_LEN)return;
    int c, i, j;
    for (i = 0, j = length - 1; i < j; i++, j--)
    {
        c = string[i];
        string[i] = string[j];
        string[j] = c;
    }
}
