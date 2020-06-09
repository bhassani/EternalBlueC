#ifndef EX_STRING_H_INCLUDED
#define EX_STRING_H_INCLUDED

int replace_str(char *pStrBuf, char *pOld, char *pNew);
char *upper_str(char *pStr);
char *lower_str(char *pStr);
char* strtok_r(char *str, const char *delim, char **nextp);

#endif // EX_STRING_H_INCLUDED
