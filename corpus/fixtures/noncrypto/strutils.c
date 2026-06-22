#include<stddef.h>

size_t my_strlen(const char *s){
    size_t n = 0;
    while(s[n]) n++;
    return n;
}

int my_strchmp(const char *a, const char *b){
    while(*a && *a == *b){
        a++;
        b++;
    }
    return *a - *b;
}

void my_reverse(char *s, int n){
    for(int i = 0; i < n/2; i++){
        char t = s[i];
        s[i]= s[n - 1 - i];
        s[n - 1 - i] = t;
    }
}

int count_word(const char *s){
    int c = 0, in = 0;
    while(*s){
        if(*s == ' ') in = 0;
        else if(!in){
            in = 1;
            c++;
        }
        s++;
    }
    return c;
}