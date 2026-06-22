int gcd(int a, int b){
    while(b){
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

long fib(int n){
    long a = 0, b = 1;
    for(int i = 0; i < n; i++){
        long t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int is_prime(int n){
    if(n < 2) return 0;
    for(int i = 2; i * i <= n; i++){
        if(n % i == 0) return 0;
    }
    return 1;
}

int sum_array(const int *a, int n){
    int s = 0;
    for(int i = 0; i < n; i++) s += a[i];
    return s;
}