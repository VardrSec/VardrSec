#define _GNU_SOURCE
#include <krb5.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Internal ASN.1 routines exported by upstream libkrb5; never network traffic. */
extern krb5_error_code encode_krb5_authdata(krb5_authdata *const *, krb5_data **);
extern krb5_error_code decode_krb5_authdata(const krb5_data *, krb5_authdata ***);
static void *(*real_realloc)(void *, size_t);
static int measuring;
static size_t calls;
void *realloc(void *p, size_t n) {
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    if (!real_realloc) _Exit(99);
    if (measuring) calls++;
    return real_realloc(p,n);
}
int main(int argc, char **argv) {
    const size_t count = 10000;
    krb5_authdata one = {0}, **decoded = NULL;
    krb5_authdata **items = calloc(count+1,sizeof(*items));
    krb5_data *encoded = NULL;
    krb5_error_code rc;
    size_t i, output = 0;
    int patched = argc == 2 && strcmp(argv[1],"patched") == 0;
    if (!items) return 2;
    one.ad_type = 1; one.length = 1; one.contents = (krb5_octet *)"x";
    for (i=0;i<count;i++) items[i]=&one;
    rc = encode_krb5_authdata(items,&encoded);
    if (rc) return 3;
    calls=0; measuring=1;
    rc=decode_krb5_authdata(encoded,&decoded);
    measuring=0;
    if (rc) return 4;
    while (decoded[output]) {
        if (decoded[output]->ad_type!=1 || decoded[output]->length!=1 || decoded[output]->contents[0]!='x') return 5;
        output++;
    }
    printf("elements=%zu decoded=%zu bytes=%u decode_realloc_calls=%zu expected=%s\n", count,output,encoded->length,calls,patched?"patched":"baseline");
    krb5_free_authdata(NULL,decoded); krb5_free_data(NULL,encoded); free(items);
    if(output!=count) return 6;
    return patched ? calls != 1 : calls < count;
}
