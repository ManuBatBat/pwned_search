// pwned : search this password hash "https://haveibeenpwned.com/Passwords"
//         !! ordered by hash version !!
// by <manu_bat_manu@yahoo.fr>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha1.h"

#define PASS_HASH_LIST "pwned-passwords-sha1-ordered-by-hash-v4.txt"
#define MAX_PWD_LEN 50
#define HASH_SIZE 20

void get_pwd(char *buf, int n);
int search_hash(unsigned char *sha);
/*******************************/
int main(int argc, char *argv[]){
/*******************************/
char pwd[MAX_PWD_LEN];
char pwd2[MAX_PWD_LEN];
unsigned char sha[HASH_SIZE];
SHA1_CTX ctx;
int i;
    printf("pwned\n");
    printf("-----\n");
    printf("Enter password : ");
    get_pwd(pwd,MAX_PWD_LEN);
    printf("Reenter password : ");
    get_pwd(pwd2,MAX_PWD_LEN);
    if (strcmp(pwd,pwd2)){
        printf("Password didn't match !\n");
        return 1;
    }
    SHA1Init(&ctx);
    SHA1Update(&ctx,pwd,strlen(pwd));
    SHA1Final(sha,&ctx);
    printf("hash : ");
    for (i=0;i<HASH_SIZE;i++){
        printf("%02X",sha[i]&0xFF);
    }
    printf("\n");
    return search_hash(sha);
}

/*******************************/
void get_pwd(char *buf, int n){
/*******************************/
int i,ch;
    i=0;
    while (1){
        ch=_getch();
        switch (ch){
            case 10: case 13:
                *buf=0;
                printf("\n");
                return;
                break;
            case 8:
                if (i<=0) continue;
                buf--;
                i--;
                printf("\b \b");
                break;
            default:
                if (i<n-1){
                    *buf++=ch;
                    i++;
                    printf("*");
                }
                break;
        }
    }
}

/******************************/
int search_hash(unsigned char *sha){
/******************************/
FILE *f;
int64_t sz,bot,top,mid;
#define BUF_SIZE    256
char buf[BUF_SIZE],*s,*aff;
int h,i;
    f=fopen(PASS_HASH_LIST,"rb");
    if (f==NULL){
        printf("File : %s not found !\n",PASS_HASH_LIST);
        return 1;
    }
    fseeki64(f,0,SEEK_END);
    sz=ftelli64(f);

    bot=0;top=sz;
    while (bot<top){
        mid=(bot+top)/2;
        fseeki64(f,mid,SEEK_SET);
        buf[0]=0;
        fread(buf,1,BUF_SIZE,f);
        s=buf;
        while (s<buf+BUF_SIZE-HASH_SIZE && *s!='\r') s++;
        while (s<buf+BUF_SIZE-HASH_SIZE && (*s=='\r' || *s=='\n')) s++;
        for (i=0;i<HASH_SIZE;i++){
    #define HEX(x) (((x)>='0' && (x)<='9') ? (x)-'0' : (x|0x20)-'a'+10)
            h=(HEX(s[0])<<4)|(HEX(s[1]));
            s+=2;
            if (h==sha[i])
                continue;
            if (h<sha[i]){
                bot=mid+(int64_t)(s-buf);
                break;
            }
            if (h>sha[i]){
                top=mid;
                break;
            }
        }
        if (i==HASH_SIZE){
            s+=1;
            aff=s;
            while (s<buf+BUF_SIZE-1 && *s!='\r') s++;
            *s=0;
            printf("Found in password list : %s times",aff);
            return 1;
        }
    }
    fclose(f);
    return 0;
}
