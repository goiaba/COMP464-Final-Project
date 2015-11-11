/***************************************************************************
                
                rsa.cpp  - RSA encryption and decryption 
                  - HTML generated from source by VIM -
                ----------------------------------------
         
    last edited    : Mon Jul 21 10:59:19 IST 2003
    
    authors        : Rajorshi Biswas       <rajorshi@fastmail.fm>
                     Shibdas Bandyopadhyay <shibdas@rediffmail.com>
                     Anirban Banerjee      <anir_iiit@yahoo.co.uk>     
              
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>
#include <sys/time.h>

#ifdef _OPENMP
    #include <omp.h>
#endif

#define BITSTRENGTH  1024               /* size of modulus (n) in bits */
#define PRIMESIZE    (BITSTRENGTH / 2)  /* size of the primes p and q  */


/* Declare global variables */

mpz_t d,e,n;
mpz_t M,c;


/* Declare time-related variables */

struct timeval tv1,tv2;
struct timeval tvdiff;
struct timezone tz;


/* Declare core routines */

void RSA_generateKeys();
int  RSA_checkKeys();
void RSA_decrypt(char* file);


/* Initialization related routines */

void initializeGMP();
void clearGMP();
void initializeRandom();


/* Timing routine */
void timediff(struct timeval*,struct timeval*,struct timeval*);


/* Helper routines */
inline char* process(char*);
void process(char** &decryptedTextArray, int decryptedTextArraySize);
inline void encrypt(char*,FILE*);



/* Main subroutine */
int main(int argc, char* argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Wrong number of arguments. Please provide the file to be decrypted.\n\n");
        exit(1);
    }

    /* Initialize the GMP integers first */
    initializeGMP();

    /*
    *  Check existence of key files : ~/.rsapublic 
    *  and ~/.rsaprivate else generate new keys and file 
    */

    if(!RSA_checkKeys())
    {
        printf("Creating new RSA Key Files...\n\n");
        RSA_generateKeys();
    }

    RSA_decrypt(argv[1]);

    /* Clear the GMP integers */
    clearGMP();

    return 0;
}



void initializeGMP()
{
    /* Initialize all the GMP integers once and for all */

    mpz_init(d);
    mpz_init(e);
    mpz_init(n);

    mpz_init(M);
    mpz_init(c);
}



void clearGMP()
{
    /* Clean up the GMP integers */

    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(n);

    mpz_clear(M);
    mpz_clear(c);
}



void initializeRandom()
{
    /* This initializes the random number generator */

    /* sleep for one second (avoid calls in the same second) */
    sleep(1);

    /* Set seed for rand() by system time() ... */
    unsigned int time_elapsed;
    time((time_t*)&time_elapsed);
    srand(time_elapsed);
}



void timediff(struct timeval* a,struct timeval* b,struct timeval* result)
{
    /* This function calculates and returns the time
    *  difference between two timeval structs
    */

    (result)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;

    if((result)->tv_usec < 0)
    {
        --(result)->tv_sec;
        (result)->tv_usec += 1000000;
    }
}



int RSA_checkKeys()
{
    /* This function checks whether the keys exist 
    *  in the file ~/.rsaprivate and ~/.rsapublic
    */

    char publicFile[100];
    char privateFile[100];

    strcpy(publicFile,getenv("HOME"));
    strcpy(privateFile,getenv("HOME"));

    strcat(publicFile,"/.rsapublic");
    strcat(privateFile,"/.rsaprivate");

    FILE* fpublic  = fopen(publicFile,"r");
    FILE* fprivate = fopen(privateFile,"r");

    if((!fpublic) || (!fprivate))
    {
        /* Key files do not exist */
        return 0;
    }


    printf("\nUsing RSA Key Files : \n");
    printf("\nPublic Key File  : %s",publicFile);
    printf("\nPrivate Key File : %s\n",privateFile);

    char d_str[1000];
    char e_str[100];
    char n_str[1000];


    /* Get keys */
    fscanf(fpublic,"%s\n",e_str);
    fscanf(fpublic,"%s\n",n_str);

    fscanf(fprivate,"%s\n",d_str);

    mpz_set_str(d,d_str,10);
    mpz_set_str(e,e_str,10);
    mpz_set_str(n,n_str,10);

    fclose(fpublic);
    fclose(fprivate);

    return 1;
}



void RSA_generateKeys()
{
    /* This function creates the keys. The basic algorithm is...
    *
    *  1. Generate two large distinct primes p and q randomly
    *  2. Calculate n = pq and x = (p-1)(q-1)
    *  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
    *  4. Calculate the unique d such that ed = 1(mod x)
    *  5. Public key pair : (e,n), Private key pair : (d,n)
    *
    */

    /* initialize random seed */
    initializeRandom();

    /* first, record the start time */
    if(gettimeofday(&tv1,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    /*
    *  Step 1 : Get two large (512 bits) primes.
    */

    mpz_t p,q;

    mpz_init(p);
    mpz_init(q);

    char* p_str = new char[PRIMESIZE+1];
    char* q_str = new char[PRIMESIZE+1];

    p_str[0] = '1';
    q_str[0] = '1';

    for(int i=1;i<PRIMESIZE;i++)
        p_str[i] = (int)(2.0*rand()/(RAND_MAX+1.0)) + 48;

    for(int i=1;i<PRIMESIZE;i++)
        q_str[i] = (int)(2.0*rand()/(RAND_MAX+1.0)) + 48;

    p_str[PRIMESIZE] = '\0';
    q_str[PRIMESIZE] = '\0';

    mpz_set_str(p,p_str,2);
    mpz_set_str(q,q_str,2);

    mpz_nextprime(p,p);
    mpz_nextprime(q,q);

    mpz_get_str(p_str,10,p);
    mpz_get_str(q_str,10,q);

    printf("Random Prime 'p' = %s\n",p_str);
    printf("Random Prime 'q' = %s\n",q_str);

    /*
    *  Step 2 : Calculate n (=pq) ie the 1024 bit modulus
    *  and x (=(p-1)(q-1)).
    */

    char n_str[1000];

    mpz_t x;

    mpz_init(x);


    /* Calculate n... */

    mpz_mul(n,p,q);

    mpz_get_str(n_str,10,n);
    printf("\nn = %s\n",n_str);


    /* Calculate x... */

    mpz_t p_minus_1,q_minus_1;

    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1,p,(unsigned long int)1);
    mpz_sub_ui(q_minus_1,q,(unsigned long int)1);

    mpz_mul(x,p_minus_1,q_minus_1);


    /*
    *  Step 3 : Get small odd integer e such that gcd(e,x) = 1.
    */

    mpz_t gcd;
    mpz_init(gcd);

    /*
    *  Assuming that 'e' will not exceed the range
    *  of a long integer, which is quite a reasonable
    *  assumption.
    */

    unsigned long int e_int = 65537;

    while(true)
    {
        mpz_gcd_ui(gcd,x,e_int);

        if(mpz_cmp_ui(gcd,(unsigned long int)1)==0)
            break;

        /* try the next odd integer... */
        e_int += 2;
    }

    mpz_set_ui(e,e_int);


    /*
    *  Step 4 : Calculate unique d such that ed = 1(mod x)
    */


    char d_str[1000];

    if(mpz_invert(d,e,x)==0)
    {
        printf("\nOOPS : Could not find multiplicative inverse!\n");
        printf("\nTrying again...");
        RSA_generateKeys();

    }

    mpz_get_str(d_str,10,d);

    printf("\n\n");

    /*
    *  Print the public and private key pairs...
    */

    printf("\nPublic Keys (e,n): \n\n");
    printf("\nValue of 'e' : %ld",e_int);
    printf("\nValue of 'n' : %s ",n_str);

    printf("\n\n");

    printf("\nPrivate Key : \n\n");
    printf("\nValue of 'd' : %s",d_str);

    /* get finish time of key generation */
    if(gettimeofday(&tv2,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    timediff(&tv2,&tv1,&tvdiff);

    printf("\nKey Generation took (including I/O) ...\n");
    printf("\n%-15s : %ld","Seconds",tvdiff.tv_sec);
    printf("\n%-15s : %ld","Microseconds",tvdiff.tv_usec);


    /* Write values to file $HOME/.rsapublic and $HOME/.rsaprivate */

    char publicFile[100];
    char privateFile[100];

    strcpy(publicFile,getenv("HOME"));
    strcpy(privateFile,getenv("HOME"));

    strcat(publicFile,"/.rsapublic");
    strcat(privateFile,"/.rsaprivate");

    FILE* fpublic  = fopen(publicFile,"w");
    FILE* fprivate = fopen(privateFile,"w");

    if((!fpublic) || (!fprivate))
    {
        fprintf(stderr,"FATAL: Could not write to RSA Key Files!");
        exit(1);
    }

    /* Write ~/.rsapublic */
    fprintf(fpublic,"%ld\n",e_int);
    fprintf(fpublic,"%s\n",n_str);

    /* Write ~/.rsaprivate */
    fprintf(fprivate,"%s\n",d_str);

    fclose(fpublic);
    fclose(fprivate);

    printf("\nWrote RSA Key Files ...\n");
    printf("\nPublic Key File  : %s",publicFile);
    printf("\nPrivate Key File : %s",privateFile);

    /* clean up the gmp mess */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(x);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(gcd);

}



void populateArray(const char * filename, char ** &ciphertextArray, int &ciphertextArraySize) {
    FILE* fp;

    char ciphertextElement[1000];
    int ciphertextElementLength;

    fp = fopen(filename, "r");

    if(!fp) {
        fprintf(stderr,"FATAL : Could not open %s for reading", filename);
        exit(1);
    }

    while(fscanf(fp, "%s\n", ciphertextElement) > 0) {
        ciphertextElementLength = strlen(ciphertextElement);
        ciphertextArray = (char**) realloc(ciphertextArray, (ciphertextArraySize + 1) * sizeof(char *));
        ciphertextArray[ciphertextArraySize] = (char*) calloc(sizeof(char), ciphertextElementLength + 1);
        strcpy(ciphertextArray[ciphertextArraySize], ciphertextElement);
        ciphertextArraySize++;
    }

    fclose(fp);
}




void freeArray(char ** &array, int &size) {
    for (int index = 0; index < size; index++) {
        free(array[index]);
    }
    free(array);
}




void RSA_decrypt(char* file) {
    /* The RSA decryption routine */

    printf("\nRSA Decryption:\n\n");

    /* Here, (mpz_t) c is the cipher in gmp integer  
    *  and (mpz_t) M is the message in gmp integer */

    char decrypted[1000];    /* decypted text */

    int ciphertextArraySize = 0;
    char ** ciphertextArray = NULL;
    char ** decryptedTextArray = NULL;

    /* Passing ciphertextArray and ciphertextArraySize by reference
     *  to the populateArray function. This code will be invoked by
     *  the main process.
     */
    populateArray(file, ciphertextArray, ciphertextArraySize);

    /* Create a new array with the same size of ciphertextArray to
     *  store the decrypted data. This array will be sliced among the
     *  nodes to be worked in parallel.
     */
    decryptedTextArray = (char **) malloc(ciphertextArraySize * sizeof(char *));

    /* Get time before decryption */
    if(gettimeofday(&tv1,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    #pragma omp parallel for
    for (int index = 0; index < ciphertextArraySize; index++) {
        mpz_set_str(c,ciphertextArray[index],10);

        /* M = c^d(mod n) */
        mpz_powm(M,c,d,n);

        mpz_get_str(decrypted,10,M);
    
        decryptedTextArray[index] = (char*) calloc(sizeof(char), strlen(decrypted) + 1);
        strcpy(decryptedTextArray[index], decrypted);
    }

    /*
     * Dealocate memory that is not used anymore. Now the data is already decrypted and
     *  stored in the decryptedTextArray.
     */
    freeArray(ciphertextArray, ciphertextArraySize);

    process(decryptedTextArray, ciphertextArraySize);

    /*
     * Print decrypted text to the stdout
     */
    for (int index = 0; index < ciphertextArraySize; index++) {
        printf("%s", decryptedTextArray[index]);
    }

    /*
     * Dealocate memory that is not used anymore.
     */
    freeArray(decryptedTextArray, ciphertextArraySize);

    /* Get time after decription */
    if(gettimeofday(&tv2,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    timediff(&tv2,&tv1,&tvdiff);

    printf("\nDecryption took... (including output)\n");
    printf("\n%-15s : %ld","Seconds",tvdiff.tv_sec);
    printf("\n%-15s : %ld\n\n","Microseconds",tvdiff.tv_usec);
}

void process(char** &decryptedTextArray, int decryptedTextArraySize) {
    #pragma omp parallel for
    for (int index = 0; index < decryptedTextArraySize; index++) {
        char* processed = process(decryptedTextArray[index]);
        free(decryptedTextArray[index]);
        decryptedTextArray[index] = (char*) calloc(sizeof(char), strlen(processed) + 1);
        strcpy(decryptedTextArray[index], processed);
    }
}

inline char* process(char* str)
{
    /* This function shows the decrypted integer 
    *  message as an understandable text string 
    */

    unsigned int i=0, j=0;
    int tmpnum;
    char strmod[1000];
    char* output = (char*) calloc(sizeof(char), 1000);

    /* make the message length an integral multiple
    *  of 3 by adding zeroes to the left if required
    */

    if(strlen(str)%3 == 1)
    {
        strcpy(strmod,"00");
        strcat(strmod,str);
    }
    else if(strlen(str)%3 == 2)
    {
        strcpy(strmod,"0");
        strcat(strmod,str);
    }
    else
        strcpy(strmod,str);

    while(i<=strlen(strmod)-3)
    {
        tmpnum = strmod[i] - 48;
        tmpnum = 10*tmpnum + (strmod[i+1] - 48);
        tmpnum = 10*tmpnum + (strmod[i+2] - 48);

        i += 3;

        output[j++] = tmpnum;
    }

    return output;
}

