#include <stdio.h>
int main(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; ++i)
        printf(argv[i]);
    printf("\n");
}

/*
printf non sa quanti argomenti gli vengono passati: si fida della format string. 
Se la stringa contiene 2 specifier (%s %d) ma gli argomenti sono 0, 
printf prenderà qualunque cosa ci sia sullo stack e cercherà di interpretarla come argomento.

./a.out "%x %x %x %x"
Quindi printf cercherà 4 argomenti sullo stack. Ma non ce ne sono! Prende dati casuali dalla pila, 
li interpreta come numeri esadecimali e li stampa. Così possiamo leggere valori arbitrari dallo stack.
*/