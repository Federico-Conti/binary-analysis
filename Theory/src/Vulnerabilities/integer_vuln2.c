#include <stdio.h>

int main()
{
    int i, j;

    if (scanf("%d %d", &i, &j) != 2)
    { /* ... */
        return 1;
    } /*...*/
    if (i < 0 || j < 0) 
    {
        printf("i and j must be non-negative!\n");
        return 1;
    }
    int k = i + j;

    if (k >= 100)
    {
        printf("i and j are too big!\n");
        return 1;
    }
    printf("%d is in the interval [0, 99]\n", k);
    /* (***) use k; e.g. to index an array of 100 elements */

    return 0;
}

/*
 * Prima Condizione di Vulnerabilità:
 * Supponiamo che int sia a 32 bit (tipico su molte piattaforme), il range è:
 *
 * int: da −2,147,483,648 a 2,147,483,647
 *
 * Se inserisci un numero maggiore di 2,147,483,647, ad esempio:
 *
 * 2147483648 1
 * Il primo valore (2147483648) eccede il massimo valore rappresentabile da int,
 * quindi viene interpretato come −2,147,483,648 (overflow), e la condizione i < 0 sarà vera.
 */


/* * Seconda Condizione di Vulnerabilità:
 * Consideriamo l'input:
 *
 * 2147483647 1
 * In questo caso, la somma i + j sarà 2147483648, che causa un overflow e
 * viene interpretata come −2,147,483,648. La condizione k >= 100 sarà vera.
 */