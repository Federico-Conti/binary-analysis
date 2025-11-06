#include <stdio.h>
#include <stdlib.h>

int *array_copy(int *array, int len) {
    if (array == 0 || len < 0) return 0;
    int *copy, i;
    copy = malloc(len * sizeof(int));
    if (copy == 0)
        return 0;
    for (i = 0; i < len; i++)
        copy[i] = array[i];
    return copy;
}

int main() {
    int array[] = {1, 2, 3, 4, 5};
    int len = sizeof(array) / sizeof(array[0]);

    int *copy = array_copy(array, len);
    if (copy == 0) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    printf("Original array: ");
    for (int i = 0; i < len; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");

    printf("Copied array: ");
    for (int i = 0; i < len; i++) {
        printf("%d ", copy[i]);
    }
    printf("\n");

    free(copy);
    return 0;
}




/*
 * ❌ Non si può davvero verificare se il puntatore array sia valido
 *
 * In C, un puntatore può puntare a qualunque indirizzo. Controllare solo
 * array == 0 (cioè NULL) non basta. Il puntatore potrebbe essere:
 * 
 * - Non NULL, ma non valido (non punta a memoria allocata o accessibile);
 * - Puntare a un’area più piccola di len * sizeof(int).
 *
 * Se accade questo, il ciclo for accede a memoria non valida, causando
 * undefined behavior (ad esempio, segmentation fault o peggio).
 *
 * ⚠️ Possibile overflow aritmetico nel calcolo len * sizeof(int)
 *
 * Se len è molto grande, la moltiplicazione len * sizeof(int) può oltrepassare
 * il massimo valore rappresentabile da size_t, causando un overflow.
 *
 * Esempio:
 * - Supponiamo sizeof(int) = 4 e len = 2^30 + 1.
 * - Allora: len * sizeof(int) = (2^30 + 1) * 4 = 2^32 + 4.
 * - Su sistemi a 32 bit, 2^32 vale 0 (per overflow), quindi la richiesta diventa
 *   malloc(4), cioè alloca solo 4 byte, spazio per un singolo int!
 *
 * Successivamente, il ciclo for copia len elementi, scrivendo milioni di valori
 * oltre i limiti, causando corruzione di memoria (buffer overflow).
 *
 * Questo è uno dei bug più gravi, verificatosi in codice reale con conseguenze
 * di sicurezza importanti (exploit, vulnerabilità, ecc.).
 */