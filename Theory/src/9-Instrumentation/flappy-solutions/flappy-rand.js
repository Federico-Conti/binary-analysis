'use strict';

// 1) individua il simbolo globale rand() (libc)
const randPtr = Module.getGlobalExportByName('rand'); // objdump -t ./flappy | grep rand
console.log('[+] rand() trovato a ' + randPtr);

// 2) il nostro nuovo rand():
//
//    • restituisce sempre 0  → nel sorgente di Flappy:
//         RANDOM_PIPE_HEIGHT = (rand() % range) + 60
//      quindi tutte le colonne nasceranno alla quota minima (60 px),
//      rendendo il gioco facilissimo.
const cheatRand = new NativeCallback(function () {
    return 0;                 // valore compreso fra 0 e RAND_MAX
}, 'int', []);

// 3) sostituisci l’implementazione originale
Interceptor.replace(randPtr, cheatRand);

console.log('[+] rand() rimpiazzato con cheatRand');
