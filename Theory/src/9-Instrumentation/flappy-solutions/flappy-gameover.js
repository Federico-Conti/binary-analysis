'use strict';

// 1) Individua il simbolo `game_over` con i debug-symbol e calcola addr assoluto.
const sym = DebugSymbol.fromName('game_over');  // objdump -t ./flappy | grep over

if (!sym) {
    throw new Error('[-] Impossibile trovare game_over()');
}

if (sym.moduleName !== 'flappy') {
    throw new Error(`[-] game_over si trova in ${sym.moduleName}, non in flappy`);
}

console.log(`[+] game_over() trovato a ${sym.address}`);

/*
 * 2) Crea una NativeCallback “vuota”.
 *    Tipo di ritorno: void   |   Argomenti: none
 *    La nostra funzione non fa assolutamente nulla → il tuo uccellino è immortale.
 */

const noop = new NativeCallback(function () {
    // intentionally empty
}, 'void', []);

/*
 * 3) Rimpiazza l’implementazione originale.
 */
Interceptor.replace(sym.address, noop);

console.log('[+] game_over() è stato neutralizzato. Buon volo!');
