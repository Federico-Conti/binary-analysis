# BASC 27/10/2025


## function1

Vediamo ora un esempio pratico.
Abbiamo due eseguibili (*function_one* e simili) che chiedono tre numeri all’utente, eseguono un calcolo e stampano il risultato.

Aprendo *function_one* in Ghidra, vediamo che non ci sono simboli: siamo quindi al punto d’ingresso (*entry*).
Applichiamo il trucco di prima: seguiamo la chiamata a `__libc_start_main` per arrivare a *main*, rinominiamo la funzione, e analizziamo.

Nel codice, troviamo:

* una chiamata a `printf` per stampare istruzioni all’utente,
* una chiamata a `scanf` per leggere tre numeri, che possiamo rinominare come `x1`, `x2`, `x3`,
* un controllo sul numero di valori letti da `scanf`,
* una chiamata a una *misteriosa funzione* con i tre argomenti,
* infine, la stampa del risultato.

Fin qui tutto chiaro: il codice sembra coerente con quanto stampato dall'eseguibile:  prende tre interi e fa solo `a + b - c`. .

---

## function2


Procediamo come funzione1.

Analizzando la funzione 'misteriosa', sembra che non faccia nulla.

l'assembly mostra in realtà che la funzione fa qualcosa, inizializza un paio di registri .

* primo argomento → `move r11, rdi`,
* secondo argomento → `move qr12, rsi`,
* terzo argomento → `move r13, rdx`,

Inoltre dopo la chiamata di un altra funzione 'misteriosa2', il risultato viene messo in **r10** e poi spostato in **rax**.
Quindi questa funzione utilizza una **calling convention personalizzata**:

Entrando nella funzione 'misteriosa2', vediamo che fa il calcolo:

```sh
ADD R12, R12
MOV R11, R12
ADD RAX, R13
ADD R13, R13
ADD R11, R13
MOV R11, RAX
ADD R10, R11
```

Il programma usa registri non inizializzati secondo la convenzione standard, quindi Ghidra non capisce la logica.
La convenzione ABI per Linux a 64 bit prevede che i primi sei argomenti siano passati nei registri **rdi**, **rsi**, **rdx**, **rcx**, **r8** e **r9**, e il valore di ritorno in **rax**.


Aggiornando la firma della funzione in Ghidra  (specificando i registri corretti per argomenti e valore di ritorno utilizzando 'Edit function'), il decompilatore mostra finalmente il comportamento reale:

```c
return a + 2*b + 3*c;
```

---

Questo esempio dimostra che non ci si può fidare ciecamente del decompilatore.
In presenza di convenzioni di chiamata personalizzate o codice volutamente offuscato, il decompilatore può fallire completamente.

## restricted_area_v2

There is no input that would make the program print the flag. However, there are two possible approaches:

1. **Using GDB**: Set the return register `eax` to a value other than `0` after the function call.
2. **Patching the binary**: Modify the binary to force the execution flow to print the flag.
    1. Right-click on the assembly code of the `return 0` instruction.
    2. Select "Patch Instruction" and change the instruction from `mov eax, 0` to `mov eax, 1`.
