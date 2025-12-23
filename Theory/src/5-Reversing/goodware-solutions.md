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


## bomb 

File: `bomb, bomb.txt, bomb_run_server.sh, pwn_bomb.py`

Questo è un esempio in cui hai a disposizione un eseguibile e uno script che avvia un container Docker sulla tua macchina. Il container esegue un servizio in ascolto su una porta specifica, in questo caso la porta 6000. Questo servizio simula un host remoto che riceve richieste da internet. Tuttavia, in questo caso, possiamo "barare" perché il container Docker gira localmente sulla tua macchina. Puoi aprire una shell all'interno del container e ottenere direttamente la flag. Questo approccio, però, non è particolarmente utile per il nostro scopo.

L'idea è di supporre che non possiamo accedere direttamente alla macchina, se non tramite la porta in ascolto. Questo è il presupposto. Tuttavia, abbiamo l'eseguibile a disposizione. Possiamo eseguirlo localmente per analizzarlo, cercare eventuali bug o capire quale input si aspetta.

Una volta individuato l'input corretto, possiamo inviarlo al servizio remoto per ottenere la flag. Questo è il concetto di base.

Quando esegui l'eseguibile, esso richiede un input. Se inserisci un input errato, il programma "esplode". Devi fornire un input specifico per evitare l'esplosione della "bomba". Questo è, in sostanza, il funzionamento del sistema.

Prima di analizzare gli STEP:

- `__isoc99_scanf(&DAT_0804a0b9,local_58);  --> __isoc99_scanf("%s",user_input); `
- `_code *local_6c [4]; --> char local_6c[5];` (usando retypes in  `void *[5] `)
  - Qui c'è un problema importante: il ciclo va da i = 0 a i < 5, quindi viene eseguito 5 volte, ma l'array local_6c ha solo 4 elementi, indicizzati da 0 a 3

Per  risolvere gli stages:

- #1 l'input corretto deve essere `ThisPhaseIsEasy`
- #2 interpreta i primi 4 byte come int *, quindi legge 4 byte dalla stringa e li interpreta come intero (-0x4523f00d). Quindi devi fornire come input esattamente questi 4 byte  `\xf3\x0f\xdc\xba `: quindi `echo $'ThisPhaseIsEasy\n\xf3\x0f\xdc\xba\n' | ./bomb`

Nota: Adesso per procedere con lo stege 3, dobbiamo inviare l'input al servizio in ascolto sulla porta 6000.

- `./bomb_run_server.sh`
- `nc localhost 6000` 
- `echo -n $'ThisPhaseIsEasy\n\xf3\x0f\xdc\xba\n' | nc localhost 6000`

Usiamo pwntools per automatizzare l'invio dell'input corretto:

- `pwn template basc-goodware/bomb --host 127.0.0.1 --port 6000 > pwn_bomb.p`
- `./pwn_bomb.py LOCAL` or `./pwn_bomb.py` 


- #3 `void step3(int param_1) --> void step3(char* param_1)` and the input must be `86Gp4LSbeM7g757a`
- #4 c'è un quezione da rislvere --- bisogna inviare `1` come input per evitare l'esplosione.
- #5 `strncpy(&local_16,user_input,10);` quidni dobbiamo convertire `char local_16;` in `char s [10];`  e inviare come input `qgxdieogd`

**Differenza logica: LOCAL vs REMOTE**

| Modalità | Cosa fa esattamente | Esempio pratico |
|----------|---------------------|-----------------|
| LOCAL    | Avvia il binario sul tuo PC (ad esempio il file ./bomb dentro WSL). | `p = process("./bomb")` → pwntools esegue il programma nel tuo ambiente locale, puoi attaccare GDB, manipolare file, ecc. |
| REMOTE   | Si connette via rete TCP/IP a un programma che gira altrove (es. dentro un container o su un server remoto). | `p = remote("127.0.0.1", 6000)` → pwntools apre un socket TCP e parla con il processo che ascolta su quella porta. Nota: ovviamente devi sapere il nome dell'eseguibile. |

Posso anche usare GDB per fare il debug del programma in locale. 
Andando a modificare lo script `pwn_bomb.py`:

```sh
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())
```

## acrostic.elf

La soluzione di questa sfida si basa sull'idea dell'acrostico, come suggerito nel testo: bisogna trovare un nome nascosto prendendo la prima lettera di ogni riga del messaggio.

Nel file .txt Ora, prendendo la prima lettera di ogni riga:
ecco l'indirizzo

-  `D i s a S s e M b l e T h e E L F `

```sh
objdump -D acrostic.elf
ù
000000000040100a <a_great_game>:
  40100a:       48 85 c0                test   %rax,%rax
  40100d:       f2 0f 7c c1             haddps %xmm1,%xmm0
  401011:       c8 00 00 00             enter  $0x0,$0x0
  401015:       48 8d 00                lea    (%rax),%rax
  401018:       48 01 c0                add    %rax,%rax
  40101b:       f9                      stc
  40101c:       48 85 c0                test   %rax,%rax
  40101f:       48 09 c0                or     %rax,%rax
  401022:       dc c0                   fadd   %st,%st(0)
  401024:       66 0f 14 c1             unpcklpd %xmm1,%xmm0
  401028:       48 29 c0                sub    %rax,%rax

```
Ecco la flag:  `t h e l a s t o f u s `


## math_is_for_fun 

Obiettivo dell'utente

Trovare due numeri x1, x2 diversi tra loro, tali che:

poly((int)x1) == 0

poly((int)x2) == 0

dove 

poly(x)=x^2−74x+213

Solution

```sh
Gimme two numbers: 3 71
BASC{inTerN3t_iS4pr0n}
```

## minions

Come testare la Flag trovata nell'esecuzione

File: `minions_run_server.sh`

Verifica che il container sia in esecuzione

```sh
nc localhost 6002
Password: BaNaNa!
BASC{d3Sp1c4bLe_M3}
```