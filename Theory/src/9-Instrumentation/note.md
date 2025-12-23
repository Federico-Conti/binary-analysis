**Cos’è `ptrace` (o B-Trace)?**

* È un'interfaccia di sistema che permette a un processo (tracer, es. debugger) di:

  * Osservare e controllare un altro processo (tracee).
  * Leggere/scrivere la memoria del tracee.
  * Ricevere notifiche sui segnali ricevuti dal tracee.
* Tutti i debugger Unix si basano (sono un wrapper) su `ptrace` (es. GDB, `strace`, `ltrace`).
* È una sola funzione con molte modalità diverse a seconda dell’argomento passato (una API considerata "brutta" dal professore perché poco chiara e non ben progettata).

---

**Permessi e sicurezza (`ptrace_scope`)**

* Il kernel Linux controlla chi può "attaccare" (attach) un processo con `ptrace`.
* Parametro `/proc/sys/kernel/yama/ptrace_scope` definisce il livello di restrizione:

  * `0`: puoi fare debug di qualsiasi processo del tuo utente (poco sicuro).
  * `1` (default su Ubuntu): puoi fare debug **solo dei tuoi figli** (child processes).
  * Altri valori vietano `ptrace` o lo limitano a root.
* Se vuoi attaccare un processo esterno al tuo programma, devi usare `sudo` o modificare `ptrace_scope`.

---

**Meccanismo di debug (attach, segnali, freeze, ecc.)**

* Un debugger solitamente **fa `fork()`** e il figlio esegue `ptrace(PTRACE_TRACEME)` per farsi debuggare.
* Il figlio poi si ferma con `raise(SIGSTOP)` o `execve()` (che genera `SIGTRAP`).
* Quando il processo riceve un segnale, si **blocca** (frozen), e il debugger viene notificato e può decidere cosa fare (es. continuare, modificare memoria, ecc.).
* GDB mostra e gestisce i segnali (vedi `info handle` in GDB):

  * Alcuni segnali non vengono mai consegnati al processo (es. `SIGTRAP`, `SIGINT`) perché servono per il debugger.
  * Questo comportamento può essere usato per **rilevare la presenza di un debugger** (anti-debugging).

---

**Uso pratico di `ptrace`**

* Comandi principali:

  * `PTRACE_ATTACH`: attacca un processo.
  * `PTRACE_PEEKDATA`: legge una parola dalla memoria del processo.
  * `PTRACE_CONT`: continua l'esecuzione del processo.
  * `PTRACE_SINGLESTEP`: esegue una singola istruzione.
* Quando usi `PEEKDATA`, il valore restituito è ambiguo (es. `-1` può essere un dato valido), quindi devi controllare `errno`.

---

* Tutto ciò serve come base per parlare di **strumentazione dinamica**, cioè modificare il comportamento di un programma durante l'esecuzione, argomento legato a strumenti come **Frida**.

## Instrumentation 

Per instrumentation si intende l’inserimento di nuovo codice in un programma o in un processo allo scopo di osservarne o modificarne il comportamento. Naturalmente, se si ha il codice sorgente è piuttosto facile: si aggiungono manualmente delle stampe, oppure si usa il compilatore. Per esempio, quando utilizziamo i vari sanitizer, istruiamo il compilatore a generare codice aggiuntivo per controllare se la memoria è usata correttamente e così via. Ma la parte davvero interessante riguarda l’instrumentazione del binario.

Tre scenari diversi. 

1. **sostituzione di codice esistente**. In un certo senso, questo può essere visto anche come una rimozione: se sostituisci qualcosa, stai di fatto togliendo il codice originale. Non lo rimuovi davvero, ma l’effetto è lo stesso. E questo lo avete già fatto: quando avete trovato i cheat per Doppler, avete esattamente fatto questo. Avete cambiato del codice, sostituito alcune istruzioni, e basta. Questo va bene finché avete spazio sufficiente per inserire le nuove istruzioni e finché i byte che sostituite non sono target di un salto.
   - Interessante è la tecnica E9-patch
2. **inserire o rimuovere codice nel mezzo**, aggiungendo poi nuovo codice da qualche altra parte purché due condizioni siano vere:
   - il nuovo codice deve entrare nello spazio occupato dalle istruzioni che state sovrascrivendo;
   - i target dei salti devono essere preservati.
3. **aggiungere nuovo codice**. Trovare code caves o holes nelle sezioni di codice (spazi allocati ma non utilizzati) dove inserire nuovo codice, oppure aggiungere nuove sezioni o caricare nuove librerie (es. `LD_PRELOAD` su Linux). Il vero problema è hijackare il control flow: il nuovo codice non viene eseguito automaticamente, quindi devi redirigere l'esecuzione verso il tuo codice (logging, analisi, ecc.) e poi tornare al codice originale. Tecniche comuni: modificare l'entry point, gli initializer, oppure le voci della GOT (Global Offset Table su Linux) o IAT (Import Address Table su Windows).

**Instrumentazione statica**

- Modifica il binario una volta per tutte
- Più veloce in esecuzione
- Limitazioni significative:
    - Non supporta codice generato dinamicamente
    - Non permette di attaccarsi e staccarsi da un processo
    - Non funziona con codice cifrato, compresso o scaricato a runtime
- In pratica, raramente utilizzata

**Instrumentazione dinamica**

- Avviene a runtime
- Supera i limiti della statica
- Permette flessibilità nella modifica del comportamento durante l'esecuzione

### Dynamic Binary Instrumentation

Ci sono due approcci principali all’instrumentazione dinamica di binari:

1. Process patching
2. Dynamic translation

**Process patching**
Frida, un toolkit open source di dynamic binary instrumentation che gira su Windows, Linux, Android, iOS, ecc.

Frida inietta un agente (una libreria condivisa) nel processo target. Il processo di iniezione funziona così:

1. **Attach con ptrace**: Frida si attacca al processo target usando `ptrace`, lo ferma e ottiene il controllo.

2. **Allocazione memoria remota**: Frida alloca memoria nel processo remoto usando `mmap` senza dipendere da libc:
    - Modifica l'instruction pointer per forzare una chiamata a `mmap`
    - Intercetta il ritorno (tramite un crash controllato)
    - Legge il valore di ritorno in RAX (indirizzo della memoria allocata)

3. **Bootstrapper**: Scrive un piccolo programma (bootstrapper) nello spazio allocato ed esegue:
    - Crea un nuovo thread nel processo target
    - Apre una socket per la comunicazione
    - Carica la libreria dell'agente con `dlopen`
    - Avvia l'agente Frida

4. **Ripristino**: Frida ripristina lo stato originale del processo (registri) e si stacca.


Frida non è "stealth": un programma può rilevare l'iniezione controllando:

- Il numero di thread
- Se è in esecuzione sotto `ptrace`
- Nuove librerie caricate in memoria

Per questo motivo, Frida spesso non funziona con videogiochi e software con protezioni anti-debugging.


Frida intercetta le chiamate a funzioni tramite la tecnica del **function hooking**:

1. **Sostituzione entry point**: I primi byte della funzione target `g` vengono sostituiti con un salto verso un trampolino.
s
2. **Trampolino**: Un piccolo pezzo di codice che:
    - Salva i registri
    - Chiama il codice dell'utente (JavaScript/Python)
    - Ripristina i registri
    - Esegue le istruzioni originali di `g` (rilocate nel trampolino)
    - Salta al resto della funzione

La tecnica funziona finché i primi byte della funzione non sono target di salti. Normalmente non è un problema perché il prologo di una funzione non è solitamente destinazione di jump.

Questo approccio permette di eseguire codice arbitrario prima dell'esecuzione di qualsiasi funzione target.

**Gestione della memoria in Frida**

* JavaScript non può rappresentare interi a 64 bit senza perdita di precisione, quindi Frida introduce `NativePointer`.
* Creazione di un `NativePointer`:
    * `ptr(numero)` o, preferibilmente, `ptr("0x1234567890abcdef")` (stringa).
* I `NativePointer` sono immutabili: per modificarli occorre crearne uno nuovo.
* Distinzione fondamentale:
    * `toInt()`: converte il **valore del puntatore** stesso a intero.
    * `readInt()`: **dereferenzia** il puntatore e legge l'intero puntato (dalla memoria).

**download Frida**
* Sito ufficiale: https://frida.re/
* Installazione con pip:

* ```sh
  pip install frida-tools
  ```


**frida-examples/hello-frida.py**

- `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
- start target process `./hello-frida`

**frida-examples/spawn-hello.py**


`./spawn-hello.py`


Frida spawns the target process and injects the agent automatically
* Live reload the agent (automatic reload on file change):
  `frida -n hello-frida -l agent.js`  

Speed optimization example:
  `frida -n hello-frida -l speedup.js`
  

Call functions from the target via RPC from script and REPL:
  `frida -q -n hello-frida -l call-f.js`


**PIN (Program Instrumentation)**

PIN è più complesso, più articolato. Quindi, se Frida è sufficiente per quello che vi serve, allora Frida è la scelta giusta. Tuttavia, con PIN si può fare di più, ed è per questo che abbiamo discusso entrambi.

Con Frida ci si può agganciare a una funzione (pre-function), quindi si può eseguire il proprio codice prima o dopo la funzione, si può sostituire la funzione, e questo è molto semplice da fare con Frida. Tuttavia, se per esempio si vuole, non so, rimuovere le istruzioni add, non si può fare con Frida, a meno di fare manualmente molte cose che PIN invece fa automaticamente.

PIN è una sorta di compilatore JIT, just-in-time compile

Quando “lanci” un programma con PIN, in realtà stai eseguendo PIN e gli passi:

* il PIN tool (plugin di analisi/strumentazione),
* il programma target (o un PID per attach).

Tre componenti nello stesso spazio di indirizzamento:

  1. PIN (runtime + infrastruttura),
  2. applicazione target,
  3. PIN tool (codice dell’utente).

* Flusso generale:
  * PIN avvia il tool, e il tool registra le callback di instrumentazione.
  * PIN inizia l’esecuzione dell’applicazione, ma il codice viene gestito “a richiesta”.

* Traduzione per trace (tipo basic block esteso):
  * All’inizio, il codice non è ancora strumentato perché non è mai stato visto.
  * PIN individua una trace (un Basic Block): una sequenza di istruzioni con controllo di flusso “lineare” (senza jmp in uscita interni).
  * Traduzione: PIN chiama il tool per chiedere se si vuole instrumentare la trace.

* Instrumentazione durante la traduzione:
  * Se l’instrumentazione è 'per-istruzione', per ogni istruzione PIN chiede al tool se:
    * inserire analisi prima o dopo l’istruzione,
    * oppure sostituire l’istruzione.

* PIN crea quindi un nuovo pezzo di codice in cui il codice originale è mescolato con le chiamate alle funzioni di analisi
* Prima e dopo queste chiamate, PIN inserisce automaticamente il codice per salvare e ripristinare i registri. In questo modo, nelle funzioni di analisi non ci si deve preoccupare di salvare e ripristinare lo stato del processo:


* Il codice tradotto viene memorizzato nelle **code cache** di PIN, e l’esecuzione continua lì.
* Quando si incontra una nuova trace (quindi qunado è presente un salto), il processo si ripete.

PIN gestisce tre livelli di argomenti, separati da opzioni speciali:

`pin [pin-opts ] -t tool [tool-args ] -- app [app-args ]`

- **Argomenti di PIN**: tutto ciò che viene **prima di `-t`**.
- Esempi tipici: opzioni di logging, modalità di esecuzione, attach/spawn, ecc.
- **Tool**: subito **dopo `-t`** c’è il **nome del tool**, cioè la libreria caricata da PIN (es. `.so` su Linux, `.dll` su Windows).
- **Argomenti dell’applicazione target**: tutto ciò che viene **dopo `--`** (nome del programma + suoi argomenti).

Gli argomenti dedicati al tool si chiamano **knob**: vengono scritti sulla command line insieme agli altri argomenti e PIN li inoltra automaticamente al tool. Nel codice del tool si dichiarano knob (stringhe, booleani, interi, ecc.) e PIN li inizializza automaticamente in base ai valori passati da riga di comando.

Esempio:

1. contare istruzioni (versione semplice, ma lenta)
  
- n_instr è globale
- count_instr() incrementa di 1
- per ogni istruzione inserisci una call BEFORE

- Instrumentation: trace(...) inserisce la chiamata
- Analysis: count_instr() viene chiamata ogni volta che l’istruzione gira

```c++

UINT64 n_instr = 0;

void count_instr() { ++n_instr; }

void trace(INS instruction, void *v) {
  INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)count_instr, IARG_END);
}
```

2. PIN_FAST_ANALYSIS_CALL: ridurre overhead

Chiamare una funzione per ogni istruzione costa molto. PIN fornisce un meccanismo per ridurre questo overhead:
- Definisci la funzione di analisi con la macro `PIN_FAST_ANALYSIS_CALL`.
- Devi passare `IARG_FAST_ANALYSIS_CALL` nella INS_InsertCall 
  
```c++
void PIN_FAST_ANALYSIS_CALL count_instr() { ++n_instr; }

INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)count_instr,
              IARG_FAST_ANALYSIS_CALL, IARG_END);
```

3. Versione più veloce: contare per Basic Block (BBL)

Invece di fare +1 per ogni istruzione, fai:

- una call per ogni BBL
- aggiungi BBL_NumIns(bbl) (numero istruzioni nel blocco)

```c++
void PIN_FAST_ANALYSIS_CALL count_instr(UINT32 numInstInBbl) {
  n_instr += numInstInBbl;
}

void trace(TRACE trace, void *v) {
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)count_instr,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_UINT32, BBL_NumIns(bbl),
                   IARG_END);
  }
}
```