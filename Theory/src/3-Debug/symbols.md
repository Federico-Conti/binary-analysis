# Simboli e informazioni di debug
### Comprendere i simboli

Ho già menzionato i **simboli**, cioè semplicemente metadati che permettono di mappare nomi a indirizzi di memoria. Per esempio, invece di dire che il puntatore di istruzione è all'indirizzo `123AACD`, si può dire che è alla funzione `printf` o `fubar` o qualunque altra. Ovviamente questo è utile per noi esseri umani.

### Informazioni di debug vs simboli

A volte si possono avere solo i simboli. Questi non costituiscono le informazioni di debug complete. Le informazioni di debug complete sono più di questo: sono metadati che permettono di mettere in corrispondenza il codice macchina con le corrispondenti costanti a livello di sorgente. Per esempio, il debugger può riconoscere che una particolare istruzione macchina corrisponde a un `if` a livello C e viceversa.

### Simboli nei programmi rilasciati

I programmi rilasciati tipicamente non includono le informazioni di debug né i simboli, ma si basano di norma sulle librerie standard. Per esempio, i simboli per le librerie standard sono quasi sempre presenti, perché — come abbiamo detto — il linking ora è di default dinamico. Questo significa che quando esegui un eseguibile il sistema deve collegare dinamicamente le librerie necessarie. Di conseguenza negli eseguibili il compilatore deve includere il nome delle librerie e il nome delle funzioni usate da quelle librerie. Quei nomi devono quindi essere presenti, altrimenti il linker dinamico fallirebbe all'avvio del processo.

Quindi di solito è possibile trovare i nomi delle funzioni esterne usate da un programma. Dico “di solito” perché esistono trucchi che permettono a un programma di trovare dinamicamente le funzioni di cui ha bisogno. Alcuni programmi protetti o offuscati, come certi campioni di malware, possono non avere questi simboli per cercare di nascondere ciò che fanno. Vi mostrerò più avanti nel corso un eseguibile senza nessuna dipendenza esterna che funziona e fa cose; usa dei trucchi per trovare le altre parti a runtime.

### Distribuzione dei simboli in Linux

In Linux, almeno su Ubuntu, i simboli C sono distribuiti separatamente perché gli utenti normali non hanno bisogno dei simboli delle librerie: questi servono se vuoi fare il debug di una libreria standard, ma gli utenti normali non debuggano le librerie di sistema. Potrebbe quindi essere necessario installarli se vuoi dare un'occhiata dentro la libreria standard. Questo di solito non è necessario perché possiamo assumere che le librerie standard funzionino come previsto. Quando l'esecuzione entra nella libreria standard puoi tipicamente lasciare che il programma continui e aspettare che esca dal codice della libreria standard e ritorni al suo stato normale. Alcune tecniche avanzate di exploitation possono richiedere di fare il debug della libreria standard, ma non le studieremo in questo corso.

# Formati di file e standard

Vi mostro alcuni esempi e anche dei nomi. Il formato di file eseguibile in Unix in generale si chiama **ELF**, che sta per *Executable and Linkable Format*. È un acronimo, naturalmente. E per nessuna ragione se non perché chi l'ha progettato è nerd, le informazioni di debug usano un formato chiamato **DWARF**. Questo non è un acronimo, ma sapete — elfi e nani e dungeon & dragons e così via — ecco perché il formato delle informazioni di debug si chiama DWARF.
