#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd;
    char buffer[1024];

    if (access("file", W_OK) != 0)
        exit(EXIT_FAILURE);

    // ATTACK: symlink("/etc/passwd","file");

    fd = open("file", O_WRONLY);
    write(fd, buffer, sizeof(buffer));
    close(fd);

    return 0;
}

/*

access() from MAN: "The check is done using the calling process's real UID and GID,
rather than the effective IDs as is done when actually attempting
an operation (e.g., open(2)) on the file"


- access("file", W_OK): controlla se il file "file" è scrivibile, ma usa il Real UID (RUID).
- open("file", O_WRONLY): apre il file in scrittura, ma usa l’Effective UID (EUID).
- write(...): scrive nel file, se è stato aperto con successo.


TOCTOU è una vulnerabilità causata da una finestra di tempo tra:

- Check (access) → Verifica se il file è scrivibile per l'utente reale.
- Use (open) → Apre il file e scrive.

Durante quella finestra, un attaccante può:

1. Creare un symlink (es. file -> /etc/passwd);
2. Aspettare che access() controlli il file (controllo OK, perché file è normale);
3. Cambiare rapidamente il link simbolico;
4. Quando open() viene chiamato, il programma scrive in un file privilegiato (/etc/passwd) con EUID = root.

*/





/*

In Linux/Unix, ogni processo ha questi identificativi utente:

| Sigla    | Nome              | Significato                                                       |
| -------- | ----------------- | ----------------------------------------------------------------- |
| **RUID** | Real User ID      | L’utente che ha eseguito il programma.                            |
| **EUID** | Effective User ID | L’ID usato per determinare i **permessi effettivi** del processo. |
| **SUID** | Saved User ID     | Una copia dell’EUID originale, per poterlo ripristinare.          |


Un programma SUID root, quando viene eseguito, ha:

- RUID = UID dell’utente normale (es. 1000)
- EUID = 0 (root), grazie al SUID
- SUID = 0, copia salvata dell’EUID

Linux permette al processo di commutare tra EUID e RUID/SUID:

- Può "abbassare" i privilegi → seteuid(RUID)
- Può "riprendere" i privilegi → seteuid(SUID) (se era root all'inizio)

*/