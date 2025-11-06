int bad_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && *s1 == *s2)
    {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}


/**
 * Per affrontare il problema descritto, è necessario garantire che i caratteri
 * vengano trattati come unsigned char per evitare problemi di estensione del segno
 * quando si confrontano i valori. Questo può essere fatto esplicitamente castando
 * i caratteri a unsigned char nella funzione bad_strcmp.
 *
 * Spiegazione:
 * - Cast a unsigned char: I caratteri *s1 e *s2 vengono castati a unsigned char
 *   sia nel confronto che nella sottrazione. Questo garantisce che il comportamento
 *   sia coerente indipendentemente dal fatto che char sia signed o unsigned sulla piattaforma.
 *   (a differenza di int che è sempre signed, il tipo char può essere signed o unsigned a seconda del compilatore )
 * - Mantiene la logica originale: La logica della funzione rimane invariata, ma ora è
 *   robusta contro problemi di estensione del segno.
 */