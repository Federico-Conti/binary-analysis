/*********************************************************************
 * flappy_auto.so – fa “volare” l’uccellino da solo                 *
 * g++ -std=c++17 -O3 -fPIC -shared flappy_auto.cpp \                *
 *     -I$PIN_ROOT/Source/include/pin -I$PIN_ROOT/Source/include/pin/gen \
 *     -o obj-intel64/flappy_auto.so -ldl -Wl,-Bsymbolic             *
 *********************************************************************/
#include "pin.H"
#include <cmath>
#include <iostream>

#define PIPE_W  86
#define GAP     220
#define PLYR_X  80
#define PLYR_SZ 60
#define MAX_STEP 7.0f   // spostamento massimo per frame: evita “teletrasporti”

// ➊ Indirizzi globali calcolati a runtime
static ADDRINT base        = 0;
static ADDRINT addr_player = 0;
static ADDRINT addr_pipe_x = 0;
static ADDRINT addr_pipe_y = 0;

// ➋ Calcola indirizzi quando Pin carica l’eseguibile principale (PIE-friendly)
VOID ImageLoad(IMG img, VOID *)
{
    if (!IMG_IsMainExecutable(img)) return;

    base        = IMG_LowAddress(img);
    addr_player = base + 0x204060;
    addr_pipe_x = base + 0x204080;
    addr_pipe_y = base + 0x204090;

    std::cerr << "[+] player_y @ " << std::hex << addr_player << std::endl;
}

// ➌ Routine chiamata *prima* di qualunque istruzione che scriva memory
VOID PIN_FAST_ANALYSIS_CALL AutoPilot(ADDRINT ea)
{
    if (ea != addr_player) return;                 // non è la variabile che ci interessa

    int   *px = reinterpret_cast<int* >(addr_pipe_x);
    float *py = reinterpret_cast<float*>(addr_pipe_y);
    float *y  = reinterpret_cast<float*>(ea);

    /* Scegli il tubo più vicino davanti al giocatore */
    int i = (px[0] + PIPE_W < PLYR_X) ? 1 : 0;

    float safeY   = py[i] + GAP/2.0f - PLYR_SZ/2.0f;
    float delta   = safeY - *y;
    float adjust  = std::fabs(delta) > MAX_STEP ? (delta > 0 ? MAX_STEP : -MAX_STEP)
                                                : delta;

    *y += adjust;      // “piccolo tocco” verso il centro del gap
}

// ➍ Inserisci AutoPilot su **ogni istruzione** che scrive in memoria
VOID Instrument(INS ins, VOID *)
{
    if (!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE,
                   (AFUNPTR)AutoPilot,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_MEMORYWRITE_EA,
                   IARG_END);
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return 1;

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instrument, 0);
    PIN_StartProgram();    // mai torna

    return 0;
}
