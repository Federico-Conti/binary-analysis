Creare variabile


wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-4.1-99687-gd9b8f822c-gcc-linux.tar.gz
tar -xvzf pin-external-4.1-99687-gd9b8f822c-gcc-linux.tar.gz
export PIN_ROOT=/percorso/assoluto/pin-4.1-99687-gd9b8f822c-gcc-linux
$PIN_ROOT/pin -t ./obj-intel64/count_instr.so -- /bin/ls
nano ~/.bashrc             # o usa vi/vim, gedit, ecc.


Inserire in fondo al file la riga seguente:
export PIN_ROOT="/home/conti/binary-analysis/Theory/src/9-Instrumentation/pin-external-4.1-99687-gd9b8f822c-gcc-linux"