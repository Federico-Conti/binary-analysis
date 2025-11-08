# Reversing warm-up

The goal of this assignment is to familiarize yourself with dynamic linking, `gdb` and *Ghidra*. The following exercises are (more or less) in order of difficulty; if you're stuck during the lab, don't hesitate to ask for help.

Also, notice that many exercises have an accompanying `.txt` file, with a tongue-in-cheek description that might provide some clues.

The executables are on Aulaweb. Download the ELF examples (`examples-elf-aulaweb.tar.xz`) and `basc-goodware.zip` from Aulaweb.

## ELF

Try to run `hello-world-maybe-broken` and then try to debug it. Why does it run but it seems to be undebuggable?

## `antidebug1` and `antidebug2`

Can you debug, under `gdb`, the "evil" behaviour of `antidebug1` and `antidebug2`? You can find more details and some help/hints on the ELF slides.

## `acrostic.elf`

A very simple exercise (check its `.txt` description!). `objdump` is more than enough to solve it.

## `function1` and `function2`

These are examples that show you that you cannot totally rely on decompilers.
Don't spend too much time on these, we'll discuss them in class. However, it is worthwhile to open them in Ghidra and try to understand what they do. Then, run them and check if your guess is right.

## `math_is_for_fun` and `minions`

These are very simple reversing exercises. The Ghidra decompiler should be quite helpful here.

## `volatility`

This is a bit trickier, but `gdb` should be enough.

## All other challenges (in BASC goodware)

The other challenges require more familiarity with reverse engineering, so unless you have previous knowledge, it's probably better to wait a bit before trying to solve them.
