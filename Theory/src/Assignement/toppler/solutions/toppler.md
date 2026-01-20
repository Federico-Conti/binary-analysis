# Toppler

## Infinite lives

```sh
main -> startgame -> men_main -> men_options -> men_game_options_menu -> game_options_menu_lives
```

In this function, which is used to set the maximum number of lives (3) in the game options,

the global variable is often used:

```config.i_start_lives```

Using Find References, we can see that this variable is used in:

we find that it is used by the function `pts_reset` to reset the number of lives with:

```c++
lifes = config.i_start_lives;
```

We then search for references to the variable `lifes` and see that it is used
in a function that decrements the lives when you die:

```c++
void pts_died(void)

{
  lifes = lifes + -1;
  return;
}
```

### Patching with Ghidra

The instruction is located at address ```0x08056417``` and occupies 7 bytes.

Using Ghidra's Patching Instruction:

```c++
SUB dword ptr [0x0806919c],0x1
--> 
SUB dword ptr [0x0806919c],0x0
```

### Patching with pwntools   

```python
elf = ELF('toppler_basc/toppler32')
elf.write(0x0805641d, b'\x00')
elf.save('toppler_basc/toppler32_infinitelife')
```


### in 64-bit

We know that the current number of lives is stored at address `0x42b8f0` (see hints README). 

To locate the relevant code:

1. Use the "Search Program Text" feature (Ctrl+F) in Ghidra's "Listing" tab to search for references to the variable `DAT_0042b8f0`.
2. Look for patterns involving the decrement instruction `SUB`.

From this search, we identify the function to patch at address `0x00414005`.

```sh
SUB EAX, 0x1
MOV dword ptr [DAT_0042b8f0],EAX
```

In python:

```python
elf = ELF('toppler_basc/toppler64')
elf.write(0x00414007, b'\x00')  
elf.save('toppler_basc/toppler64_infinitelife')
```

## Playing without robot collisions

Since it's compiled with debug symbols, one advantage is that we can easily 
search for functions with names like:

- robot_update()
- robot_collision()
- ...

Specifically:

- The function rob_topplercollision() checks collisions between an object (the "toppler") and a list of other objects (object[]) present in the game.
- Returns -1 if there is no collision.

Using cross-referencing, we see that this function is called in `top_testcollision()`:
which handles when the character should fall, based on collisions, state and position.

### Patching with Ghidra

The objective is to patch every `CALL topple()` instruction in `top_testcollision()` 

```c++
 CALL  topple --> CALL  walking                                          
```

### Patching with pwntools 

```python
# walking function address
walking_fun = 0x0041d0bc

# list of CALL sites to be modified in top_testcollision()
call_sites = [
    0x0805cb4c,
    0x0805cb6b,
    0x0805cc48,
    0x0805cc21,
    0x0805cc2b,
]

elf = ELF(orig_elf)

for symbol, addr in elf.symbols.items():
    if addr == walking_fun:
        print(f"Check walking function in {hex(walking_fun)}: {symbol}")
        break
else:
    print(f"No symbol found at {hex(walking_fun)}")

print("\nDisassembly walking function:")
print(disasm(elf.read(walking_fun, 21)))


# Patching CALL toppler() instruction in top_testcollision() to point to walking() 
for call_site in call_sites:
    # offset: target - (source + 5)
    offset = walking_fun - (call_site + 5)
    
    elf.write(call_site, b'\xE8' + p32(offset,signed=True))
    
    print(f"\nPatched CALL at {hex(call_site)}:")
    print(f"New offset: {hex(offset)}")
    print(disasm(elf.read(call_site, 5)))


elf.save(out_elf)
```

### in 64-bit

We know that the function topple() has state=7.

To locate the relevant code:

1. Use the "Search Program Text" feature (Ctrl+F) in Ghidra's "Listing" tab to search for references to the `0x7`.
2. Look for patterns involving the mov instruction `MOV`.

From this search, we identify the function topple() at address `0x0805be37`.
and rename the function to `topple` and map the symbol `state`.

```sh
  MOV dword ptr [DAT_0046cd40 ],0x7
```

Search for references to the function `topple()`.

- It is called by the function at address `0041e119`, which is `top_testcollision()`.
- Retrieve the virtual addresses of the calls to `topple()`.

```python
call_sites = [
    0x0041e2bf,
    0x0041e248
    0x0041e25b
    0x041e1b2
    0x0041e1c3
]
```

Now, to find the address of the `walking()` function, since we have mapped the symbol of the variable `state`:

- Use "Search Program Text" in Ghidra to look for `[state],0x0`. 
- We find the `walking()` function at `0x0041d0bc`.

```python
walking_fun = 0x0041d0bc
```