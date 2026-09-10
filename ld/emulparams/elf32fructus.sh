SCRIPT_NAME=elf
TEMPLATE_NAME=elf
OUTPUT_FORMAT="elf32-fructus"
ARCH=fructus
MAXPAGESIZE=4
EMBEDDED=yes

# A default only.  A Fructus board says where its ROM and RAM are, and the
# memory map that matters lives in a linker script beside the program - see
# ld/fructus-rom16k.ld in the fructus repository.  0xc000 is where a 16K ROM
# at the top of the address space begins.
TEXT_START_ADDR=0xc000
