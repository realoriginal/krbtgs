#
# Used to create object files that are
# compatible with Beacon's inline-execute
# command.
#

CC_x64 := x86_64-w64-mingw32-gcc
LD_x64 := x86_64-w64-mingw32-ld
STRx64 := x86_64-w64-mingw32-strip
OUTx64 := KrbTgsBof.x64.o

CC_x86 := i686-w64-mingw32-gcc
LD_x86 := i686-w64-mingw32-ld
STRx86 := i686-w64-mingw32-strip
OUTx86 := KrbTgsBof.x86.o

SOURCE := $(wildcard ./*.c)
OBJECT := $(SOURCE:%.c=%.o)
CFLAGS := -Os -s -Qn -nostdlib 
LFLAGS := -Wl,-s,--exclude-all-symbols,--no-leading-underscore

all: $(OBJECT)
	$(LD_x64) -x -r *.x64.o -o $(OUTx64)
	$(LD_x86) -x -r *.x86.o -o $(OUTx86)

.c.o:
	$(CC_x64) -o $(basename $@).x64.o -c $< $(CFLAGS) $(LFLAGS)
	$(STRx64) -N $(basename $(notdir $@)).c $(basename $@).x64.o
	$(CC_x86) -o $(basename $@).x86.o -c $< $(CFLAGS) $(LFLAGS)
	$(STRx86) -N $(basename $(notdir $@)).c $(basename $@).x86.o

clean:
	rm -rf *.o
	rm -rf $(OUTx64) $(OUTx86)
