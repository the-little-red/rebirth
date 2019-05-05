CC= gcc
CFLAGS= -g -Wall -Wno-unused-result pkg-config
OBJ= main.o

%.o: %.c

   		$(CC) -c -o $@ $< `pkg-config fuse --cflags` $(CFLAGS)

rebirth: $(OBJ)

			$(CC) -o $@ $^  `pkg-config fuse --libs` $(CFLAGS)

.PHONY: clean

clean:
    		rm *	.o

run:
				./rebirth
