CC= gcc
CFLAGS= -g -Wall -Wno-unused-result pkg-config  `pkg-config fuse --cflags`
LFLAGS= `pkg-config fuse --libs`
OBJ= main.o

%.o: %.c

   		$(CC) -c -o $@ $< $(CFLAGS) $(LFLAGS)

rebirth: $(OBJ)

			$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

.PHONY: clean

clean:
    		rm *	.o

run:
				./rebirth
