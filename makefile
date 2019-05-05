CC= gcc
CFLAGS= -g -Wall -Wno-unused-result pkg-config
OBJ= main.o

%.o: %.c

   		$(CC) -c -o $@ $< pkg-config $(CFLAGS)

rebirth: $(OBJ)

			$(CC) -o $@ $^^$(CFLAGS)

.PHONY: clean

clean:
    		rm *	.o

run:
				./rebirth
