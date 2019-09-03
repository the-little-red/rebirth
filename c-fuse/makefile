CC= gcc
CFLAGS= -g -Wall -Wno-unused-result -D_FILE_OFFSET_BITS=64
OBJ= main.o

%.o: %.c

	$(CC) -c -o $@ $< $(CFLAGS) 

rebirth: $(OBJ)

	$(CC) -o $@ $^ `pkg-config fuse --cflags --libs`

.PHONY: clean

clean:
	rm *.o

run:
	./rebirth
