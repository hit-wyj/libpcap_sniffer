BIN = lsniffer
CC  = gcc
INC  = -I. -I./kernel/ -I./base/
CFLAGS  = -g -Wall
OBJECTS = $(wildcard ./kernel/*.c)

$(BIN): $(OBJECTS)
    $(CC) $(CFLAGS) $(OBJECTS) -o $@ $(INC)
clean:
    rm -fr ./*.o $(BIN)
