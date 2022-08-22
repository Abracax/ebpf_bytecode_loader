CC=gcc
CFLAGS=-g -Wall
LIBS=-lelf
OBJS=main.o filter_gen.o
OBJ=filter_extractor

all: $(OBJS) 
	gcc $(CFLAGS) -o $(OBJ) $(OBJS) $(LIBS) 
clean:
	rm $(OBJS) $(OBJ)

