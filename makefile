OBJS	= main.o
SOURCE	= main.c
HEADER	= netstructs.h
OUT	= catears
CC	 = gcc
FLAGS	 = -g -c
LFLAGS	 = -l pcap

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

main.o: main.c
	$(CC) $(FLAGS) main.c 


clean:
	rm -f $(OBJS) $(OUT)
