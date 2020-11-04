TARGET = netfilter-test
CC = gcc
CFLAGS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): netfilter-test.c
		$(CC) -o $(TARGET) netfilter-test.c $(CFLAGS)

clean:
		rm -f $(TARGET)