CC=gcc
OBJS=pcap_test.o
TARGET=pcap_test
LIBS=-lpcap

all : $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(LIBS) -o $(TARGET) $(TARGET).c 

clean :
	rm -f $(TARGET)