#
# Makefile for chan_sip3 support
#
all: sip3_refer.o sip3_subscribe.o sip3_network.o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm -rf *.a *.o *.so 
