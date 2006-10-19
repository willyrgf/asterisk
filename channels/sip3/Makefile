#
# Makefile for chan_sip3 support
#
all: sip3_refer.o sip3_subscribe.o sip3_network.o sip3_domain.o sip3_callerid.o sip3_auth.o \
	sip3_sdprtp.o sip3_config.o

%.o: %.c sip3_funcs.h sip3.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm -rf *.a *.o *.so 
