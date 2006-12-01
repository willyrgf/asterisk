#
# Makefile for chan_sip3 support
#
all: sip3_refer.o sip3_subscribe.o sip3_network.o sip3_domain.o sip3_callerid.o sip3_auth.o \
	sip3_sdprtp.o sip3_config.o sip3_cliami.o sip3_dialog.o sip3_services.o \
	sip3_compose.o sip3_parse.o sip3_utils.o sip3_pokedevice.o sip3_monitor.o

%.o: %.c sip3funcs.h sip3.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm -rf *.a *.o *.so 
