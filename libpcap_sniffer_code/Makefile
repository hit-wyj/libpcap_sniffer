lsniffer:lsniffer.o init.o proc.o
	gcc -o $@ $^
.c.o:
	gcc -c $<
clean:
	rm -fr *.o lsniffer
