CFLAGS = -O0 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function

probe: probe.c pe-loader.c
	$(CC) $(CFLAGS) -o $@ probe.c

.PHONY: clean
clean:
	$(RM) probe
