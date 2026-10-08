CFLAGS = -O0 -g -Wall -Wextra -Wno-unused-parameter

probe: probe.c pe-loader.c
	$(CC) $(CFLAGS) -o $@ probe.c

.PHONY: clean
clean:
	$(RM) probe
