CFLAGS = -O0 -g -Wall -Wextra -Wno-unused-parameter
ENGINE = ../../libfprint/drivers/elan_oem

probe: probe.c $(ENGINE)/elan_oem_engine.c $(ENGINE)/elan_oem_engine.h $(ENGINE)/pe-loader.c
	$(CC) $(CFLAGS) -I$(ENGINE) -o $@ probe.c $(ENGINE)/elan_oem_engine.c

.PHONY: clean
clean:
	$(RM) probe
