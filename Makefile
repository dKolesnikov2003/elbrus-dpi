.PHONY: all core cli gui clean

all: core cli gui

core:
	$(MAKE) -C core

cli:
	$(MAKE) -C cli

gui:
	$(MAKE) -C gui

clean:
	$(MAKE) -C core clean
	$(MAKE) -C cli clean
	$(MAKE) -C gui clean