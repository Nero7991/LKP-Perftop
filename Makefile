## [M1: point 1]
#  Set MODULE = ex3
#  ...
MODULE = perftop

## [M2: point 1]
#  Add MODULE.o (ex3.o) to obj-m. Basically defines all the c source files for the module 
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Set KERNELDIR if not already set to /lib/modules/$(shell uname -r)/build where $(shell uname -r) evalues to kernel version
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Set PWD to current working directory
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Used to tell make what to build when make all is used. In this case, its just ex3 
#  ...
all: $(MODULE)


## [M6: point 1]
#  This evaluates to something like this: gcc -std=c99 -W -Wall ex3.c -c
#  It invokes the complier to create object files and create executable
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  build the module (make ex3). M=$(PWD) specifies that an external module is being built and specifies the absolute path
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Clean the modules (make clean). Remove all the generated files in the module
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
