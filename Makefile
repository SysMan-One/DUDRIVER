#
#++
#  Abstract: Make file for DUdriver for Linux
#
#  Author: Ruslan R. Laishev
#
#  Creation date: 5-SEP-2018
#
#  Usage : 
#	$ make <Enter>
#
#  Modification history:
#	
#
#--
#

# Comment/uncomment the following line to disable/enable debugging
DEBUG = y`

#ccflags-y += -Xlinker -Map=dudriver.map 
ccflags-y+=-Wframe-larger-than=9720 
#-Wno-error=date-time


# Add your debugging flag (or not) to ccflags-y
ifeq ($(DEBUG),y)
 	DEBFLAGS = -O -g -D_DEBUG # "-O" is needed to expand inlines
else
 	DEBFLAGS = -O2
endif

ccflags-y += $(DEBFLAGS)
ccflags-y += -I..


#
#  Main part of the make script ...
#

ifneq ($(KERNELRELEASE),)
# call from kernel build system

	obj-m	:= dudriver.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

depend .depend dep:
	$(CC) $(ccflags-y) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
	include .depend
endif
