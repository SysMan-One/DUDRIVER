# DUDRIVER
LDD is supposed to be placed on top of targed block device driver - to performs transparent interception of the data.

## Description
This project is study case to get basic knowoledge in programming of Linex kernel modules, block device drivers and so on stuff.

Main idea of this drive is a implement a stackable driver by replacing of make_request_fn () for a target block device.to intercept 
and processing WRITE requests, and bio_endio() to process READ request.
Also there is a small piece of code to demonstrate a external control function is implemented by IOCTL do "du$ctl" pseudo-device.
