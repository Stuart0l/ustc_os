#
# Students' Makefile for the Malloc Lab
#
VERSION = 1

CC = gcc
CFLAGS = -ggdb -Wall -O2 -m32

OBJS_IM = mdriver.o mm_implicit.o memlib.o fsecs.o fcyc.o clock.o ftimer.o
OBJS_EX = mdriver.o mm_explicit.o memlib.o fsecs.o fcyc.o clock.o ftimer.o

mdriver_im: $(OBJS_IM)
	$(CC) $(CFLAGS) -o mdriver_im $(OBJS_IM)

mdriver_ex: $(OBJS_EX)
	$(CC) $(CFLAGS) -o mdriver_ex $(OBJS_EX)

mdriver.o: mdriver.c fsecs.h fcyc.h clock.h memlib.h config.h mm.h
memlib.o: memlib.c memlib.h
mm_implicit.o: mm_implicit.c mm.h memlib.h
mm_explicit.o: mm_explicit.c mm.h memlib.h
fsecs.o: fsecs.c fsecs.h config.h
fcyc.o: fcyc.c fcyc.h
ftimer.o: ftimer.c ftimer.h config.h
clock.o: clock.c clock.h


clean:
	rm -f *~ *.o mdriver_*


