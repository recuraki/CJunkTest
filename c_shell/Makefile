#MEM_MGMT_DISP=
MEM_MGMT_DISP=-DMEM_MGMT_DISP

CC	= gcc
CFLAGS	= -static -O0 -g -Wall -DMEM_MGMT $(MEM_MGMT_DISP) -I/usr/local/include -L/usr/local/lib

LD	= gcc
LDFLAGS	= -static -O0 -g -Wall -I/usr/local/include -L/usr/local/lib
LDFLAGS2=

SRCS	= $(lib_SRCS) $(shell_test_SRCS) $(remote_SRCS)
lib_SRCS = mem_mgmt.c \
	  llist_queue.c \
	  llist_queue_int.c \
	  backdoor.c \
	  backdoor_lq.c
shell_test_SRCS = main.c
remote_SRCS = remote_sh.c

OBJS = $(lib_OBJS) $(shell_test_OBJS) $(remote_OBJS)
lib_OBJS	= $(lib_SRCS:.c=.o)
shell_test_OBJS	= $(shell_test_SRCS:.c=.o)
remote_OBJS	= $(remote_SRCS:.c=.o)

PACKAGE	= shell_test remote

RM	= rm -f

.SUFFIXES: .o .c

all: $(PACKAGE)

$(PACKAGE): $(OBJS)
	$(LD) $(LDFLAGS) $(lib_OBJS) $($@_OBJS) -o $@ $(LDFLAGS2)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(PACKAGE) *.core tags $(OBJS)

tag: ctags etags
ctags:
	ctags -R *.c *.h
etags:
	etags -R *.c *.h
