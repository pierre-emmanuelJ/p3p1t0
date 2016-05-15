##
## Makefile for  in
##
## Made by Jean PLANCHER
## Login   <planch_j@epitech.net>
##
## Started on  Thu Apr 28 06:00:21 2016 Jean PLANCHER
## Last update Tue May 10 17:01:09 2016 Jean PLANCHER
##

CC	= gcc

RM	= rm -f

CFLAGS	+= -I../sources/includes
LDFLAGS	= -L../sources/lib -lsecret -lsupersecret -Wl,-rpath,../sources/lib

NAME	= pepito

FOLDER	= ../sources/src/

SRCS	= $(addprefix $(FOLDER), \
	  main.c \
	  daemon.c \
	  network.c \
	  utils.c)

OBJS	= $(SRCS:.c=.o)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

all: $(NAME)

clean:
	$(RM) $(OBJS)

fclean:	clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
