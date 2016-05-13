##
## Makefile for pepito in /home/nico/rendu/S02/Pepito/2016_P3p1t0
## 
## Made by Nicolas Loriot
## Login   <loriot_n@epitech.net>
## 
## Started on  Fri May 13 17:42:32 2016 Nicolas Loriot
## Last update Fri May 13 18:37:59 2016 Nicolas Loriot
##

NAME		=	pepito

NAME_SECRET	=	libsecret.so

CC			=	gcc

CFLAGS		+=	-Wall -Wextra

LDFLAGS		=	-L./lib -lsecret -lsupersecret

SRC			=	src/main.c \
				src/utils.c \
				src/daemon.c \
				src/network.c \

OBJS		=	$(SRC:.c=:.o)

$(NAME):	$(OBJS)
			$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

all:		$(NAME)

clean:
			rm -f $(OBJS)

fclean:		clean
			rm -f $(NAME)

secret:		$(CC) -shared -fPIC ./reverse/libsecret.c -o ./reverse/libsecret.so

re:			fclean all

.PHONY:		all clean fclean re
