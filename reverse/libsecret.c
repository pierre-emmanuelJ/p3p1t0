/*
** libsecret.c for libsecret in /home/nico/rendu/S02/Pepito/pepito_v2
** 
** Made by Nicolas Loriot
** Login   <loriot_n@epitech.net>
** 
** Started on  Thu May 12 16:02:11 2016 Nicolas Loriot
** Last update Fri May 13 14:36:49 2016 Nicolas Loriot
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pepito.h"
#include "network.h"
#include "daemon.h"
#include "utils.c"
#include "recipes.h"
#include "secret.h"

extern t_stock		stock[7];
extern t_recipes	tab_recipes[6];

int	handlerMakeSecretRecipes(void *packetPtr, size_t packetSize)
{
  int	i = 0;
  char	xor_key;
  char	*password;
  char	msg[256];
  char	*str;

  password = getStr(&packetPtr, &packetSize);
  if (checkPassword(password) == ADMIN)
    {
      str = getStr(&packetPtr, &packetSize);
      while (stock[i].quantity)
	{
	  if (stock[i].quantity <= 4)
	    {
	      snprintf(msg, sizeof(msg), "Need more %s\n", stock[i].name);
	      sendLogMessage(msg);
	      return (-1);
	    }
	  i++;
	}
      i = 0;
      if (str[i] == 0x42)
	{
	  while (str[i])
	    {
	    }
	}
      else

    }
  return (0);
}
