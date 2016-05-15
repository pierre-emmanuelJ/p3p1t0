/*
** libsecret.c for libsecret in /home/nico/rendu/S02/Pepito/pepito_v2
** 
** Made by Nicolas Loriot
** Login   <loriot_n@epitech.net>
** 
** Started on  Thu May 12 16:02:11 2016 Nicolas Loriot
** Last update Fri May 13 17:37:54 2016 Nicolas Loriot
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

/*
** "F4r3w311_51x_<3" ^ 0x3f
*/

#define SECRET "\x79\x0b\x4d\x0c\x48\x0c\x0e\x0e\x60\x0a\x0e\x47\x60\x03\x0c"

int	handlerMakeSecretRecipes(void *packetPtr, size_t packetSize)
{
  int	i = 0;
  char	xor_key = 0x3f;
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
      while (str[i])
	{
	  str[i] ^= xor_key;
	  if (str[i] == SECRET[i])
	    i++;
	  else
	    break;
	}
      if (i == packetSize)
	{
	  i = 0;
	  while (stock[i].name)
	    stock[i++].quantity -= 5;
	  tab_recipes[Secret_Recipe].quantity += 1;
	  sendLogMessage("Secret Granola was made !!\n");
	}
      else
	sendLogMessage("Bad secret ingredient !!\n");
    }
  return (0);
}
