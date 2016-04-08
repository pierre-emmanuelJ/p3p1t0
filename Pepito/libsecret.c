/*
** secret.c for source in /home/salwan_j/ESL/projects/pepito/2012/source
** 
** Made by jonathan salwan
** Login   <salwan_j@epitech.net>
** 
** Started on  Wed Mar 14 17:54:00 2012 jonathan salwan
** Last update Tue Mar 20 19:48:21 2012 Loïc Michaux
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "pepito.h"
#include "network.h"
#include "daemon.h"
#include "utils.h"
#include "recipes.h"
#include "secret.h"

/* "Boomer's tits" ^ 0xf3 */
# define SECRET "\xb1\x9c\x9c\x9e\x96\x81\xd4\x80\xd3\x87\x9a\x87\x80"

extern t_stock    stock[7];
extern t_recipes  tab_recipes[6];

int
handlerMakeSecretRecipes(void *packetPtr, size_t packetSize)
{
  int			i = 0;
  char			key = 0xf3;
  char			msg[256];
  char			*str;
  char			*password = NULL;

  password = getStr(&packetPtr, &packetSize);
  if (checkPassword(password) == ADMIN) {
    str = getStr(&packetPtr, &packetSize);
    while (stock[i].name) {
      if (stock[i].quantity < 5) {
	snprintf(msg, sizeof(msg), "Need more %s\n", stock[i].name);
	sendLogMessage(msg);
	return -1;
      }
      i++;
    }
    i = 0;
    while (str[i])
      str[i++] ^= key;
    if (!strcmp(str, SECRET)) {
      i = 0;
      while (stock[i].name) {
	stock[i].quantity -= 5;
	i++;
      }
      tab_recipes[Secret_Recipe].quantity += 1;
      sendLogMessage("Secret Granola was made !!\n");
    }
    else
      sendLogMessage("Bad secret ingredient !!\n");
  }
  return 0;
}
