diff --git a/Makefile b/Makefile
new file mode 100644
index 0000000..c922b69
--- /dev/null
+++ b/Makefile
@@ -0,0 +1,43 @@
+##
+## Makefile for pepito in /home/nico/rendu/S02/Pepito/2016_P3p1t0
+## 
+## Made by Nicolas Loriot
+## Login   <loriot_n@epitech.net>
+## 
+## Started on  Fri May 13 17:42:32 2016 Nicolas Loriot
+## Last update Fri May 13 18:37:59 2016 Nicolas Loriot
+##
+
+NAME		=	pepito
+
+NAME_SECRET	=	libsecret.so
+
+CC			=	gcc
+
+CFLAGS		+=	-Wall -Wextra
+
+LDFLAGS		=	-L./lib -lsecret -lsupersecret
+
+SRC			=	src/main.c \
+				src/utils.c \
+				src/daemon.c \
+				src/network.c \
+
+OBJS		=	$(SRC:.c=:.o)
+
+$(NAME):	$(OBJS)
+			$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)
+
+all:		$(NAME)
+
+clean:
+			rm -f $(OBJS)
+
+fclean:		clean
+			rm -f $(NAME)
+
+secret:		$(CC) -shared -fPIC ./reverse/libsecret.c -o ./reverse/libsecret.so
+
+re:			fclean all
+
+.PHONY:		all clean fclean re
diff --git a/Pepito/Makefile b/Pepito/Makefile
deleted file mode 100644
index 13da877..0000000
--- a/Pepito/Makefile
+++ /dev/null
@@ -1,24 +0,0 @@
-NAME		=	pepito
-CC		=	gcc
-
-CFLAGS		+=	-Wextra -Wall -ggdb
-LDFLAGS		= 	-L. -lsecret
-
-SRCS		=	main.c daemon.c network.c utils.c
-
-OBJS		=	${SRCS:.c=.o}
-
-${NAME}:	${OBJS}
-		${CC} ${OBJS} -o ${NAME} ${LDFLAGS}
-
-all:		${NAME}
-
-clean:
-		rm -f ${OBJS}
-
-fclean:		clean
-		rm -f ${NAME}
-
-re:		fclean all
-
-.PHONY:		all clean fclean re
diff --git a/Pepito/Patchnote.txt b/Pepito/Patchnote.txt
deleted file mode 100644
index 47be864..0000000
--- a/Pepito/Patchnote.txt
+++ /dev/null
@@ -1,11 +0,0 @@
-Patch du 22/03/2012
---------------------------------------------
-Corrections
-
-- Bug sur l'handle des recettes
-- Erreur dans le mot de passe XORé ...
-- "Use after free" non-exploitable supprimé
-
-Ajouts de contenu
-
-- Client interactif avec description des commandes
diff --git a/Pepito/daemon.c b/Pepito/daemon.c
deleted file mode 100644
index 6c001fe..0000000
--- a/Pepito/daemon.c
+++ /dev/null
@@ -1,127 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#include <signal.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <strings.h>
-#include <unistd.h>
-
-#include <sys/stat.h>
-
-#include "pepito.h"
-
-#include "daemon.h"
-#include "network.h"
-
-/* Main daemon functions ---------------------------------------- */
-
-/* sig */
-
-void
-sigHandler(int sig)
-{
-  switch (sig) {
-  case SIGINT:
-    fprintf(stderr, "Process received SIGINT.\n" \
-	    "Exiting\n");
-    break;
-  case SIGTERM:
-    fprintf(stderr, "Process received SIGTERM.\n" \
-	    "Exiting\n");
-    break;
-  }
-  remove("pepito.pid");
-  exit(EXIT_SUCCESS);
-}
-
-/* run */
-
-int
-checkOtherProcess(void)
-{
-  struct stat		buf;
-
-  if (stat("pepito.pid", &buf) == 0) {
-    fprintf(stderr, "Daemon is already running.\n"	  \
-	    "If it's not, please check 'pepito.pid'.\n"	  \
-	    "Exiting\n");
-    return -1;
-  }
-  return 0;
-}
-
-int
-savePid(void)
-{
-  FILE*			pidFile;
-  pid_t			pid;
-
-  if (!(pidFile = fopen("pepito.pid", "w"))) {
-    fprintf(stderr, "Cannot save process id.\n" \
-	    "Exiting\n");
-    return -1;
-  }
-  pid = getpid();
-  fprintf(pidFile, "%i", pid);
-  fclose(pidFile);
-  return 0;
-}
-
-int
-runDaemon(int debug)
-{
-  char			packetPtr[PACKETLEN];
-  size_t	       	packetSize;
-  struct sockaddr_in	sa;
-
-  if (checkOtherProcess())
-    return (EXIT_FAILURE);
-  signal(SIGTERM, sigHandler);
-  signal(SIGINT, sigHandler);
-  signal(SIGUSR1, sigHandler);
-
-  if (!debug) {
-    daemon(1, 1);
-    if (savePid())
-      return EXIT_FAILURE;
-  }
-
-  fprintf(stderr, "Daemon started\n");
-
-  initConnection(&sa);
-  while (1) {
-    setClient(acceptClient(&sa));
-    bzero(packetPtr, PACKETLEN);
-    getPacket(packetPtr, &packetSize);
-    handlePacket(packetPtr, packetSize);
-    setClient(-1);
-  }
-  setSock(-1);
-  return EXIT_SUCCESS;
-}
-
-/* stop */
-
-int
-stopDaemon(void)
-{
-  int			pid;
-  FILE*			pidFile;
-
-  if ((pidFile = fopen("pepito.pid", "r")) == NULL)
-    return EXIT_SUCCESS;
-  fscanf(pidFile, "%i", &pid);
-  kill(pid, SIGUSR1);
-  fprintf(stderr, "Stopping daemon (%i)\n", pid);
-  remove("pepito.pid");
-  return EXIT_SUCCESS;
-}
diff --git a/Pepito/daemon.h b/Pepito/daemon.h
deleted file mode 100644
index 2cf3d64..0000000
--- a/Pepito/daemon.h
+++ /dev/null
@@ -1,25 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#ifndef		__DAEMON_H__
-# define	__DAEMON_H__
-
-#define NORMAL 0
-#define DEBUG  1
-
-int			runDaemon(int debug);
-int			stopDaemon(void);
-
-int			savePid(void);
-int			checkOtherProcess(void);
-void			sigHandler(int sig);
-
-#endif	    /* !__DAEMON_H__ */
diff --git a/Pepito/lib_freebsd/libsecret.so b/Pepito/lib_freebsd/libsecret.so
deleted file mode 100644
index 86ab90d..0000000
Binary files a/Pepito/lib_freebsd/libsecret.so and /dev/null differ
diff --git a/Pepito/lib_linux/libsecret.so b/Pepito/lib_linux/libsecret.so
deleted file mode 100755
index ee493a1..0000000
Binary files a/Pepito/lib_linux/libsecret.so and /dev/null differ
diff --git a/Pepito/libsecret.c b/Pepito/libsecret.c
deleted file mode 100644
index c665bdb..0000000
--- a/Pepito/libsecret.c
+++ /dev/null
@@ -1,65 +0,0 @@
-/*
-** secret.c for source in /home/salwan_j/ESL/projects/pepito/2012/source
-** 
-** Made by jonathan salwan
-** Login   <salwan_j@epitech.net>
-** 
-** Started on  Wed Mar 14 17:54:00 2012 jonathan salwan
-** Last update Tue Mar 20 19:48:21 2012 Loïc Michaux
-*/
-
-#include <stdio.h>
-#include <stdlib.h>
-#include <unistd.h>
-#include <string.h>
-
-#include "pepito.h"
-#include "network.h"
-#include "daemon.h"
-#include "utils.h"
-#include "recipes.h"
-#include "secret.h"
-
-/* "Boomer's tits" ^ 0xf3 */
-# define SECRET "\xb1\x9c\x9c\x9e\x96\x81\xd4\x80\xd3\x87\x9a\x87\x80"
-
-extern t_stock    stock[7];
-extern t_recipes  tab_recipes[6];
-
-int
-handlerMakeSecretRecipes(void *packetPtr, size_t packetSize)
-{
-  int			i = 0;
-  char			key = 0xf3;
-  char			msg[256];
-  char			*str;
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  if (checkPassword(password) == ADMIN) {
-    str = getStr(&packetPtr, &packetSize);
-    while (stock[i].name) {
-      if (stock[i].quantity < 5) {
-	snprintf(msg, sizeof(msg), "Need more %s\n", stock[i].name);
-	sendLogMessage(msg);
-	return -1;
-      }
-      i++;
-    }
-    i = 0;
-    while (str[i])
-      str[i++] ^= key;
-    if (!strcmp(str, SECRET)) {
-      i = 0;
-      while (stock[i].name) {
-	stock[i].quantity -= 5;
-	i++;
-      }
-      tab_recipes[Secret_Recipe].quantity += 1;
-      sendLogMessage("Secret Granola was made !!\n");
-    }
-    else
-      sendLogMessage("Bad secret ingredient !!\n");
-  }
-  return 0;
-}
diff --git a/Pepito/libsecret.so b/Pepito/libsecret.so
deleted file mode 100755
index ee493a1..0000000
Binary files a/Pepito/libsecret.so and /dev/null differ
diff --git a/Pepito/main.c b/Pepito/main.c
deleted file mode 100644
index c0d7f1b..0000000
--- a/Pepito/main.c
+++ /dev/null
@@ -1,373 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk and Djo wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy us some belgian
-** beers in return.
-*/
-
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
-#include <unistd.h>
-
-#include "pepito.h"
-#include "network.h"
-#include "daemon.h"
-#include "utils.h"
-#include "recipes.h"
-#include "secret.h"
-
-static char		adminPassword[512] = "\x25\x20\x21\x34\x3c\x3b\x38\x3a\x3b\x05\x05\x16"; /* putainmonPPC */
-static char		userPassword[512] = "jt3d1l4t3";
-static char    		xorKey = 0x55;
-static int    		money = 11110;
-
-t_recipes               tab_recipes[] =
-{
-  {"Granola with some MDMA", 0},
-  {"Granola with some Whisky", 0},
-  {"Granola with some Cum", 0},
-  {"Granola with some LSD", 0},
-  {"Secret Granola", 0},
-  {NULL, 0}
-};
-
-t_stock                 stock[] =
-{
-  {"MDMA",       10},
-  {"Whisky",     10},
-  {"Cum",        10},
-  {"LSD",        10},
-  {"Chocolate",  10},
-  {"Flour",      10},
-  {NULL,         0}
-};
-
-/* --- checkPassword() ---------------------------------------------- */
-
-int
-checkPassword(char *password)
-{
-  char			savePassword[64] = {0};
-  char			*logMessage;
-  int			isUser = 0;
-  int			isAdmin = 0;
-  int			i;
-
-  if (!strcmp(password, userPassword))
-    isUser = 1;
-  strcpy(savePassword, password);
-
-  for (i = 0; password[i]; ++i)
-    password[i] ^= xorKey;
-  if (!strcmp(password, adminPassword))
-    isAdmin = 1;
-
-  if (!(isAdmin | isUser)) {
-    logMessage = malloc(sizeof(*logMessage) * (strlen(password) + 21));
-    memset(logMessage, 0, strlen(password) + 21);
-    strcat(logMessage, "Invalid password : ");
-    strcat(logMessage, savePassword);
-    strcat(logMessage, "\n");
-    sendLogMessage(logMessage);
-    free(logMessage);
-  }
-  return isAdmin ? ADMIN : isUser ? USER : NOBODY;
-}
-
-/* --- change*Password() -------------------------------------------- */
-
-static void
-changeUserPassword(char *password)
-{
-  if (password) {
-    strcpy(userPassword, password);
-    sendLogMessage(PASSWD_CHANGE);
-  }
-}
-
-static void
-changeAdminPassword(char *password)
-{
-  int			i;
-
-  if (password) {
-    for (i = 0; password[i]; ++i)
-      password[i] ^= xorKey;
-    strcpy(adminPassword, password);
-    sendLogMessage(PASSWD_CHANGE);
-  }
-}
-
-/* --- Packet handlers ---------------------------------------------- */
-
-static int
-handlerChangePassword(void *packetPtr, size_t packetSize)
-{
-  int			identity = NOBODY;
-  char			*newPassword;
-  char			*oldPassword;
-
-  oldPassword = getStr(&packetPtr, &packetSize);
-  newPassword = getStr(&packetPtr, &packetSize);
-  if ((identity = checkPassword(oldPassword)) == ADMIN)
-    changeAdminPassword(newPassword);
-  else if (identity == USER)
-    changeUserPassword(newPassword);
-  if (newPassword)
-    free(newPassword);
-  if (oldPassword)
-    free(oldPassword);
-  return 0;
-}
-
-/* --- Display all Recipes ------------------------------------------ */
-
-static int
-handlerDisplayRecipes(void *packetPtr, size_t packetSize)
-{
-  int			i;
-  int			user = NOBODY;
-  char			msg[256] = {0};
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  user = checkPassword(password);
-  if (user == USER || user == ADMIN) {
-    sendLogMessage("Lists of Recipes\n================\n");
-    for (i = 0; tab_recipes[i].name; ++i) {
-      snprintf(msg, sizeof(msg), "[%d] - %s\n", i, tab_recipes[i].name);
-      sendLogMessage(msg);
-    }
-  }
-  free(password);
-  return 0;
-}
-
-/* --- Display Stock of Granola Corp --------------------------------- */
-
-static int
-handlerDisplayStock(void *packetPtr, size_t packetSize)
-{
-  int			i;
-  int			user = NOBODY;
-  char			msg[256] = {0};
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  if ((user = checkPassword(password)) == USER || user == ADMIN) {
-    snprintf(msg, sizeof(msg), "Money : %d\n", money);
-    sendLogMessage(msg);
-    sendLogMessage("\nIngredient stock\n================\n");
-    for (i = 0; stock[i].name; ++i) {
-      snprintf(msg, sizeof(msg), "[%d] - %s\n", stock[i].quantity, stock[i].name);
-      sendLogMessage(msg);
-    }
-    sendLogMessage("\nFor sale\n========\n");
-    for (i = 0; tab_recipes[i].name; ++i) {
-      if (tab_recipes[i].quantity) {
-	snprintf(msg, sizeof(msg), "%d x %s\n", tab_recipes[i].quantity, tab_recipes[i].name);
-	sendLogMessage(msg);
-      }
-    }
-  }
-  free(password);
-  return 0;
-}
-
-/* --- Make Recipes -------------------------------------------------- */
-
-static int
-_checkIngredient(unsigned int id)
-{
-  if (id > sizeof(stock) / sizeof(t_stock))
-    return -1;
-  return 0;
-}
-
-static char *
-_checkStock(int id)
-{
-  if (stock[CHOCOLATE].quantity - 1 < 0)
-    return "Need more Chocolate";
-  if (stock[FLOUR].quantity - 1 < 0)
-    return "Need more Flour";
-  if (id == MDMA && stock[MDMA].quantity - 1 < 0)
-    return "Need more MDMA";
-  if (id == WHISKY && stock[WHISKY].quantity - 1 < 0)
-    return "Need more WHISKY";
-  if (id == CUM && stock[CUM].quantity - 1 < 0)
-    return "Need more CUM";
-  if (id == LSD && stock[LSD].quantity - 1 < 0)
-    return "Need more LSD";
-  return NULL;
-}
-
-static void
-_useIngredient(int MagicIngredient)
-{
-  stock[CHOCOLATE].quantity		-= 1;
-  stock[FLOUR].quantity			-= 1;
-  stock[MagicIngredient].quantity	-= 1;
-  tab_recipes[MagicIngredient].quantity += 1;
-}
-
-static int
-handlerMakeRecipes(void *packetPtr, size_t packetSize)
-{
-  int			id = 0;
-  char			*recipe;
-  char			*log;
-  char			msg[256];
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  if (checkPassword(password) == ADMIN) {
-    recipe = getStr(&packetPtr, &packetSize);
-    if ((log = _checkStock(id))) {
-      sendLogMessage(log);
-      return -1;
-    }
-    fprintf(stderr, "Recipe : '%s'\n", recipe);
-    for (id = 0; tab_recipes[id].name != NULL
-	   && strcmp(tab_recipes[id].name, recipe); ++id);
-    if (tab_recipes[id].name == NULL) {
-      sendLogMessage(UNKNOWN_RECIPE);
-      return -1;
-    }
-
-    if (_checkIngredient(id)) {
-      sendLogMessage(UNKNOWN_INGREDIENT);
-      return -1;
-    }
-    _useIngredient(id);
-    snprintf(msg, sizeof(msg), "%s was made\n", tab_recipes[id].name);
-    sendLogMessage(msg);
-    free(recipe);
-  }
-  free(password);
-  return 0;
-}
-
-/* --- Sale Granola ----------------------------------------------- */
-
-static int
-handlerSaleGranola(void *packetPtr, size_t packetSize)
-{
-  char			*recipe;
-  int			user = NOBODY;
-  int			id;
-  char			msg[256];
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  if ((user = checkPassword(password)) == USER || user == ADMIN) {
-    recipe = getStr(&packetPtr, &packetSize);
-    for (id = 0; tab_recipes[id].name != NULL
-	   && strcmp(tab_recipes[id].name, recipe); ++id) ;
-    if (tab_recipes[id].name == NULL) {
-      sendLogMessage(UNKNOWN_RECIPE);
-      return -1;
-    }
-    if (tab_recipes[id].quantity > 0) {
-      tab_recipes[id].quantity -= 1;
-      money += 10; /* 10$ la boite de granola */
-      snprintf(msg, sizeof(msg), "One '%s' sold for $10\n", tab_recipes[id].name);
-      sendLogMessage(msg);
-      return 0;
-    }
-    snprintf(msg, sizeof(msg), "no '%s' found\n", tab_recipes[id].name);
-    sendLogMessage(msg);
-    free(recipe);
-  }
-  free(password);
-  return -1;
-}
-
-static int
-handlerBuyIngredient(void *packetPtr, size_t packetSize)
-{
-  int			i;
-  char			*ingredientName;
-  int			amount;
-  char			log[128];
-  char			*password = NULL;
-
-  password = getStr(&packetPtr, &packetSize);
-  if (checkPassword(password) == ADMIN) {
-    ingredientName = getStr(&packetPtr, &packetSize);
-    amount = getNumber(&packetPtr, &packetSize);
-
-    if ((money - 2 * amount) < 0) {
-      sendLogMessage("Need more money !!\n");
-      return -1;
-    }
-
-    for (i = 0; stock[i].name != NULL; ++i) {
-      if (!strcmp(ingredientName, stock[i].name)) {
-	money -= 2 * amount;
-	stock[i].quantity += amount;
-	sendLogMessage(INGREDIENT_BOUGHT);
-	sprintf(log, "echo \"%s was bought\" >> log", ingredientName);
-	free(ingredientName);
-	system(log);
-	return amount;
-      }
-    }
-
-    sendLogMessage(UNKNOWN_INGREDIENT);
-  }
-  return -1;
-}
-
-/* --- Handler function -------------------------------------------- */
-
-static int		(*handlerTab[])(void *packetPtr, size_t packetSize) =
-{
-  handlerChangePassword,
-  handlerDisplayRecipes,
-  handlerDisplayStock,
-  handlerMakeRecipes,
-  handlerMakeSecretRecipes,
-  handlerSaleGranola,
-  handlerBuyIngredient,
-  NULL
-};
-
-#define HANDLER_LEN (sizeof(handlerTab) / sizeof (handlerTab[0]))
-
-/* --- handlePacket() ----------------------------------------------- */
-
-int
-handlePacket(void *packetPtr, size_t packetSize)
-{
-  int			cmdId;
-
-  cmdId = getNumber(&packetPtr, &packetSize);
-  if (cmdId > (int)HANDLER_LEN)
-    fprintf(stderr, "ID (%i) out of range.\n", cmdId);
-  else
-    handlerTab[cmdId](packetPtr, packetSize);
-  return 0;
-}
-
-/* --- main() ------------------------------------------------------- */
-
-int
-main(int argc, char **argv)
-{
-  if (argc > 1) {
-    if (!strcmp(argv[1], "start"))
-      return (runDaemon(0));
-    else if (!strcmp(argv[1], "debug"))
-      return (runDaemon(1));
-    else if (!strcmp(argv[1], "stop"))
-      return (stopDaemon());
-  }
-  fprintf(stderr, "usage: %s {start|debug|stop}\n", argv[0]);
-  return EXIT_SUCCESS;
-}
diff --git a/Pepito/network.c b/Pepito/network.c
deleted file mode 100644
index 19c10de..0000000
--- a/Pepito/network.c
+++ /dev/null
@@ -1,91 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#include <unistd.h>
-#include <stdio.h>
-#include <string.h>
-
-#include <sys/socket.h>
-#include <sys/stat.h>
-#include <sys/types.h>
-
-#include <netinet/in.h>
-
-#include "pepito.h"
-
-#include "network.h"
-#include "utils.h"
-
-static int	       	sockFd = -1;
-static int	       	client = -1;
-
-void
-initConnection(struct sockaddr_in *sa)
-{
-  if ((sockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
-    die("socket()");
-
-  bzero(sa, sizeof *sa);
-  sa->sin_family = AF_INET;
-  sa->sin_port = htons(PORT);
-  sa->sin_addr.s_addr = htonl(INADDR_ANY);
-
-  if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
-    die("setsockopt()");
-  if (bind(sockFd, (struct sockaddr *)sa, sizeof *sa) < 0)
-    die("bind()");
-  if (listen(sockFd, 1) < 0)
-    die("listen()");
-}
-
-int
-acceptClient(struct sockaddr_in *sa)
-{
-  int			res;
-  socklen_t	       	sa_len = sizeof *sa;
-
-  if ((res = accept(sockFd, (struct sockaddr *)sa, &sa_len)) < 0)
-    die("accept()");
-  return res;
-}
-
-int
-getPacket(void *packetPtr, size_t *packetSize)
-{
-  if ((*(ssize_t *)packetSize = recv(client, packetPtr, PACKETLEN, 0)) < 0)
-    die("recv()");
-  if (*packetSize > 0)
-    return (1);
-  return 0;
-}
-
-void
-sendLogMessage(char *msg)
-{
-  write(client, msg, strlen(msg));
-  fprintf(stderr, msg);
-}
-
-void
-setClient(int fd)
-{
-  if (client != -1)
-    close(client);
-  client = fd;
-}
-
-void
-setSock(int fd)
-{
-  if (sockFd != -1)
-    close(sockFd);
-  sockFd = fd;
-}
diff --git a/Pepito/network.h b/Pepito/network.h
deleted file mode 100644
index be2027a..0000000
--- a/Pepito/network.h
+++ /dev/null
@@ -1,29 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#ifndef			_NETWORK_H__
-# define		_NETWORK_H__
-
-#include <sys/socket.h>
-#include <sys/stat.h>
-#include <sys/types.h>
-
-#include <netinet/in.h>
-
-void			initConnection(struct sockaddr_in *sa);
-int			acceptClient(struct sockaddr_in *sa);
-int			getPacket(void *packetPtr, size_t *packetSize);
-void			sendLogMessage(char *msg);
-
-void			setClient(int fd);
-void			setSock(int fd);
-
-#endif		    /* !_NETWORK_H__ */
diff --git a/Pepito/pepito b/Pepito/pepito
deleted file mode 100755
index f80d413..0000000
Binary files a/Pepito/pepito and /dev/null differ
diff --git a/Pepito/pepito.h b/Pepito/pepito.h
deleted file mode 100644
index 2c3eb19..0000000
--- a/Pepito/pepito.h
+++ /dev/null
@@ -1,34 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#ifndef		__PEPITO_H__
-# define	__PEPITO_H__
-
-#define PACKETLEN	0x1000
-#define PORT		0x7A69
-
-#define PASSWD_CHANGE		"Password successfully changed\n"
-#define AD_CHANGE		"Advertisement successfully changed\n"
-#define PASSWD_FAIL		"Wrong password\n"
-
-#define INGREDIENT_BOUGHT	"Ingredient successfully acquired.\n"
-#define UNKNOWN_INGREDIENT	"Unknown ingredient.\n"
-#define UNKNOWN_RECIPE		"Unknown recipe.\n"
-
-#define NOBODY		0
-#define ADMIN		1
-#define USER		2
-
-int			checkPassword(char *password);
-
-int			handlePacket(void *packetPtr, size_t packetSize);
-
-#endif
diff --git a/Pepito/recipes.h b/Pepito/recipes.h
deleted file mode 100644
index 89e9822..0000000
--- a/Pepito/recipes.h
+++ /dev/null
@@ -1,41 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Djo wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy me a Chimay
-** blue in return.
-*/
-
-#ifndef           __RECIPES_H__
-# define          __RECIPES_H__
-
-# define Recipe_MDMA    0
-# define Recipe_Whisky  1
-# define Recipe_Cum     2
-# define Recipe_LSD     3
-# define Secret_Recipe  4
-
-# define MDMA           0
-# define WHISKY         1
-# define CUM            2
-# define LSD            3
-# define CHOCOLATE      4
-# define FLOUR          5
-
-/* tableau de structure des recettes */
-typedef struct    s_recipes
-{
-  char            *name;          /* nom de la recette */
-  int             quantity;       /* nombre de recette faite */
-}                 t_recipes;
-
-typedef struct    s_stock
-{
-  char            *name;
-  int             quantity;
-}                 t_stock;
-
-#endif     /* !__RECIPES_H__ */
diff --git a/Pepito/secret.h b/Pepito/secret.h
deleted file mode 100644
index 788fb26..0000000
--- a/Pepito/secret.h
+++ /dev/null
@@ -1,7 +0,0 @@
-
-#ifndef   SECRET_H
-# define    SECRET_H
-
-int handlerMakeSecretRecipes(void *packetPtr, size_t packetSize);
-
-#endif     /* !SECRET_H */
diff --git a/Pepito/utils.c b/Pepito/utils.c
deleted file mode 100644
index bf0b5f0..0000000
--- a/Pepito/utils.c
+++ /dev/null
@@ -1,67 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Mota, The Polish Plumber and Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy us [:drinks:]*
-** in return.
-*/
-
-#include <fcntl.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
-#include <unistd.h>
-
-#include "pepito.h"
-
-#include "utils.h"
-
-#define	NOTANUMBER 0xFFFF
-
-/* Utils functions ---------------------------------------------- */
-
-void
-die(char *fctName) {
-  perror(fctName);
-  remove("pepito.pid");
-  exit(EXIT_FAILURE);
-}
-
-char
-getChar(void **p) {
-  char			res;
-
-  res = *(char *)(*p);
-  (*p) += sizeof (res);
-  return res;
-}
-
-int
-getNumber(void **p, size_t *packetSize) {
-  int 			res = 0;
-  void			*save = *p;
-
-  res = strtol(*p, (char **)p, 10);
-  if (save == *p)
-    return NOTANUMBER;
-  *packetSize -= *p - save;
-  return res;
-}
-
-char
-*getStr(void **p, size_t *l) {
-  int 			len;
-  char 			*res = NULL;
-
-  if ((len = getNumber(p, l)) > 0) {
-    res = malloc(len + 1);
-    res[len] = '\0';
-    strncpy(res, *p, len);
-    (*p) += len;
-    (*l) -= len;
-  }
-  return res;
-}
diff --git a/Pepito/utils.h b/Pepito/utils.h
deleted file mode 100644
index 9f6797d..0000000
--- a/Pepito/utils.h
+++ /dev/null
@@ -1,21 +0,0 @@
-/*
-** Epitech Security Lab
-** http://esl.epitech.net - <staff@esl.epitech.eu>
-**
-** Mota, The Polish Plumber and Zerk wrote this.
-** As long as you retain this notice you can do whatever
-** you want with this stuff. If we meet some day, and you
-** think this stuff is worth it, you can buy us [:drinks:]*
-** in return.
-*/
-
-#ifndef		__UTILS_H__
-# define	__UTILS_H__
-
-void			die(char *fctName);
-
-char			getChar(void **p);
-int 			getNumber(void **p, size_t *packetSize);
-char 			*getStr(void **p, size_t *l);
-
-#endif
diff --git a/exploit/Makefile b/exploit/Makefile
new file mode 100644
index 0000000..3015caf
--- /dev/null
+++ b/exploit/Makefile
@@ -0,0 +1,43 @@
+##
+## Makefile for  in
+##
+## Made by Jean PLANCHER
+## Login   <planch_j@epitech.net>
+##
+## Started on  Thu Apr 28 06:00:21 2016 Jean PLANCHER
+## Last update Tue May 10 17:01:09 2016 Jean PLANCHER
+##
+
+CC	= gcc
+
+RM	= rm -f
+
+CFLAGS	+= -I../pepito/includes
+LDFLAGS	= -L../pepito/lib -lsecret -lsupersecret -Wl,-rpath,../pepito/lib
+
+NAME	= pepito
+
+FOLDER	= ../pepito/src/
+
+SRCS	= $(addprefix $(FOLDER), \
+	  main.c \
+	  daemon.c \
+	  network.c \
+	  utils.c)
+
+OBJS	= $(SRCS:.c=.o)
+
+$(NAME): $(OBJS)
+	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)
+
+all: $(NAME)
+
+clean:
+	$(RM) $(OBJS)
+
+fclean:	clean
+	$(RM) $(NAME)
+
+re: fclean all
+
+.PHONY: all clean fclean re
diff --git a/exploit/pepito b/exploit/pepito
new file mode 100755
index 0000000..dd0a242
Binary files /dev/null and b/exploit/pepito differ
diff --git a/pepito.tar.gz b/pepito.tar.gz
index 49c4bb1..c91acdb 100644
Binary files a/pepito.tar.gz and b/pepito.tar.gz differ
diff --git a/pepito/.gdb_history b/pepito/.gdb_history
new file mode 100644
index 0000000..dd54e50
--- /dev/null
+++ b/pepito/.gdb_history
@@ -0,0 +1,73 @@
+r start
+status
+help
+r start
+handle SIGSEGV nostop
+r start
+handle SIGSEGV nostop noprint
+r start
+r start
+handle SIGSEGV nostop noprint
+handle SIGSEGV nostop noprint
+r start
+attach 11156
+p adminPassword
+file pepito
+p adminPassword
+p adminPassword
+info variables
+p userPassword
+detach 
+bt
+info variables
+handle SIGSEGV nostop noprint
+info variables
+info locals
+info locals
+info locales
+bt
+p userPassword
+p adminPassword
+p adminPassword
+p userPassword
+detach 11156
+help detach
+detach pepito
+detach
+attach pepito 11156
+attach 11156
+p userPassword
+detach
+detach
+attach 12164
+p userPassword
+p adminPassword
+set var userPassword="jt3d1l4t3"
+p userPassword
+detach
+attach 23575
+attach 23575
+p userPassword
+p userPassword
+detach
+p adminPassword
+quit
+p adminPassword
+quit
+p userPassword
+set var userPassword="jt3d1l4t3\0"
+p userPassword
+quit
+p adminPassword
+p userPassord
+p userPassword
+set var userPassword="jt3d1l4t3"
+p adminPassword
+set var userPasswod="jt3d1l4t3"
+set var userPassword="jt3d1l4t3"
+p adminPassword
+set var userPassword="jt3d1l4t3"
+p adminPassword
+p userPassword
+set var userPassword="jt3d1l4t3"
+set var userPassword="toto"
diff --git a/pepito/CMakeCache.txt b/pepito/CMakeCache.txt
new file mode 100644
index 0000000..35468df
--- /dev/null
+++ b/pepito/CMakeCache.txt
@@ -0,0 +1,322 @@
+# This is the CMakeCache file.
+# For build in directory: /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+# It was generated by CMake: /usr/bin/cmake
+# You can edit this file to change values found and used by cmake.
+# If you do not want to change any of the values, simply exit the editor.
+# If you do want to change a value, simply edit, save, and exit the editor.
+# The syntax for the file is as follows:
+# KEY:TYPE=VALUE
+# KEY is the name of a variable in the cache.
+# TYPE is a hint to GUIs for the type of VALUE, DO NOT EDIT TYPE!.
+# VALUE is the current value for the KEY.
+
+########################
+# EXTERNAL cache entries
+########################
+
+//Path to a program.
+CMAKE_AR:FILEPATH=/usr/bin/ar
+
+//For backwards compatibility, what version of CMake commands and
+// syntax should this version of CMake try to support.
+CMAKE_BACKWARDS_COMPATIBILITY:STRING=2.4
+
+//Choose the type of build, options are: None(CMAKE_CXX_FLAGS or
+// CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel.
+CMAKE_BUILD_TYPE:STRING=
+
+//Enable/Disable color output during build.
+CMAKE_COLOR_MAKEFILE:BOOL=ON
+
+//CXX compiler
+CMAKE_CXX_COMPILER:FILEPATH=/usr/bin/c++
+
+//Flags used by the compiler during all build types.
+CMAKE_CXX_FLAGS:STRING=
+
+//Flags used by the compiler during debug builds.
+CMAKE_CXX_FLAGS_DEBUG:STRING=-g
+
+//Flags used by the compiler during release builds for minimum
+// size.
+CMAKE_CXX_FLAGS_MINSIZEREL:STRING=-Os -DNDEBUG
+
+//Flags used by the compiler during release builds.
+CMAKE_CXX_FLAGS_RELEASE:STRING=-O3 -DNDEBUG
+
+//Flags used by the compiler during release builds with debug info.
+CMAKE_CXX_FLAGS_RELWITHDEBINFO:STRING=-O2 -g -DNDEBUG
+
+//C compiler
+CMAKE_C_COMPILER:FILEPATH=/usr/bin/cc
+
+//Flags used by the compiler during all build types.
+CMAKE_C_FLAGS:STRING=
+
+//Flags used by the compiler during debug builds.
+CMAKE_C_FLAGS_DEBUG:STRING=-g
+
+//Flags used by the compiler during release builds for minimum
+// size.
+CMAKE_C_FLAGS_MINSIZEREL:STRING=-Os -DNDEBUG
+
+//Flags used by the compiler during release builds.
+CMAKE_C_FLAGS_RELEASE:STRING=-O3 -DNDEBUG
+
+//Flags used by the compiler during release builds with debug info.
+CMAKE_C_FLAGS_RELWITHDEBINFO:STRING=-O2 -g -DNDEBUG
+
+//Flags used by the linker.
+CMAKE_EXE_LINKER_FLAGS:STRING=
+
+//Flags used by the linker during debug builds.
+CMAKE_EXE_LINKER_FLAGS_DEBUG:STRING=
+
+//Flags used by the linker during release minsize builds.
+CMAKE_EXE_LINKER_FLAGS_MINSIZEREL:STRING=
+
+//Flags used by the linker during release builds.
+CMAKE_EXE_LINKER_FLAGS_RELEASE:STRING=
+
+//Flags used by the linker during Release with Debug Info builds.
+CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO:STRING=
+
+//Enable/Disable output of compile commands during generation.
+CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=OFF
+
+//Install path prefix, prepended onto install directories.
+CMAKE_INSTALL_PREFIX:PATH=/usr/local
+
+//Path to a program.
+CMAKE_LINKER:FILEPATH=/usr/bin/ld
+
+//Path to a program.
+CMAKE_MAKE_PROGRAM:FILEPATH=/usr/bin/make
+
+//Flags used by the linker during the creation of modules.
+CMAKE_MODULE_LINKER_FLAGS:STRING=
+
+//Flags used by the linker during debug builds.
+CMAKE_MODULE_LINKER_FLAGS_DEBUG:STRING=
+
+//Flags used by the linker during release minsize builds.
+CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL:STRING=
+
+//Flags used by the linker during release builds.
+CMAKE_MODULE_LINKER_FLAGS_RELEASE:STRING=
+
+//Flags used by the linker during Release with Debug Info builds.
+CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO:STRING=
+
+//Path to a program.
+CMAKE_NM:FILEPATH=/usr/bin/nm
+
+//Path to a program.
+CMAKE_OBJCOPY:FILEPATH=/usr/bin/objcopy
+
+//Path to a program.
+CMAKE_OBJDUMP:FILEPATH=/usr/bin/objdump
+
+//Value Computed by CMake
+CMAKE_PROJECT_NAME:STATIC=pepito
+
+//Path to a program.
+CMAKE_RANLIB:FILEPATH=/usr/bin/ranlib
+
+//Flags used by the linker during the creation of dll's.
+CMAKE_SHARED_LINKER_FLAGS:STRING=
+
+//Flags used by the linker during debug builds.
+CMAKE_SHARED_LINKER_FLAGS_DEBUG:STRING=
+
+//Flags used by the linker during release minsize builds.
+CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL:STRING=
+
+//Flags used by the linker during release builds.
+CMAKE_SHARED_LINKER_FLAGS_RELEASE:STRING=
+
+//Flags used by the linker during Release with Debug Info builds.
+CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO:STRING=
+
+//If set, runtime paths are not added when installing shared libraries,
+// but are added when building.
+CMAKE_SKIP_INSTALL_RPATH:BOOL=NO
+
+//If set, runtime paths are not added when using shared libraries.
+CMAKE_SKIP_RPATH:BOOL=NO
+
+//Flags used by the linker during the creation of static libraries.
+CMAKE_STATIC_LINKER_FLAGS:STRING=
+
+//Flags used by the linker during debug builds.
+CMAKE_STATIC_LINKER_FLAGS_DEBUG:STRING=
+
+//Flags used by the linker during release minsize builds.
+CMAKE_STATIC_LINKER_FLAGS_MINSIZEREL:STRING=
+
+//Flags used by the linker during release builds.
+CMAKE_STATIC_LINKER_FLAGS_RELEASE:STRING=
+
+//Flags used by the linker during Release with Debug Info builds.
+CMAKE_STATIC_LINKER_FLAGS_RELWITHDEBINFO:STRING=
+
+//Path to a program.
+CMAKE_STRIP:FILEPATH=/usr/bin/strip
+
+//If this value is on, makefiles will be generated without the
+// .SILENT directive, and all commands will be echoed to the console
+// during the make.  This is useful for debugging only. With Visual
+// Studio IDE projects all commands are done without /nologo.
+CMAKE_VERBOSE_MAKEFILE:BOOL=FALSE
+
+//Single output directory for building all executables.
+EXECUTABLE_OUTPUT_PATH:PATH=
+
+//Single output directory for building all libraries.
+LIBRARY_OUTPUT_PATH:PATH=
+
+//Path to a library.
+LIBSECRET:FILEPATH=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/lib/libsecret.so
+
+//Path to a library.
+LIBSUPERSECRET:FILEPATH=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/lib/libsupersecret.so
+
+//Value Computed by CMake
+pepito_BINARY_DIR:STATIC=/home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+//Value Computed by CMake
+pepito_SOURCE_DIR:STATIC=/home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+
+########################
+# INTERNAL cache entries
+########################
+
+//ADVANCED property for variable: CMAKE_AR
+CMAKE_AR-ADVANCED:INTERNAL=1
+//This is the directory where this CMakeCache.txt was created
+CMAKE_CACHEFILE_DIR:INTERNAL=/home/qwebify/rendu/secu/2016_P3p1t0/pepito
+//Major version of cmake used to create the current loaded cache
+CMAKE_CACHE_MAJOR_VERSION:INTERNAL=3
+//Minor version of cmake used to create the current loaded cache
+CMAKE_CACHE_MINOR_VERSION:INTERNAL=5
+//Patch version of cmake used to create the current loaded cache
+CMAKE_CACHE_PATCH_VERSION:INTERNAL=2
+//ADVANCED property for variable: CMAKE_COLOR_MAKEFILE
+CMAKE_COLOR_MAKEFILE-ADVANCED:INTERNAL=1
+//Path to CMake executable.
+CMAKE_COMMAND:INTERNAL=/usr/bin/cmake
+//Path to cpack program executable.
+CMAKE_CPACK_COMMAND:INTERNAL=/usr/bin/cpack
+//Path to ctest program executable.
+CMAKE_CTEST_COMMAND:INTERNAL=/usr/bin/ctest
+//ADVANCED property for variable: CMAKE_CXX_COMPILER
+CMAKE_CXX_COMPILER-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_CXX_FLAGS
+CMAKE_CXX_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_CXX_FLAGS_DEBUG
+CMAKE_CXX_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_CXX_FLAGS_MINSIZEREL
+CMAKE_CXX_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_CXX_FLAGS_RELEASE
+CMAKE_CXX_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_CXX_FLAGS_RELWITHDEBINFO
+CMAKE_CXX_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_COMPILER
+CMAKE_C_COMPILER-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_FLAGS
+CMAKE_C_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_FLAGS_DEBUG
+CMAKE_C_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_FLAGS_MINSIZEREL
+CMAKE_C_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_FLAGS_RELEASE
+CMAKE_C_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_C_FLAGS_RELWITHDEBINFO
+CMAKE_C_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//Path to cache edit program executable.
+CMAKE_EDIT_COMMAND:INTERNAL=/usr/bin/ccmake
+//Executable file format
+CMAKE_EXECUTABLE_FORMAT:INTERNAL=ELF
+//ADVANCED property for variable: CMAKE_EXE_LINKER_FLAGS
+CMAKE_EXE_LINKER_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_EXE_LINKER_FLAGS_DEBUG
+CMAKE_EXE_LINKER_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_EXE_LINKER_FLAGS_MINSIZEREL
+CMAKE_EXE_LINKER_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_EXE_LINKER_FLAGS_RELEASE
+CMAKE_EXE_LINKER_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO
+CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_EXPORT_COMPILE_COMMANDS
+CMAKE_EXPORT_COMPILE_COMMANDS-ADVANCED:INTERNAL=1
+//Name of external makefile project generator.
+CMAKE_EXTRA_GENERATOR:INTERNAL=
+//Name of generator.
+CMAKE_GENERATOR:INTERNAL=Unix Makefiles
+//Name of generator platform.
+CMAKE_GENERATOR_PLATFORM:INTERNAL=
+//Name of generator toolset.
+CMAKE_GENERATOR_TOOLSET:INTERNAL=
+//Source directory with the top level CMakeLists.txt file for this
+// project
+CMAKE_HOME_DIRECTORY:INTERNAL=/home/qwebify/rendu/secu/2016_P3p1t0/pepito
+//Install .so files without execute permission.
+CMAKE_INSTALL_SO_NO_EXE:INTERNAL=0
+//ADVANCED property for variable: CMAKE_LINKER
+CMAKE_LINKER-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MAKE_PROGRAM
+CMAKE_MAKE_PROGRAM-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MODULE_LINKER_FLAGS
+CMAKE_MODULE_LINKER_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MODULE_LINKER_FLAGS_DEBUG
+CMAKE_MODULE_LINKER_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL
+CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MODULE_LINKER_FLAGS_RELEASE
+CMAKE_MODULE_LINKER_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO
+CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_NM
+CMAKE_NM-ADVANCED:INTERNAL=1
+//number of local generators
+CMAKE_NUMBER_OF_MAKEFILES:INTERNAL=1
+//ADVANCED property for variable: CMAKE_OBJCOPY
+CMAKE_OBJCOPY-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_OBJDUMP
+CMAKE_OBJDUMP-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_RANLIB
+CMAKE_RANLIB-ADVANCED:INTERNAL=1
+//Path to CMake installation.
+CMAKE_ROOT:INTERNAL=/usr/share/cmake-3.5
+//ADVANCED property for variable: CMAKE_SHARED_LINKER_FLAGS
+CMAKE_SHARED_LINKER_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SHARED_LINKER_FLAGS_DEBUG
+CMAKE_SHARED_LINKER_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL
+CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SHARED_LINKER_FLAGS_RELEASE
+CMAKE_SHARED_LINKER_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO
+CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SKIP_INSTALL_RPATH
+CMAKE_SKIP_INSTALL_RPATH-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_SKIP_RPATH
+CMAKE_SKIP_RPATH-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STATIC_LINKER_FLAGS
+CMAKE_STATIC_LINKER_FLAGS-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STATIC_LINKER_FLAGS_DEBUG
+CMAKE_STATIC_LINKER_FLAGS_DEBUG-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STATIC_LINKER_FLAGS_MINSIZEREL
+CMAKE_STATIC_LINKER_FLAGS_MINSIZEREL-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STATIC_LINKER_FLAGS_RELEASE
+CMAKE_STATIC_LINKER_FLAGS_RELEASE-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STATIC_LINKER_FLAGS_RELWITHDEBINFO
+CMAKE_STATIC_LINKER_FLAGS_RELWITHDEBINFO-ADVANCED:INTERNAL=1
+//ADVANCED property for variable: CMAKE_STRIP
+CMAKE_STRIP-ADVANCED:INTERNAL=1
+//uname command
+CMAKE_UNAME:INTERNAL=/usr/bin/uname
+//ADVANCED property for variable: CMAKE_VERBOSE_MAKEFILE
+CMAKE_VERBOSE_MAKEFILE-ADVANCED:INTERNAL=1
+
diff --git a/pepito/CMakeFiles/3.5.2/CMakeCCompiler.cmake b/pepito/CMakeFiles/3.5.2/CMakeCCompiler.cmake
new file mode 100644
index 0000000..41ad869
--- /dev/null
+++ b/pepito/CMakeFiles/3.5.2/CMakeCCompiler.cmake
@@ -0,0 +1,67 @@
+set(CMAKE_C_COMPILER "/usr/bin/cc")
+set(CMAKE_C_COMPILER_ARG1 "")
+set(CMAKE_C_COMPILER_ID "GNU")
+set(CMAKE_C_COMPILER_VERSION "6.1.1")
+set(CMAKE_C_COMPILER_WRAPPER "")
+set(CMAKE_C_STANDARD_COMPUTED_DEFAULT "11")
+set(CMAKE_C_COMPILE_FEATURES "c_function_prototypes;c_restrict;c_variadic_macros;c_static_assert")
+set(CMAKE_C90_COMPILE_FEATURES "c_function_prototypes")
+set(CMAKE_C99_COMPILE_FEATURES "c_restrict;c_variadic_macros")
+set(CMAKE_C11_COMPILE_FEATURES "c_static_assert")
+
+set(CMAKE_C_PLATFORM_ID "Linux")
+set(CMAKE_C_SIMULATE_ID "")
+set(CMAKE_C_SIMULATE_VERSION "")
+
+set(CMAKE_AR "/usr/bin/ar")
+set(CMAKE_RANLIB "/usr/bin/ranlib")
+set(CMAKE_LINKER "/usr/bin/ld")
+set(CMAKE_COMPILER_IS_GNUCC 1)
+set(CMAKE_C_COMPILER_LOADED 1)
+set(CMAKE_C_COMPILER_WORKS TRUE)
+set(CMAKE_C_ABI_COMPILED TRUE)
+set(CMAKE_COMPILER_IS_MINGW )
+set(CMAKE_COMPILER_IS_CYGWIN )
+if(CMAKE_COMPILER_IS_CYGWIN)
+  set(CYGWIN 1)
+  set(UNIX 1)
+endif()
+
+set(CMAKE_C_COMPILER_ENV_VAR "CC")
+
+if(CMAKE_COMPILER_IS_MINGW)
+  set(MINGW 1)
+endif()
+set(CMAKE_C_COMPILER_ID_RUN 1)
+set(CMAKE_C_SOURCE_FILE_EXTENSIONS c;m)
+set(CMAKE_C_IGNORE_EXTENSIONS h;H;o;O;obj;OBJ;def;DEF;rc;RC)
+set(CMAKE_C_LINKER_PREFERENCE 10)
+
+# Save compiler ABI information.
+set(CMAKE_C_SIZEOF_DATA_PTR "8")
+set(CMAKE_C_COMPILER_ABI "ELF")
+set(CMAKE_C_LIBRARY_ARCHITECTURE "")
+
+if(CMAKE_C_SIZEOF_DATA_PTR)
+  set(CMAKE_SIZEOF_VOID_P "${CMAKE_C_SIZEOF_DATA_PTR}")
+endif()
+
+if(CMAKE_C_COMPILER_ABI)
+  set(CMAKE_INTERNAL_PLATFORM_ABI "${CMAKE_C_COMPILER_ABI}")
+endif()
+
+if(CMAKE_C_LIBRARY_ARCHITECTURE)
+  set(CMAKE_LIBRARY_ARCHITECTURE "")
+endif()
+
+set(CMAKE_C_CL_SHOWINCLUDES_PREFIX "")
+if(CMAKE_C_CL_SHOWINCLUDES_PREFIX)
+  set(CMAKE_CL_SHOWINCLUDES_PREFIX "${CMAKE_C_CL_SHOWINCLUDES_PREFIX}")
+endif()
+
+
+
+
+set(CMAKE_C_IMPLICIT_LINK_LIBRARIES "c")
+set(CMAKE_C_IMPLICIT_LINK_DIRECTORIES "/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1;/usr/lib;/lib")
+set(CMAKE_C_IMPLICIT_LINK_FRAMEWORK_DIRECTORIES "")
diff --git a/pepito/CMakeFiles/3.5.2/CMakeCXXCompiler.cmake b/pepito/CMakeFiles/3.5.2/CMakeCXXCompiler.cmake
new file mode 100644
index 0000000..2d3d556
--- /dev/null
+++ b/pepito/CMakeFiles/3.5.2/CMakeCXXCompiler.cmake
@@ -0,0 +1,68 @@
+set(CMAKE_CXX_COMPILER "/usr/bin/c++")
+set(CMAKE_CXX_COMPILER_ARG1 "")
+set(CMAKE_CXX_COMPILER_ID "GNU")
+set(CMAKE_CXX_COMPILER_VERSION "6.1.1")
+set(CMAKE_CXX_COMPILER_WRAPPER "")
+set(CMAKE_CXX_STANDARD_COMPUTED_DEFAULT "14")
+set(CMAKE_CXX_COMPILE_FEATURES "cxx_template_template_parameters;cxx_alias_templates;cxx_alignas;cxx_alignof;cxx_attributes;cxx_auto_type;cxx_constexpr;cxx_decltype;cxx_decltype_incomplete_return_types;cxx_default_function_template_args;cxx_defaulted_functions;cxx_defaulted_move_initializers;cxx_delegating_constructors;cxx_deleted_functions;cxx_enum_forward_declarations;cxx_explicit_conversions;cxx_extended_friend_declarations;cxx_extern_templates;cxx_final;cxx_func_identifier;cxx_generalized_initializers;cxx_inheriting_constructors;cxx_inline_namespaces;cxx_lambdas;cxx_local_type_template_args;cxx_long_long_type;cxx_noexcept;cxx_nonstatic_member_init;cxx_nullptr;cxx_override;cxx_range_for;cxx_raw_string_literals;cxx_reference_qualified_functions;cxx_right_angle_brackets;cxx_rvalue_references;cxx_sizeof_member;cxx_static_assert;cxx_strong_enums;cxx_thread_local;cxx_trailing_return_types;cxx_unicode_literals;cxx_uniform_initialization;cxx_unrestricted_unions;cxx_user_literals;cxx_variadic_macros;cxx_variadic_templates;cxx_aggregate_default_initializers;cxx_attribute_deprecated;cxx_binary_literals;cxx_contextual_conversions;cxx_decltype_auto;cxx_digit_separators;cxx_generic_lambdas;cxx_lambda_init_captures;cxx_relaxed_constexpr;cxx_return_type_deduction;cxx_variable_templates")
+set(CMAKE_CXX98_COMPILE_FEATURES "cxx_template_template_parameters")
+set(CMAKE_CXX11_COMPILE_FEATURES "cxx_alias_templates;cxx_alignas;cxx_alignof;cxx_attributes;cxx_auto_type;cxx_constexpr;cxx_decltype;cxx_decltype_incomplete_return_types;cxx_default_function_template_args;cxx_defaulted_functions;cxx_defaulted_move_initializers;cxx_delegating_constructors;cxx_deleted_functions;cxx_enum_forward_declarations;cxx_explicit_conversions;cxx_extended_friend_declarations;cxx_extern_templates;cxx_final;cxx_func_identifier;cxx_generalized_initializers;cxx_inheriting_constructors;cxx_inline_namespaces;cxx_lambdas;cxx_local_type_template_args;cxx_long_long_type;cxx_noexcept;cxx_nonstatic_member_init;cxx_nullptr;cxx_override;cxx_range_for;cxx_raw_string_literals;cxx_reference_qualified_functions;cxx_right_angle_brackets;cxx_rvalue_references;cxx_sizeof_member;cxx_static_assert;cxx_strong_enums;cxx_thread_local;cxx_trailing_return_types;cxx_unicode_literals;cxx_uniform_initialization;cxx_unrestricted_unions;cxx_user_literals;cxx_variadic_macros;cxx_variadic_templates")
+set(CMAKE_CXX14_COMPILE_FEATURES "cxx_aggregate_default_initializers;cxx_attribute_deprecated;cxx_binary_literals;cxx_contextual_conversions;cxx_decltype_auto;cxx_digit_separators;cxx_generic_lambdas;cxx_lambda_init_captures;cxx_relaxed_constexpr;cxx_return_type_deduction;cxx_variable_templates")
+
+set(CMAKE_CXX_PLATFORM_ID "Linux")
+set(CMAKE_CXX_SIMULATE_ID "")
+set(CMAKE_CXX_SIMULATE_VERSION "")
+
+set(CMAKE_AR "/usr/bin/ar")
+set(CMAKE_RANLIB "/usr/bin/ranlib")
+set(CMAKE_LINKER "/usr/bin/ld")
+set(CMAKE_COMPILER_IS_GNUCXX 1)
+set(CMAKE_CXX_COMPILER_LOADED 1)
+set(CMAKE_CXX_COMPILER_WORKS TRUE)
+set(CMAKE_CXX_ABI_COMPILED TRUE)
+set(CMAKE_COMPILER_IS_MINGW )
+set(CMAKE_COMPILER_IS_CYGWIN )
+if(CMAKE_COMPILER_IS_CYGWIN)
+  set(CYGWIN 1)
+  set(UNIX 1)
+endif()
+
+set(CMAKE_CXX_COMPILER_ENV_VAR "CXX")
+
+if(CMAKE_COMPILER_IS_MINGW)
+  set(MINGW 1)
+endif()
+set(CMAKE_CXX_COMPILER_ID_RUN 1)
+set(CMAKE_CXX_IGNORE_EXTENSIONS inl;h;hpp;HPP;H;o;O;obj;OBJ;def;DEF;rc;RC)
+set(CMAKE_CXX_SOURCE_FILE_EXTENSIONS C;M;c++;cc;cpp;cxx;mm;CPP)
+set(CMAKE_CXX_LINKER_PREFERENCE 30)
+set(CMAKE_CXX_LINKER_PREFERENCE_PROPAGATES 1)
+
+# Save compiler ABI information.
+set(CMAKE_CXX_SIZEOF_DATA_PTR "8")
+set(CMAKE_CXX_COMPILER_ABI "ELF")
+set(CMAKE_CXX_LIBRARY_ARCHITECTURE "")
+
+if(CMAKE_CXX_SIZEOF_DATA_PTR)
+  set(CMAKE_SIZEOF_VOID_P "${CMAKE_CXX_SIZEOF_DATA_PTR}")
+endif()
+
+if(CMAKE_CXX_COMPILER_ABI)
+  set(CMAKE_INTERNAL_PLATFORM_ABI "${CMAKE_CXX_COMPILER_ABI}")
+endif()
+
+if(CMAKE_CXX_LIBRARY_ARCHITECTURE)
+  set(CMAKE_LIBRARY_ARCHITECTURE "")
+endif()
+
+set(CMAKE_CXX_CL_SHOWINCLUDES_PREFIX "")
+if(CMAKE_CXX_CL_SHOWINCLUDES_PREFIX)
+  set(CMAKE_CL_SHOWINCLUDES_PREFIX "${CMAKE_CXX_CL_SHOWINCLUDES_PREFIX}")
+endif()
+
+
+
+
+set(CMAKE_CXX_IMPLICIT_LINK_LIBRARIES "stdc++;m;c")
+set(CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES "/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1;/usr/lib;/lib")
+set(CMAKE_CXX_IMPLICIT_LINK_FRAMEWORK_DIRECTORIES "")
diff --git a/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_C.bin b/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_C.bin
new file mode 100755
index 0000000..063a25b
Binary files /dev/null and b/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_C.bin differ
diff --git a/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_CXX.bin b/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_CXX.bin
new file mode 100755
index 0000000..ee36398
Binary files /dev/null and b/pepito/CMakeFiles/3.5.2/CMakeDetermineCompilerABI_CXX.bin differ
diff --git a/pepito/CMakeFiles/3.5.2/CMakeSystem.cmake b/pepito/CMakeFiles/3.5.2/CMakeSystem.cmake
new file mode 100644
index 0000000..951b24f
--- /dev/null
+++ b/pepito/CMakeFiles/3.5.2/CMakeSystem.cmake
@@ -0,0 +1,15 @@
+set(CMAKE_HOST_SYSTEM "Linux-4.5.2-1-ARCH")
+set(CMAKE_HOST_SYSTEM_NAME "Linux")
+set(CMAKE_HOST_SYSTEM_VERSION "4.5.2-1-ARCH")
+set(CMAKE_HOST_SYSTEM_PROCESSOR "x86_64")
+
+
+
+set(CMAKE_SYSTEM "Linux-4.5.2-1-ARCH")
+set(CMAKE_SYSTEM_NAME "Linux")
+set(CMAKE_SYSTEM_VERSION "4.5.2-1-ARCH")
+set(CMAKE_SYSTEM_PROCESSOR "x86_64")
+
+set(CMAKE_CROSSCOMPILING "FALSE")
+
+set(CMAKE_SYSTEM_LOADED 1)
diff --git a/pepito/CMakeFiles/3.5.2/CompilerIdC/CMakeCCompilerId.c b/pepito/CMakeFiles/3.5.2/CompilerIdC/CMakeCCompilerId.c
new file mode 100644
index 0000000..570a15e
--- /dev/null
+++ b/pepito/CMakeFiles/3.5.2/CompilerIdC/CMakeCCompilerId.c
@@ -0,0 +1,544 @@
+#ifdef __cplusplus
+# error "A C++ compiler has been selected for C."
+#endif
+
+#if defined(__18CXX)
+# define ID_VOID_MAIN
+#endif
+
+
+/* Version number components: V=Version, R=Revision, P=Patch
+   Version date components:   YYYY=Year, MM=Month,   DD=Day  */
+
+#if defined(__INTEL_COMPILER) || defined(__ICC)
+# define COMPILER_ID "Intel"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+  /* __INTEL_COMPILER = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__INTEL_COMPILER/100)
+# define COMPILER_VERSION_MINOR DEC(__INTEL_COMPILER/10 % 10)
+# if defined(__INTEL_COMPILER_UPDATE)
+#  define COMPILER_VERSION_PATCH DEC(__INTEL_COMPILER_UPDATE)
+# else
+#  define COMPILER_VERSION_PATCH DEC(__INTEL_COMPILER   % 10)
+# endif
+# if defined(__INTEL_COMPILER_BUILD_DATE)
+  /* __INTEL_COMPILER_BUILD_DATE = YYYYMMDD */
+#  define COMPILER_VERSION_TWEAK DEC(__INTEL_COMPILER_BUILD_DATE)
+# endif
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+
+#elif defined(__PATHCC__)
+# define COMPILER_ID "PathScale"
+# define COMPILER_VERSION_MAJOR DEC(__PATHCC__)
+# define COMPILER_VERSION_MINOR DEC(__PATHCC_MINOR__)
+# if defined(__PATHCC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__PATHCC_PATCHLEVEL__)
+# endif
+
+#elif defined(__BORLANDC__) && defined(__CODEGEARC_VERSION__)
+# define COMPILER_ID "Embarcadero"
+# define COMPILER_VERSION_MAJOR HEX(__CODEGEARC_VERSION__>>24 & 0x00FF)
+# define COMPILER_VERSION_MINOR HEX(__CODEGEARC_VERSION__>>16 & 0x00FF)
+# define COMPILER_VERSION_PATCH DEC(__CODEGEARC_VERSION__     & 0xFFFF)
+
+#elif defined(__BORLANDC__)
+# define COMPILER_ID "Borland"
+  /* __BORLANDC__ = 0xVRR */
+# define COMPILER_VERSION_MAJOR HEX(__BORLANDC__>>8)
+# define COMPILER_VERSION_MINOR HEX(__BORLANDC__ & 0xFF)
+
+#elif defined(__WATCOMC__) && __WATCOMC__ < 1200
+# define COMPILER_ID "Watcom"
+   /* __WATCOMC__ = VVRR */
+# define COMPILER_VERSION_MAJOR DEC(__WATCOMC__ / 100)
+# define COMPILER_VERSION_MINOR DEC((__WATCOMC__ / 10) % 10)
+# if (__WATCOMC__ % 10) > 0
+#  define COMPILER_VERSION_PATCH DEC(__WATCOMC__ % 10)
+# endif
+
+#elif defined(__WATCOMC__)
+# define COMPILER_ID "OpenWatcom"
+   /* __WATCOMC__ = VVRP + 1100 */
+# define COMPILER_VERSION_MAJOR DEC((__WATCOMC__ - 1100) / 100)
+# define COMPILER_VERSION_MINOR DEC((__WATCOMC__ / 10) % 10)
+# if (__WATCOMC__ % 10) > 0
+#  define COMPILER_VERSION_PATCH DEC(__WATCOMC__ % 10)
+# endif
+
+#elif defined(__SUNPRO_C)
+# define COMPILER_ID "SunPro"
+# if __SUNPRO_C >= 0x5100
+   /* __SUNPRO_C = 0xVRRP */
+#  define COMPILER_VERSION_MAJOR HEX(__SUNPRO_C>>12)
+#  define COMPILER_VERSION_MINOR HEX(__SUNPRO_C>>4 & 0xFF)
+#  define COMPILER_VERSION_PATCH HEX(__SUNPRO_C    & 0xF)
+# else
+   /* __SUNPRO_CC = 0xVRP */
+#  define COMPILER_VERSION_MAJOR HEX(__SUNPRO_C>>8)
+#  define COMPILER_VERSION_MINOR HEX(__SUNPRO_C>>4 & 0xF)
+#  define COMPILER_VERSION_PATCH HEX(__SUNPRO_C    & 0xF)
+# endif
+
+#elif defined(__HP_cc)
+# define COMPILER_ID "HP"
+  /* __HP_cc = VVRRPP */
+# define COMPILER_VERSION_MAJOR DEC(__HP_cc/10000)
+# define COMPILER_VERSION_MINOR DEC(__HP_cc/100 % 100)
+# define COMPILER_VERSION_PATCH DEC(__HP_cc     % 100)
+
+#elif defined(__DECC)
+# define COMPILER_ID "Compaq"
+  /* __DECC_VER = VVRRTPPPP */
+# define COMPILER_VERSION_MAJOR DEC(__DECC_VER/10000000)
+# define COMPILER_VERSION_MINOR DEC(__DECC_VER/100000  % 100)
+# define COMPILER_VERSION_PATCH DEC(__DECC_VER         % 10000)
+
+#elif defined(__IBMC__) && defined(__COMPILER_VER__)
+# define COMPILER_ID "zOS"
+  /* __IBMC__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMC__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMC__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMC__    % 10)
+
+#elif defined(__IBMC__) && !defined(__COMPILER_VER__) && __IBMC__ >= 800
+# define COMPILER_ID "XL"
+  /* __IBMC__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMC__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMC__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMC__    % 10)
+
+#elif defined(__IBMC__) && !defined(__COMPILER_VER__) && __IBMC__ < 800
+# define COMPILER_ID "VisualAge"
+  /* __IBMC__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMC__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMC__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMC__    % 10)
+
+#elif defined(__PGI)
+# define COMPILER_ID "PGI"
+# define COMPILER_VERSION_MAJOR DEC(__PGIC__)
+# define COMPILER_VERSION_MINOR DEC(__PGIC_MINOR__)
+# if defined(__PGIC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__PGIC_PATCHLEVEL__)
+# endif
+
+#elif defined(_CRAYC)
+# define COMPILER_ID "Cray"
+# define COMPILER_VERSION_MAJOR DEC(_RELEASE_MAJOR)
+# define COMPILER_VERSION_MINOR DEC(_RELEASE_MINOR)
+
+#elif defined(__TI_COMPILER_VERSION__)
+# define COMPILER_ID "TI"
+  /* __TI_COMPILER_VERSION__ = VVVRRRPPP */
+# define COMPILER_VERSION_MAJOR DEC(__TI_COMPILER_VERSION__/1000000)
+# define COMPILER_VERSION_MINOR DEC(__TI_COMPILER_VERSION__/1000   % 1000)
+# define COMPILER_VERSION_PATCH DEC(__TI_COMPILER_VERSION__        % 1000)
+
+#elif defined(__FUJITSU) || defined(__FCC_VERSION) || defined(__fcc_version)
+# define COMPILER_ID "Fujitsu"
+
+#elif defined(__TINYC__)
+# define COMPILER_ID "TinyCC"
+
+#elif defined(__SCO_VERSION__)
+# define COMPILER_ID "SCO"
+
+#elif defined(__clang__) && defined(__apple_build_version__)
+# define COMPILER_ID "AppleClang"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+# define COMPILER_VERSION_MAJOR DEC(__clang_major__)
+# define COMPILER_VERSION_MINOR DEC(__clang_minor__)
+# define COMPILER_VERSION_PATCH DEC(__clang_patchlevel__)
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+# define COMPILER_VERSION_TWEAK DEC(__apple_build_version__)
+
+#elif defined(__clang__)
+# define COMPILER_ID "Clang"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+# define COMPILER_VERSION_MAJOR DEC(__clang_major__)
+# define COMPILER_VERSION_MINOR DEC(__clang_minor__)
+# define COMPILER_VERSION_PATCH DEC(__clang_patchlevel__)
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+
+#elif defined(__GNUC__)
+# define COMPILER_ID "GNU"
+# define COMPILER_VERSION_MAJOR DEC(__GNUC__)
+# if defined(__GNUC_MINOR__)
+#  define COMPILER_VERSION_MINOR DEC(__GNUC_MINOR__)
+# endif
+# if defined(__GNUC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__GNUC_PATCHLEVEL__)
+# endif
+
+#elif defined(_MSC_VER)
+# define COMPILER_ID "MSVC"
+  /* _MSC_VER = VVRR */
+# define COMPILER_VERSION_MAJOR DEC(_MSC_VER / 100)
+# define COMPILER_VERSION_MINOR DEC(_MSC_VER % 100)
+# if defined(_MSC_FULL_VER)
+#  if _MSC_VER >= 1400
+    /* _MSC_FULL_VER = VVRRPPPPP */
+#   define COMPILER_VERSION_PATCH DEC(_MSC_FULL_VER % 100000)
+#  else
+    /* _MSC_FULL_VER = VVRRPPPP */
+#   define COMPILER_VERSION_PATCH DEC(_MSC_FULL_VER % 10000)
+#  endif
+# endif
+# if defined(_MSC_BUILD)
+#  define COMPILER_VERSION_TWEAK DEC(_MSC_BUILD)
+# endif
+
+#elif defined(__VISUALDSPVERSION__) || defined(__ADSPBLACKFIN__) || defined(__ADSPTS__) || defined(__ADSP21000__)
+# define COMPILER_ID "ADSP"
+#if defined(__VISUALDSPVERSION__)
+  /* __VISUALDSPVERSION__ = 0xVVRRPP00 */
+# define COMPILER_VERSION_MAJOR HEX(__VISUALDSPVERSION__>>24)
+# define COMPILER_VERSION_MINOR HEX(__VISUALDSPVERSION__>>16 & 0xFF)
+# define COMPILER_VERSION_PATCH HEX(__VISUALDSPVERSION__>>8  & 0xFF)
+#endif
+
+#elif defined(__IAR_SYSTEMS_ICC__ ) || defined(__IAR_SYSTEMS_ICC)
+# define COMPILER_ID "IAR"
+
+#elif defined(__ARMCC_VERSION)
+# define COMPILER_ID "ARMCC"
+#if __ARMCC_VERSION >= 1000000
+  /* __ARMCC_VERSION = VRRPPPP */
+  # define COMPILER_VERSION_MAJOR DEC(__ARMCC_VERSION/1000000)
+  # define COMPILER_VERSION_MINOR DEC(__ARMCC_VERSION/10000 % 100)
+  # define COMPILER_VERSION_PATCH DEC(__ARMCC_VERSION     % 10000)
+#else
+  /* __ARMCC_VERSION = VRPPPP */
+  # define COMPILER_VERSION_MAJOR DEC(__ARMCC_VERSION/100000)
+  # define COMPILER_VERSION_MINOR DEC(__ARMCC_VERSION/10000 % 10)
+  # define COMPILER_VERSION_PATCH DEC(__ARMCC_VERSION    % 10000)
+#endif
+
+
+#elif defined(SDCC)
+# define COMPILER_ID "SDCC"
+  /* SDCC = VRP */
+#  define COMPILER_VERSION_MAJOR DEC(SDCC/100)
+#  define COMPILER_VERSION_MINOR DEC(SDCC/10 % 10)
+#  define COMPILER_VERSION_PATCH DEC(SDCC    % 10)
+
+#elif defined(_SGI_COMPILER_VERSION) || defined(_COMPILER_VERSION)
+# define COMPILER_ID "MIPSpro"
+# if defined(_SGI_COMPILER_VERSION)
+  /* _SGI_COMPILER_VERSION = VRP */
+#  define COMPILER_VERSION_MAJOR DEC(_SGI_COMPILER_VERSION/100)
+#  define COMPILER_VERSION_MINOR DEC(_SGI_COMPILER_VERSION/10 % 10)
+#  define COMPILER_VERSION_PATCH DEC(_SGI_COMPILER_VERSION    % 10)
+# else
+  /* _COMPILER_VERSION = VRP */
+#  define COMPILER_VERSION_MAJOR DEC(_COMPILER_VERSION/100)
+#  define COMPILER_VERSION_MINOR DEC(_COMPILER_VERSION/10 % 10)
+#  define COMPILER_VERSION_PATCH DEC(_COMPILER_VERSION    % 10)
+# endif
+
+
+/* These compilers are either not known or too old to define an
+  identification macro.  Try to identify the platform and guess that
+  it is the native compiler.  */
+#elif defined(__sgi)
+# define COMPILER_ID "MIPSpro"
+
+#elif defined(__hpux) || defined(__hpua)
+# define COMPILER_ID "HP"
+
+#else /* unknown compiler */
+# define COMPILER_ID ""
+#endif
+
+/* Construct the string literal in pieces to prevent the source from
+   getting matched.  Store it in a pointer rather than an array
+   because some compilers will just produce instructions to fill the
+   array rather than assigning a pointer to a static array.  */
+char const* info_compiler = "INFO" ":" "compiler[" COMPILER_ID "]";
+#ifdef SIMULATE_ID
+char const* info_simulate = "INFO" ":" "simulate[" SIMULATE_ID "]";
+#endif
+
+#ifdef __QNXNTO__
+char const* qnxnto = "INFO" ":" "qnxnto[]";
+#endif
+
+#if defined(__CRAYXE) || defined(__CRAYXC)
+char const *info_cray = "INFO" ":" "compiler_wrapper[CrayPrgEnv]";
+#endif
+
+#define STRINGIFY_HELPER(X) #X
+#define STRINGIFY(X) STRINGIFY_HELPER(X)
+
+/* Identify known platforms by name.  */
+#if defined(__linux) || defined(__linux__) || defined(linux)
+# define PLATFORM_ID "Linux"
+
+#elif defined(__CYGWIN__)
+# define PLATFORM_ID "Cygwin"
+
+#elif defined(__MINGW32__)
+# define PLATFORM_ID "MinGW"
+
+#elif defined(__APPLE__)
+# define PLATFORM_ID "Darwin"
+
+#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
+# define PLATFORM_ID "Windows"
+
+#elif defined(__FreeBSD__) || defined(__FreeBSD)
+# define PLATFORM_ID "FreeBSD"
+
+#elif defined(__NetBSD__) || defined(__NetBSD)
+# define PLATFORM_ID "NetBSD"
+
+#elif defined(__OpenBSD__) || defined(__OPENBSD)
+# define PLATFORM_ID "OpenBSD"
+
+#elif defined(__sun) || defined(sun)
+# define PLATFORM_ID "SunOS"
+
+#elif defined(_AIX) || defined(__AIX) || defined(__AIX__) || defined(__aix) || defined(__aix__)
+# define PLATFORM_ID "AIX"
+
+#elif defined(__sgi) || defined(__sgi__) || defined(_SGI)
+# define PLATFORM_ID "IRIX"
+
+#elif defined(__hpux) || defined(__hpux__)
+# define PLATFORM_ID "HP-UX"
+
+#elif defined(__HAIKU__)
+# define PLATFORM_ID "Haiku"
+
+#elif defined(__BeOS) || defined(__BEOS__) || defined(_BEOS)
+# define PLATFORM_ID "BeOS"
+
+#elif defined(__QNX__) || defined(__QNXNTO__)
+# define PLATFORM_ID "QNX"
+
+#elif defined(__tru64) || defined(_tru64) || defined(__TRU64__)
+# define PLATFORM_ID "Tru64"
+
+#elif defined(__riscos) || defined(__riscos__)
+# define PLATFORM_ID "RISCos"
+
+#elif defined(__sinix) || defined(__sinix__) || defined(__SINIX__)
+# define PLATFORM_ID "SINIX"
+
+#elif defined(__UNIX_SV__)
+# define PLATFORM_ID "UNIX_SV"
+
+#elif defined(__bsdos__)
+# define PLATFORM_ID "BSDOS"
+
+#elif defined(_MPRAS) || defined(MPRAS)
+# define PLATFORM_ID "MP-RAS"
+
+#elif defined(__osf) || defined(__osf__)
+# define PLATFORM_ID "OSF1"
+
+#elif defined(_SCO_SV) || defined(SCO_SV) || defined(sco_sv)
+# define PLATFORM_ID "SCO_SV"
+
+#elif defined(__ultrix) || defined(__ultrix__) || defined(_ULTRIX)
+# define PLATFORM_ID "ULTRIX"
+
+#elif defined(__XENIX__) || defined(_XENIX) || defined(XENIX)
+# define PLATFORM_ID "Xenix"
+
+#elif defined(__WATCOMC__)
+# if defined(__LINUX__)
+#  define PLATFORM_ID "Linux"
+
+# elif defined(__DOS__)
+#  define PLATFORM_ID "DOS"
+
+# elif defined(__OS2__)
+#  define PLATFORM_ID "OS2"
+
+# elif defined(__WINDOWS__)
+#  define PLATFORM_ID "Windows3x"
+
+# else /* unknown platform */
+#  define PLATFORM_ID ""
+# endif
+
+#else /* unknown platform */
+# define PLATFORM_ID ""
+
+#endif
+
+/* For windows compilers MSVC and Intel we can determine
+   the architecture of the compiler being used.  This is because
+   the compilers do not have flags that can change the architecture,
+   but rather depend on which compiler is being used
+*/
+#if defined(_WIN32) && defined(_MSC_VER)
+# if defined(_M_IA64)
+#  define ARCHITECTURE_ID "IA64"
+
+# elif defined(_M_X64) || defined(_M_AMD64)
+#  define ARCHITECTURE_ID "x64"
+
+# elif defined(_M_IX86)
+#  define ARCHITECTURE_ID "X86"
+
+# elif defined(_M_ARM)
+#  if _M_ARM == 4
+#   define ARCHITECTURE_ID "ARMV4I"
+#  elif _M_ARM == 5
+#   define ARCHITECTURE_ID "ARMV5I"
+#  else
+#   define ARCHITECTURE_ID "ARMV" STRINGIFY(_M_ARM)
+#  endif
+
+# elif defined(_M_MIPS)
+#  define ARCHITECTURE_ID "MIPS"
+
+# elif defined(_M_SH)
+#  define ARCHITECTURE_ID "SHx"
+
+# else /* unknown architecture */
+#  define ARCHITECTURE_ID ""
+# endif
+
+#elif defined(__WATCOMC__)
+# if defined(_M_I86)
+#  define ARCHITECTURE_ID "I86"
+
+# elif defined(_M_IX86)
+#  define ARCHITECTURE_ID "X86"
+
+# else /* unknown architecture */
+#  define ARCHITECTURE_ID ""
+# endif
+
+#else
+#  define ARCHITECTURE_ID ""
+#endif
+
+/* Convert integer to decimal digit literals.  */
+#define DEC(n)                   \
+  ('0' + (((n) / 10000000)%10)), \
+  ('0' + (((n) / 1000000)%10)),  \
+  ('0' + (((n) / 100000)%10)),   \
+  ('0' + (((n) / 10000)%10)),    \
+  ('0' + (((n) / 1000)%10)),     \
+  ('0' + (((n) / 100)%10)),      \
+  ('0' + (((n) / 10)%10)),       \
+  ('0' +  ((n) % 10))
+
+/* Convert integer to hex digit literals.  */
+#define HEX(n)             \
+  ('0' + ((n)>>28 & 0xF)), \
+  ('0' + ((n)>>24 & 0xF)), \
+  ('0' + ((n)>>20 & 0xF)), \
+  ('0' + ((n)>>16 & 0xF)), \
+  ('0' + ((n)>>12 & 0xF)), \
+  ('0' + ((n)>>8  & 0xF)), \
+  ('0' + ((n)>>4  & 0xF)), \
+  ('0' + ((n)     & 0xF))
+
+/* Construct a string literal encoding the version number components. */
+#ifdef COMPILER_VERSION_MAJOR
+char const info_version[] = {
+  'I', 'N', 'F', 'O', ':',
+  'c','o','m','p','i','l','e','r','_','v','e','r','s','i','o','n','[',
+  COMPILER_VERSION_MAJOR,
+# ifdef COMPILER_VERSION_MINOR
+  '.', COMPILER_VERSION_MINOR,
+#  ifdef COMPILER_VERSION_PATCH
+   '.', COMPILER_VERSION_PATCH,
+#   ifdef COMPILER_VERSION_TWEAK
+    '.', COMPILER_VERSION_TWEAK,
+#   endif
+#  endif
+# endif
+  ']','\0'};
+#endif
+
+/* Construct a string literal encoding the version number components. */
+#ifdef SIMULATE_VERSION_MAJOR
+char const info_simulate_version[] = {
+  'I', 'N', 'F', 'O', ':',
+  's','i','m','u','l','a','t','e','_','v','e','r','s','i','o','n','[',
+  SIMULATE_VERSION_MAJOR,
+# ifdef SIMULATE_VERSION_MINOR
+  '.', SIMULATE_VERSION_MINOR,
+#  ifdef SIMULATE_VERSION_PATCH
+   '.', SIMULATE_VERSION_PATCH,
+#   ifdef SIMULATE_VERSION_TWEAK
+    '.', SIMULATE_VERSION_TWEAK,
+#   endif
+#  endif
+# endif
+  ']','\0'};
+#endif
+
+/* Construct the string literal in pieces to prevent the source from
+   getting matched.  Store it in a pointer rather than an array
+   because some compilers will just produce instructions to fill the
+   array rather than assigning a pointer to a static array.  */
+char const* info_platform = "INFO" ":" "platform[" PLATFORM_ID "]";
+char const* info_arch = "INFO" ":" "arch[" ARCHITECTURE_ID "]";
+
+
+
+
+const char* info_language_dialect_default = "INFO" ":" "dialect_default["
+#if !defined(__STDC_VERSION__)
+  "90"
+#elif __STDC_VERSION__ >= 201000L
+  "11"
+#elif __STDC_VERSION__ >= 199901L
+  "99"
+#else
+#endif
+"]";
+
+/*--------------------------------------------------------------------------*/
+
+#ifdef ID_VOID_MAIN
+void main() {}
+#else
+int main(int argc, char* argv[])
+{
+  int require = 0;
+  require += info_compiler[argc];
+  require += info_platform[argc];
+  require += info_arch[argc];
+#ifdef COMPILER_VERSION_MAJOR
+  require += info_version[argc];
+#endif
+#ifdef SIMULATE_ID
+  require += info_simulate[argc];
+#endif
+#ifdef SIMULATE_VERSION_MAJOR
+  require += info_simulate_version[argc];
+#endif
+#if defined(__CRAYXE) || defined(__CRAYXC)
+  require += info_cray[argc];
+#endif
+  require += info_language_dialect_default[argc];
+  (void)argv;
+  return require;
+}
+#endif
diff --git a/pepito/CMakeFiles/3.5.2/CompilerIdC/a.out b/pepito/CMakeFiles/3.5.2/CompilerIdC/a.out
new file mode 100755
index 0000000..d2642f4
Binary files /dev/null and b/pepito/CMakeFiles/3.5.2/CompilerIdC/a.out differ
diff --git a/pepito/CMakeFiles/3.5.2/CompilerIdCXX/CMakeCXXCompilerId.cpp b/pepito/CMakeFiles/3.5.2/CompilerIdCXX/CMakeCXXCompilerId.cpp
new file mode 100644
index 0000000..e6d8536
--- /dev/null
+++ b/pepito/CMakeFiles/3.5.2/CompilerIdCXX/CMakeCXXCompilerId.cpp
@@ -0,0 +1,533 @@
+/* This source file must have a .cpp extension so that all C++ compilers
+   recognize the extension without flags.  Borland does not know .cxx for
+   example.  */
+#ifndef __cplusplus
+# error "A C compiler has been selected for C++."
+#endif
+
+
+/* Version number components: V=Version, R=Revision, P=Patch
+   Version date components:   YYYY=Year, MM=Month,   DD=Day  */
+
+#if defined(__COMO__)
+# define COMPILER_ID "Comeau"
+  /* __COMO_VERSION__ = VRR */
+# define COMPILER_VERSION_MAJOR DEC(__COMO_VERSION__ / 100)
+# define COMPILER_VERSION_MINOR DEC(__COMO_VERSION__ % 100)
+
+#elif defined(__INTEL_COMPILER) || defined(__ICC)
+# define COMPILER_ID "Intel"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+  /* __INTEL_COMPILER = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__INTEL_COMPILER/100)
+# define COMPILER_VERSION_MINOR DEC(__INTEL_COMPILER/10 % 10)
+# if defined(__INTEL_COMPILER_UPDATE)
+#  define COMPILER_VERSION_PATCH DEC(__INTEL_COMPILER_UPDATE)
+# else
+#  define COMPILER_VERSION_PATCH DEC(__INTEL_COMPILER   % 10)
+# endif
+# if defined(__INTEL_COMPILER_BUILD_DATE)
+  /* __INTEL_COMPILER_BUILD_DATE = YYYYMMDD */
+#  define COMPILER_VERSION_TWEAK DEC(__INTEL_COMPILER_BUILD_DATE)
+# endif
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+
+#elif defined(__PATHCC__)
+# define COMPILER_ID "PathScale"
+# define COMPILER_VERSION_MAJOR DEC(__PATHCC__)
+# define COMPILER_VERSION_MINOR DEC(__PATHCC_MINOR__)
+# if defined(__PATHCC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__PATHCC_PATCHLEVEL__)
+# endif
+
+#elif defined(__BORLANDC__) && defined(__CODEGEARC_VERSION__)
+# define COMPILER_ID "Embarcadero"
+# define COMPILER_VERSION_MAJOR HEX(__CODEGEARC_VERSION__>>24 & 0x00FF)
+# define COMPILER_VERSION_MINOR HEX(__CODEGEARC_VERSION__>>16 & 0x00FF)
+# define COMPILER_VERSION_PATCH DEC(__CODEGEARC_VERSION__     & 0xFFFF)
+
+#elif defined(__BORLANDC__)
+# define COMPILER_ID "Borland"
+  /* __BORLANDC__ = 0xVRR */
+# define COMPILER_VERSION_MAJOR HEX(__BORLANDC__>>8)
+# define COMPILER_VERSION_MINOR HEX(__BORLANDC__ & 0xFF)
+
+#elif defined(__WATCOMC__) && __WATCOMC__ < 1200
+# define COMPILER_ID "Watcom"
+   /* __WATCOMC__ = VVRR */
+# define COMPILER_VERSION_MAJOR DEC(__WATCOMC__ / 100)
+# define COMPILER_VERSION_MINOR DEC((__WATCOMC__ / 10) % 10)
+# if (__WATCOMC__ % 10) > 0
+#  define COMPILER_VERSION_PATCH DEC(__WATCOMC__ % 10)
+# endif
+
+#elif defined(__WATCOMC__)
+# define COMPILER_ID "OpenWatcom"
+   /* __WATCOMC__ = VVRP + 1100 */
+# define COMPILER_VERSION_MAJOR DEC((__WATCOMC__ - 1100) / 100)
+# define COMPILER_VERSION_MINOR DEC((__WATCOMC__ / 10) % 10)
+# if (__WATCOMC__ % 10) > 0
+#  define COMPILER_VERSION_PATCH DEC(__WATCOMC__ % 10)
+# endif
+
+#elif defined(__SUNPRO_CC)
+# define COMPILER_ID "SunPro"
+# if __SUNPRO_CC >= 0x5100
+   /* __SUNPRO_CC = 0xVRRP */
+#  define COMPILER_VERSION_MAJOR HEX(__SUNPRO_CC>>12)
+#  define COMPILER_VERSION_MINOR HEX(__SUNPRO_CC>>4 & 0xFF)
+#  define COMPILER_VERSION_PATCH HEX(__SUNPRO_CC    & 0xF)
+# else
+   /* __SUNPRO_CC = 0xVRP */
+#  define COMPILER_VERSION_MAJOR HEX(__SUNPRO_CC>>8)
+#  define COMPILER_VERSION_MINOR HEX(__SUNPRO_CC>>4 & 0xF)
+#  define COMPILER_VERSION_PATCH HEX(__SUNPRO_CC    & 0xF)
+# endif
+
+#elif defined(__HP_aCC)
+# define COMPILER_ID "HP"
+  /* __HP_aCC = VVRRPP */
+# define COMPILER_VERSION_MAJOR DEC(__HP_aCC/10000)
+# define COMPILER_VERSION_MINOR DEC(__HP_aCC/100 % 100)
+# define COMPILER_VERSION_PATCH DEC(__HP_aCC     % 100)
+
+#elif defined(__DECCXX)
+# define COMPILER_ID "Compaq"
+  /* __DECCXX_VER = VVRRTPPPP */
+# define COMPILER_VERSION_MAJOR DEC(__DECCXX_VER/10000000)
+# define COMPILER_VERSION_MINOR DEC(__DECCXX_VER/100000  % 100)
+# define COMPILER_VERSION_PATCH DEC(__DECCXX_VER         % 10000)
+
+#elif defined(__IBMCPP__) && defined(__COMPILER_VER__)
+# define COMPILER_ID "zOS"
+  /* __IBMCPP__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMCPP__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMCPP__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMCPP__    % 10)
+
+#elif defined(__IBMCPP__) && !defined(__COMPILER_VER__) && __IBMCPP__ >= 800
+# define COMPILER_ID "XL"
+  /* __IBMCPP__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMCPP__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMCPP__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMCPP__    % 10)
+
+#elif defined(__IBMCPP__) && !defined(__COMPILER_VER__) && __IBMCPP__ < 800
+# define COMPILER_ID "VisualAge"
+  /* __IBMCPP__ = VRP */
+# define COMPILER_VERSION_MAJOR DEC(__IBMCPP__/100)
+# define COMPILER_VERSION_MINOR DEC(__IBMCPP__/10 % 10)
+# define COMPILER_VERSION_PATCH DEC(__IBMCPP__    % 10)
+
+#elif defined(__PGI)
+# define COMPILER_ID "PGI"
+# define COMPILER_VERSION_MAJOR DEC(__PGIC__)
+# define COMPILER_VERSION_MINOR DEC(__PGIC_MINOR__)
+# if defined(__PGIC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__PGIC_PATCHLEVEL__)
+# endif
+
+#elif defined(_CRAYC)
+# define COMPILER_ID "Cray"
+# define COMPILER_VERSION_MAJOR DEC(_RELEASE_MAJOR)
+# define COMPILER_VERSION_MINOR DEC(_RELEASE_MINOR)
+
+#elif defined(__TI_COMPILER_VERSION__)
+# define COMPILER_ID "TI"
+  /* __TI_COMPILER_VERSION__ = VVVRRRPPP */
+# define COMPILER_VERSION_MAJOR DEC(__TI_COMPILER_VERSION__/1000000)
+# define COMPILER_VERSION_MINOR DEC(__TI_COMPILER_VERSION__/1000   % 1000)
+# define COMPILER_VERSION_PATCH DEC(__TI_COMPILER_VERSION__        % 1000)
+
+#elif defined(__FUJITSU) || defined(__FCC_VERSION) || defined(__fcc_version)
+# define COMPILER_ID "Fujitsu"
+
+#elif defined(__SCO_VERSION__)
+# define COMPILER_ID "SCO"
+
+#elif defined(__clang__) && defined(__apple_build_version__)
+# define COMPILER_ID "AppleClang"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+# define COMPILER_VERSION_MAJOR DEC(__clang_major__)
+# define COMPILER_VERSION_MINOR DEC(__clang_minor__)
+# define COMPILER_VERSION_PATCH DEC(__clang_patchlevel__)
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+# define COMPILER_VERSION_TWEAK DEC(__apple_build_version__)
+
+#elif defined(__clang__)
+# define COMPILER_ID "Clang"
+# if defined(_MSC_VER)
+#  define SIMULATE_ID "MSVC"
+# endif
+# define COMPILER_VERSION_MAJOR DEC(__clang_major__)
+# define COMPILER_VERSION_MINOR DEC(__clang_minor__)
+# define COMPILER_VERSION_PATCH DEC(__clang_patchlevel__)
+# if defined(_MSC_VER)
+   /* _MSC_VER = VVRR */
+#  define SIMULATE_VERSION_MAJOR DEC(_MSC_VER / 100)
+#  define SIMULATE_VERSION_MINOR DEC(_MSC_VER % 100)
+# endif
+
+#elif defined(__GNUC__)
+# define COMPILER_ID "GNU"
+# define COMPILER_VERSION_MAJOR DEC(__GNUC__)
+# if defined(__GNUC_MINOR__)
+#  define COMPILER_VERSION_MINOR DEC(__GNUC_MINOR__)
+# endif
+# if defined(__GNUC_PATCHLEVEL__)
+#  define COMPILER_VERSION_PATCH DEC(__GNUC_PATCHLEVEL__)
+# endif
+
+#elif defined(_MSC_VER)
+# define COMPILER_ID "MSVC"
+  /* _MSC_VER = VVRR */
+# define COMPILER_VERSION_MAJOR DEC(_MSC_VER / 100)
+# define COMPILER_VERSION_MINOR DEC(_MSC_VER % 100)
+# if defined(_MSC_FULL_VER)
+#  if _MSC_VER >= 1400
+    /* _MSC_FULL_VER = VVRRPPPPP */
+#   define COMPILER_VERSION_PATCH DEC(_MSC_FULL_VER % 100000)
+#  else
+    /* _MSC_FULL_VER = VVRRPPPP */
+#   define COMPILER_VERSION_PATCH DEC(_MSC_FULL_VER % 10000)
+#  endif
+# endif
+# if defined(_MSC_BUILD)
+#  define COMPILER_VERSION_TWEAK DEC(_MSC_BUILD)
+# endif
+
+#elif defined(__VISUALDSPVERSION__) || defined(__ADSPBLACKFIN__) || defined(__ADSPTS__) || defined(__ADSP21000__)
+# define COMPILER_ID "ADSP"
+#if defined(__VISUALDSPVERSION__)
+  /* __VISUALDSPVERSION__ = 0xVVRRPP00 */
+# define COMPILER_VERSION_MAJOR HEX(__VISUALDSPVERSION__>>24)
+# define COMPILER_VERSION_MINOR HEX(__VISUALDSPVERSION__>>16 & 0xFF)
+# define COMPILER_VERSION_PATCH HEX(__VISUALDSPVERSION__>>8  & 0xFF)
+#endif
+
+#elif defined(__IAR_SYSTEMS_ICC__ ) || defined(__IAR_SYSTEMS_ICC)
+# define COMPILER_ID "IAR"
+
+#elif defined(__ARMCC_VERSION)
+# define COMPILER_ID "ARMCC"
+#if __ARMCC_VERSION >= 1000000
+  /* __ARMCC_VERSION = VRRPPPP */
+  # define COMPILER_VERSION_MAJOR DEC(__ARMCC_VERSION/1000000)
+  # define COMPILER_VERSION_MINOR DEC(__ARMCC_VERSION/10000 % 100)
+  # define COMPILER_VERSION_PATCH DEC(__ARMCC_VERSION     % 10000)
+#else
+  /* __ARMCC_VERSION = VRPPPP */
+  # define COMPILER_VERSION_MAJOR DEC(__ARMCC_VERSION/100000)
+  # define COMPILER_VERSION_MINOR DEC(__ARMCC_VERSION/10000 % 10)
+  # define COMPILER_VERSION_PATCH DEC(__ARMCC_VERSION    % 10000)
+#endif
+
+
+#elif defined(_SGI_COMPILER_VERSION) || defined(_COMPILER_VERSION)
+# define COMPILER_ID "MIPSpro"
+# if defined(_SGI_COMPILER_VERSION)
+  /* _SGI_COMPILER_VERSION = VRP */
+#  define COMPILER_VERSION_MAJOR DEC(_SGI_COMPILER_VERSION/100)
+#  define COMPILER_VERSION_MINOR DEC(_SGI_COMPILER_VERSION/10 % 10)
+#  define COMPILER_VERSION_PATCH DEC(_SGI_COMPILER_VERSION    % 10)
+# else
+  /* _COMPILER_VERSION = VRP */
+#  define COMPILER_VERSION_MAJOR DEC(_COMPILER_VERSION/100)
+#  define COMPILER_VERSION_MINOR DEC(_COMPILER_VERSION/10 % 10)
+#  define COMPILER_VERSION_PATCH DEC(_COMPILER_VERSION    % 10)
+# endif
+
+
+/* These compilers are either not known or too old to define an
+  identification macro.  Try to identify the platform and guess that
+  it is the native compiler.  */
+#elif defined(__sgi)
+# define COMPILER_ID "MIPSpro"
+
+#elif defined(__hpux) || defined(__hpua)
+# define COMPILER_ID "HP"
+
+#else /* unknown compiler */
+# define COMPILER_ID ""
+#endif
+
+/* Construct the string literal in pieces to prevent the source from
+   getting matched.  Store it in a pointer rather than an array
+   because some compilers will just produce instructions to fill the
+   array rather than assigning a pointer to a static array.  */
+char const* info_compiler = "INFO" ":" "compiler[" COMPILER_ID "]";
+#ifdef SIMULATE_ID
+char const* info_simulate = "INFO" ":" "simulate[" SIMULATE_ID "]";
+#endif
+
+#ifdef __QNXNTO__
+char const* qnxnto = "INFO" ":" "qnxnto[]";
+#endif
+
+#if defined(__CRAYXE) || defined(__CRAYXC)
+char const *info_cray = "INFO" ":" "compiler_wrapper[CrayPrgEnv]";
+#endif
+
+#define STRINGIFY_HELPER(X) #X
+#define STRINGIFY(X) STRINGIFY_HELPER(X)
+
+/* Identify known platforms by name.  */
+#if defined(__linux) || defined(__linux__) || defined(linux)
+# define PLATFORM_ID "Linux"
+
+#elif defined(__CYGWIN__)
+# define PLATFORM_ID "Cygwin"
+
+#elif defined(__MINGW32__)
+# define PLATFORM_ID "MinGW"
+
+#elif defined(__APPLE__)
+# define PLATFORM_ID "Darwin"
+
+#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
+# define PLATFORM_ID "Windows"
+
+#elif defined(__FreeBSD__) || defined(__FreeBSD)
+# define PLATFORM_ID "FreeBSD"
+
+#elif defined(__NetBSD__) || defined(__NetBSD)
+# define PLATFORM_ID "NetBSD"
+
+#elif defined(__OpenBSD__) || defined(__OPENBSD)
+# define PLATFORM_ID "OpenBSD"
+
+#elif defined(__sun) || defined(sun)
+# define PLATFORM_ID "SunOS"
+
+#elif defined(_AIX) || defined(__AIX) || defined(__AIX__) || defined(__aix) || defined(__aix__)
+# define PLATFORM_ID "AIX"
+
+#elif defined(__sgi) || defined(__sgi__) || defined(_SGI)
+# define PLATFORM_ID "IRIX"
+
+#elif defined(__hpux) || defined(__hpux__)
+# define PLATFORM_ID "HP-UX"
+
+#elif defined(__HAIKU__)
+# define PLATFORM_ID "Haiku"
+
+#elif defined(__BeOS) || defined(__BEOS__) || defined(_BEOS)
+# define PLATFORM_ID "BeOS"
+
+#elif defined(__QNX__) || defined(__QNXNTO__)
+# define PLATFORM_ID "QNX"
+
+#elif defined(__tru64) || defined(_tru64) || defined(__TRU64__)
+# define PLATFORM_ID "Tru64"
+
+#elif defined(__riscos) || defined(__riscos__)
+# define PLATFORM_ID "RISCos"
+
+#elif defined(__sinix) || defined(__sinix__) || defined(__SINIX__)
+# define PLATFORM_ID "SINIX"
+
+#elif defined(__UNIX_SV__)
+# define PLATFORM_ID "UNIX_SV"
+
+#elif defined(__bsdos__)
+# define PLATFORM_ID "BSDOS"
+
+#elif defined(_MPRAS) || defined(MPRAS)
+# define PLATFORM_ID "MP-RAS"
+
+#elif defined(__osf) || defined(__osf__)
+# define PLATFORM_ID "OSF1"
+
+#elif defined(_SCO_SV) || defined(SCO_SV) || defined(sco_sv)
+# define PLATFORM_ID "SCO_SV"
+
+#elif defined(__ultrix) || defined(__ultrix__) || defined(_ULTRIX)
+# define PLATFORM_ID "ULTRIX"
+
+#elif defined(__XENIX__) || defined(_XENIX) || defined(XENIX)
+# define PLATFORM_ID "Xenix"
+
+#elif defined(__WATCOMC__)
+# if defined(__LINUX__)
+#  define PLATFORM_ID "Linux"
+
+# elif defined(__DOS__)
+#  define PLATFORM_ID "DOS"
+
+# elif defined(__OS2__)
+#  define PLATFORM_ID "OS2"
+
+# elif defined(__WINDOWS__)
+#  define PLATFORM_ID "Windows3x"
+
+# else /* unknown platform */
+#  define PLATFORM_ID ""
+# endif
+
+#else /* unknown platform */
+# define PLATFORM_ID ""
+
+#endif
+
+/* For windows compilers MSVC and Intel we can determine
+   the architecture of the compiler being used.  This is because
+   the compilers do not have flags that can change the architecture,
+   but rather depend on which compiler is being used
+*/
+#if defined(_WIN32) && defined(_MSC_VER)
+# if defined(_M_IA64)
+#  define ARCHITECTURE_ID "IA64"
+
+# elif defined(_M_X64) || defined(_M_AMD64)
+#  define ARCHITECTURE_ID "x64"
+
+# elif defined(_M_IX86)
+#  define ARCHITECTURE_ID "X86"
+
+# elif defined(_M_ARM)
+#  if _M_ARM == 4
+#   define ARCHITECTURE_ID "ARMV4I"
+#  elif _M_ARM == 5
+#   define ARCHITECTURE_ID "ARMV5I"
+#  else
+#   define ARCHITECTURE_ID "ARMV" STRINGIFY(_M_ARM)
+#  endif
+
+# elif defined(_M_MIPS)
+#  define ARCHITECTURE_ID "MIPS"
+
+# elif defined(_M_SH)
+#  define ARCHITECTURE_ID "SHx"
+
+# else /* unknown architecture */
+#  define ARCHITECTURE_ID ""
+# endif
+
+#elif defined(__WATCOMC__)
+# if defined(_M_I86)
+#  define ARCHITECTURE_ID "I86"
+
+# elif defined(_M_IX86)
+#  define ARCHITECTURE_ID "X86"
+
+# else /* unknown architecture */
+#  define ARCHITECTURE_ID ""
+# endif
+
+#else
+#  define ARCHITECTURE_ID ""
+#endif
+
+/* Convert integer to decimal digit literals.  */
+#define DEC(n)                   \
+  ('0' + (((n) / 10000000)%10)), \
+  ('0' + (((n) / 1000000)%10)),  \
+  ('0' + (((n) / 100000)%10)),   \
+  ('0' + (((n) / 10000)%10)),    \
+  ('0' + (((n) / 1000)%10)),     \
+  ('0' + (((n) / 100)%10)),      \
+  ('0' + (((n) / 10)%10)),       \
+  ('0' +  ((n) % 10))
+
+/* Convert integer to hex digit literals.  */
+#define HEX(n)             \
+  ('0' + ((n)>>28 & 0xF)), \
+  ('0' + ((n)>>24 & 0xF)), \
+  ('0' + ((n)>>20 & 0xF)), \
+  ('0' + ((n)>>16 & 0xF)), \
+  ('0' + ((n)>>12 & 0xF)), \
+  ('0' + ((n)>>8  & 0xF)), \
+  ('0' + ((n)>>4  & 0xF)), \
+  ('0' + ((n)     & 0xF))
+
+/* Construct a string literal encoding the version number components. */
+#ifdef COMPILER_VERSION_MAJOR
+char const info_version[] = {
+  'I', 'N', 'F', 'O', ':',
+  'c','o','m','p','i','l','e','r','_','v','e','r','s','i','o','n','[',
+  COMPILER_VERSION_MAJOR,
+# ifdef COMPILER_VERSION_MINOR
+  '.', COMPILER_VERSION_MINOR,
+#  ifdef COMPILER_VERSION_PATCH
+   '.', COMPILER_VERSION_PATCH,
+#   ifdef COMPILER_VERSION_TWEAK
+    '.', COMPILER_VERSION_TWEAK,
+#   endif
+#  endif
+# endif
+  ']','\0'};
+#endif
+
+/* Construct a string literal encoding the version number components. */
+#ifdef SIMULATE_VERSION_MAJOR
+char const info_simulate_version[] = {
+  'I', 'N', 'F', 'O', ':',
+  's','i','m','u','l','a','t','e','_','v','e','r','s','i','o','n','[',
+  SIMULATE_VERSION_MAJOR,
+# ifdef SIMULATE_VERSION_MINOR
+  '.', SIMULATE_VERSION_MINOR,
+#  ifdef SIMULATE_VERSION_PATCH
+   '.', SIMULATE_VERSION_PATCH,
+#   ifdef SIMULATE_VERSION_TWEAK
+    '.', SIMULATE_VERSION_TWEAK,
+#   endif
+#  endif
+# endif
+  ']','\0'};
+#endif
+
+/* Construct the string literal in pieces to prevent the source from
+   getting matched.  Store it in a pointer rather than an array
+   because some compilers will just produce instructions to fill the
+   array rather than assigning a pointer to a static array.  */
+char const* info_platform = "INFO" ":" "platform[" PLATFORM_ID "]";
+char const* info_arch = "INFO" ":" "arch[" ARCHITECTURE_ID "]";
+
+
+
+
+const char* info_language_dialect_default = "INFO" ":" "dialect_default["
+#if __cplusplus >= 201402L
+  "14"
+#elif __cplusplus >= 201103L
+  "11"
+#else
+  "98"
+#endif
+"]";
+
+/*--------------------------------------------------------------------------*/
+
+int main(int argc, char* argv[])
+{
+  int require = 0;
+  require += info_compiler[argc];
+  require += info_platform[argc];
+#ifdef COMPILER_VERSION_MAJOR
+  require += info_version[argc];
+#endif
+#ifdef SIMULATE_ID
+  require += info_simulate[argc];
+#endif
+#ifdef SIMULATE_VERSION_MAJOR
+  require += info_simulate_version[argc];
+#endif
+#if defined(__CRAYXE) || defined(__CRAYXC)
+  require += info_cray[argc];
+#endif
+  require += info_language_dialect_default[argc];
+  (void)argv;
+  return require;
+}
diff --git a/pepito/CMakeFiles/3.5.2/CompilerIdCXX/a.out b/pepito/CMakeFiles/3.5.2/CompilerIdCXX/a.out
new file mode 100755
index 0000000..49296d2
Binary files /dev/null and b/pepito/CMakeFiles/3.5.2/CompilerIdCXX/a.out differ
diff --git a/pepito/CMakeFiles/CMakeDirectoryInformation.cmake b/pepito/CMakeFiles/CMakeDirectoryInformation.cmake
new file mode 100644
index 0000000..c79b0bd
--- /dev/null
+++ b/pepito/CMakeFiles/CMakeDirectoryInformation.cmake
@@ -0,0 +1,16 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+# Relative path conversion top directories.
+set(CMAKE_RELATIVE_PATH_TOP_SOURCE "/home/qwebify/rendu/secu/2016_P3p1t0/pepito")
+set(CMAKE_RELATIVE_PATH_TOP_BINARY "/home/qwebify/rendu/secu/2016_P3p1t0/pepito")
+
+# Force unix paths in dependencies.
+set(CMAKE_FORCE_UNIX_PATHS 1)
+
+
+# The C and CXX include file regular expressions for this directory.
+set(CMAKE_C_INCLUDE_REGEX_SCAN "^.*$")
+set(CMAKE_C_INCLUDE_REGEX_COMPLAIN "^$")
+set(CMAKE_CXX_INCLUDE_REGEX_SCAN ${CMAKE_C_INCLUDE_REGEX_SCAN})
+set(CMAKE_CXX_INCLUDE_REGEX_COMPLAIN ${CMAKE_C_INCLUDE_REGEX_COMPLAIN})
diff --git a/pepito/CMakeFiles/CMakeOutput.log b/pepito/CMakeFiles/CMakeOutput.log
new file mode 100644
index 0000000..7f934b1
--- /dev/null
+++ b/pepito/CMakeFiles/CMakeOutput.log
@@ -0,0 +1,538 @@
+The system is: Linux - 4.5.2-1-ARCH - x86_64
+Compiling the C compiler identification source file "CMakeCCompilerId.c" succeeded.
+Compiler: /usr/bin/cc 
+Build flags: 
+Id flags: 
+
+The output was:
+0
+
+
+Compilation of the C compiler identification source "CMakeCCompilerId.c" produced "a.out"
+
+The C compiler identification is GNU, found in "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/3.5.2/CompilerIdC/a.out"
+
+Compiling the CXX compiler identification source file "CMakeCXXCompilerId.cpp" succeeded.
+Compiler: /usr/bin/c++ 
+Build flags: 
+Id flags: 
+
+The output was:
+0
+
+
+Compilation of the CXX compiler identification source "CMakeCXXCompilerId.cpp" produced "a.out"
+
+The CXX compiler identification is GNU, found in "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/3.5.2/CompilerIdCXX/a.out"
+
+Determining if the C compiler works passed with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_fb910/fast"
+/usr/bin/make -f CMakeFiles/cmTC_fb910.dir/build.make CMakeFiles/cmTC_fb910.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building C object CMakeFiles/cmTC_fb910.dir/testCCompiler.c.o
+/usr/bin/cc     -o CMakeFiles/cmTC_fb910.dir/testCCompiler.c.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp/testCCompiler.c
+Linking C executable cmTC_fb910
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_fb910.dir/link.txt --verbose=1
+/usr/bin/cc       CMakeFiles/cmTC_fb910.dir/testCCompiler.c.o  -o cmTC_fb910 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+Detecting C compiler ABI info compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_7128a/fast"
+/usr/bin/make -f CMakeFiles/cmTC_7128a.dir/build.make CMakeFiles/cmTC_7128a.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building C object CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o
+/usr/bin/cc     -o CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o   -c /usr/share/cmake-3.5/Modules/CMakeCCompilerABI.c
+Linking C executable cmTC_7128a
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_7128a.dir/link.txt --verbose=1
+/usr/bin/cc      -v CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o  -o cmTC_7128a -rdynamic  
+Utilisation des specs internes.
+COLLECT_GCC=/usr/bin/cc
+COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper
+Cible : x86_64-pc-linux-gnu
+Configuré avec: /build/gcc/src/gcc/configure --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++ --enable-shared --enable-threads=posix --enable-libmpx --with-system-zlib --with-isl --enable-__cxa_atexit --disable-libunwind-exceptions --enable-clocale=gnu --disable-libstdcxx-pch --disable-libssp --enable-gnu-unique-object --enable-linker-build-id --enable-lto --enable-plugin --enable-install-libiberty --with-linker-hash-style=gnu --enable-gnu-indirect-function --disable-multilib --disable-werror --enable-checking=release
+Modèle de thread: posix
+gcc version 6.1.1 20160501 (GCC) 
+COMPILER_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/
+LIBRARY_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/:/lib/../lib/:/usr/lib/../lib/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../:/lib/:/usr/lib/
+COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_7128a' '-rdynamic' '-mtune=generic' '-march=x86-64'
+ /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2 -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper -plugin-opt=-fresolution=/tmp/ccGkeC7w.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -export-dynamic -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o cmTC_7128a /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1 -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../.. CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o
+COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_7128a' '-rdynamic' '-mtune=generic' '-march=x86-64'
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+Parsed C implicit link information from above output:
+  link line regex: [^( *|.*[/\])(ld|([^/\]+-)?ld|collect2)[^/\]*( |$)]
+  ignore line: [Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp]
+  ignore line: []
+  ignore line: [Run Build Command:"/usr/bin/make" "cmTC_7128a/fast"]
+  ignore line: [/usr/bin/make -f CMakeFiles/cmTC_7128a.dir/build.make CMakeFiles/cmTC_7128a.dir/build]
+  ignore line: [make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »]
+  ignore line: [Building C object CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o]
+  ignore line: [/usr/bin/cc     -o CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o   -c /usr/share/cmake-3.5/Modules/CMakeCCompilerABI.c]
+  ignore line: [Linking C executable cmTC_7128a]
+  ignore line: [/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_7128a.dir/link.txt --verbose=1]
+  ignore line: [/usr/bin/cc      -v CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o  -o cmTC_7128a -rdynamic  ]
+  ignore line: [Utilisation des specs internes.]
+  ignore line: [COLLECT_GCC=/usr/bin/cc]
+  ignore line: [COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper]
+  ignore line: [Cible : x86_64-pc-linux-gnu]
+  ignore line: [Configuré avec: /build/gcc/src/gcc/configure --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++ --enable-shared --enable-threads=posix --enable-libmpx --with-system-zlib --with-isl --enable-__cxa_atexit --disable-libunwind-exceptions --enable-clocale=gnu --disable-libstdcxx-pch --disable-libssp --enable-gnu-unique-object --enable-linker-build-id --enable-lto --enable-plugin --enable-install-libiberty --with-linker-hash-style=gnu --enable-gnu-indirect-function --disable-multilib --disable-werror --enable-checking=release]
+  ignore line: [Modèle de thread: posix]
+  ignore line: [gcc version 6.1.1 20160501 (GCC) ]
+  ignore line: [COMPILER_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/]
+  ignore line: [LIBRARY_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/:/lib/../lib/:/usr/lib/../lib/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../:/lib/:/usr/lib/]
+  ignore line: [COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_7128a' '-rdynamic' '-mtune=generic' '-march=x86-64']
+  link line: [ /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2 -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper -plugin-opt=-fresolution=/tmp/ccGkeC7w.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -export-dynamic -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o cmTC_7128a /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1 -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../.. CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o]
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2] ==> ignore
+    arg [-plugin] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so] ==> ignore
+    arg [-plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper] ==> ignore
+    arg [-plugin-opt=-fresolution=/tmp/ccGkeC7w.res] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc_s] ==> ignore
+    arg [-plugin-opt=-pass-through=-lc] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc_s] ==> ignore
+    arg [--build-id] ==> ignore
+    arg [--eh-frame-hdr] ==> ignore
+    arg [--hash-style=gnu] ==> ignore
+    arg [-m] ==> ignore
+    arg [elf_x86_64] ==> ignore
+    arg [-export-dynamic] ==> ignore
+    arg [-dynamic-linker] ==> ignore
+    arg [/lib64/ld-linux-x86-64.so.2] ==> ignore
+    arg [-o] ==> ignore
+    arg [cmTC_7128a] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o] ==> ignore
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1]
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib]
+    arg [-L/lib/../lib] ==> dir [/lib/../lib]
+    arg [-L/usr/lib/../lib] ==> dir [/usr/lib/../lib]
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..]
+    arg [CMakeFiles/cmTC_7128a.dir/CMakeCCompilerABI.c.o] ==> ignore
+    arg [-lgcc] ==> lib [gcc]
+    arg [--as-needed] ==> ignore
+    arg [-lgcc_s] ==> lib [gcc_s]
+    arg [--no-as-needed] ==> ignore
+    arg [-lc] ==> lib [c]
+    arg [-lgcc] ==> lib [gcc]
+    arg [--as-needed] ==> ignore
+    arg [-lgcc_s] ==> lib [gcc_s]
+    arg [--no-as-needed] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o] ==> ignore
+  remove lib [gcc]
+  remove lib [gcc_s]
+  remove lib [gcc]
+  remove lib [gcc_s]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1] ==> [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib] ==> [/usr/lib]
+  collapse library dir [/lib/../lib] ==> [/lib]
+  collapse library dir [/usr/lib/../lib] ==> [/usr/lib]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..] ==> [/usr/lib]
+  implicit libs: [c]
+  implicit dirs: [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1;/usr/lib;/lib]
+  implicit fwks: []
+
+
+
+
+Detecting C [-std=c11] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_51880/fast"
+/usr/bin/make -f CMakeFiles/cmTC_51880.dir/build.make CMakeFiles/cmTC_51880.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building C object CMakeFiles/cmTC_51880.dir/feature_tests.c.o
+/usr/bin/cc    -std=c11 -o CMakeFiles/cmTC_51880.dir/feature_tests.c.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.c
+Linking C executable cmTC_51880
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_51880.dir/link.txt --verbose=1
+/usr/bin/cc       CMakeFiles/cmTC_51880.dir/feature_tests.c.o  -o cmTC_51880 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: C_FEATURE:1c_function_prototypes
+    Feature record: C_FEATURE:1c_restrict
+    Feature record: C_FEATURE:1c_static_assert
+    Feature record: C_FEATURE:1c_variadic_macros
+
+
+Detecting C [-std=c99] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_07da4/fast"
+/usr/bin/make -f CMakeFiles/cmTC_07da4.dir/build.make CMakeFiles/cmTC_07da4.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building C object CMakeFiles/cmTC_07da4.dir/feature_tests.c.o
+/usr/bin/cc    -std=c99 -o CMakeFiles/cmTC_07da4.dir/feature_tests.c.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.c
+Linking C executable cmTC_07da4
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_07da4.dir/link.txt --verbose=1
+/usr/bin/cc       CMakeFiles/cmTC_07da4.dir/feature_tests.c.o  -o cmTC_07da4 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: C_FEATURE:1c_function_prototypes
+    Feature record: C_FEATURE:1c_restrict
+    Feature record: C_FEATURE:0c_static_assert
+    Feature record: C_FEATURE:1c_variadic_macros
+
+
+Detecting C [-std=c90] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_528b2/fast"
+/usr/bin/make -f CMakeFiles/cmTC_528b2.dir/build.make CMakeFiles/cmTC_528b2.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building C object CMakeFiles/cmTC_528b2.dir/feature_tests.c.o
+/usr/bin/cc    -std=c90 -o CMakeFiles/cmTC_528b2.dir/feature_tests.c.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.c
+Linking C executable cmTC_528b2
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_528b2.dir/link.txt --verbose=1
+/usr/bin/cc       CMakeFiles/cmTC_528b2.dir/feature_tests.c.o  -o cmTC_528b2 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: C_FEATURE:1c_function_prototypes
+    Feature record: C_FEATURE:0c_restrict
+    Feature record: C_FEATURE:0c_static_assert
+    Feature record: C_FEATURE:0c_variadic_macros
+Determining if the CXX compiler works passed with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_4ad32/fast"
+/usr/bin/make -f CMakeFiles/cmTC_4ad32.dir/build.make CMakeFiles/cmTC_4ad32.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building CXX object CMakeFiles/cmTC_4ad32.dir/testCXXCompiler.cxx.o
+/usr/bin/c++      -o CMakeFiles/cmTC_4ad32.dir/testCXXCompiler.cxx.o -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp/testCXXCompiler.cxx
+Linking CXX executable cmTC_4ad32
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_4ad32.dir/link.txt --verbose=1
+/usr/bin/c++        CMakeFiles/cmTC_4ad32.dir/testCXXCompiler.cxx.o  -o cmTC_4ad32 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+Detecting CXX compiler ABI info compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_b95ce/fast"
+/usr/bin/make -f CMakeFiles/cmTC_b95ce.dir/build.make CMakeFiles/cmTC_b95ce.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building CXX object CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o
+/usr/bin/c++      -o CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o -c /usr/share/cmake-3.5/Modules/CMakeCXXCompilerABI.cpp
+Linking CXX executable cmTC_b95ce
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_b95ce.dir/link.txt --verbose=1
+/usr/bin/c++       -v CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o  -o cmTC_b95ce -rdynamic  
+Utilisation des specs internes.
+COLLECT_GCC=/usr/bin/c++
+COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper
+Cible : x86_64-pc-linux-gnu
+Configuré avec: /build/gcc/src/gcc/configure --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++ --enable-shared --enable-threads=posix --enable-libmpx --with-system-zlib --with-isl --enable-__cxa_atexit --disable-libunwind-exceptions --enable-clocale=gnu --disable-libstdcxx-pch --disable-libssp --enable-gnu-unique-object --enable-linker-build-id --enable-lto --enable-plugin --enable-install-libiberty --with-linker-hash-style=gnu --enable-gnu-indirect-function --disable-multilib --disable-werror --enable-checking=release
+Modèle de thread: posix
+gcc version 6.1.1 20160501 (GCC) 
+COMPILER_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/
+LIBRARY_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/:/lib/../lib/:/usr/lib/../lib/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../:/lib/:/usr/lib/
+COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_b95ce' '-rdynamic' '-shared-libgcc' '-mtune=generic' '-march=x86-64'
+ /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2 -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper -plugin-opt=-fresolution=/tmp/ccLHoZ30.res -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lgcc --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -export-dynamic -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o cmTC_b95ce /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1 -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../.. CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o -lstdc++ -lm -lgcc_s -lgcc -lc -lgcc_s -lgcc /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o
+COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_b95ce' '-rdynamic' '-shared-libgcc' '-mtune=generic' '-march=x86-64'
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+Parsed CXX implicit link information from above output:
+  link line regex: [^( *|.*[/\])(ld|([^/\]+-)?ld|collect2)[^/\]*( |$)]
+  ignore line: [Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp]
+  ignore line: []
+  ignore line: [Run Build Command:"/usr/bin/make" "cmTC_b95ce/fast"]
+  ignore line: [/usr/bin/make -f CMakeFiles/cmTC_b95ce.dir/build.make CMakeFiles/cmTC_b95ce.dir/build]
+  ignore line: [make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »]
+  ignore line: [Building CXX object CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o]
+  ignore line: [/usr/bin/c++      -o CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o -c /usr/share/cmake-3.5/Modules/CMakeCXXCompilerABI.cpp]
+  ignore line: [Linking CXX executable cmTC_b95ce]
+  ignore line: [/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_b95ce.dir/link.txt --verbose=1]
+  ignore line: [/usr/bin/c++       -v CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o  -o cmTC_b95ce -rdynamic  ]
+  ignore line: [Utilisation des specs internes.]
+  ignore line: [COLLECT_GCC=/usr/bin/c++]
+  ignore line: [COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper]
+  ignore line: [Cible : x86_64-pc-linux-gnu]
+  ignore line: [Configuré avec: /build/gcc/src/gcc/configure --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++ --enable-shared --enable-threads=posix --enable-libmpx --with-system-zlib --with-isl --enable-__cxa_atexit --disable-libunwind-exceptions --enable-clocale=gnu --disable-libstdcxx-pch --disable-libssp --enable-gnu-unique-object --enable-linker-build-id --enable-lto --enable-plugin --enable-install-libiberty --with-linker-hash-style=gnu --enable-gnu-indirect-function --disable-multilib --disable-werror --enable-checking=release]
+  ignore line: [Modèle de thread: posix]
+  ignore line: [gcc version 6.1.1 20160501 (GCC) ]
+  ignore line: [COMPILER_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/]
+  ignore line: [LIBRARY_PATH=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/:/lib/../lib/:/usr/lib/../lib/:/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../:/lib/:/usr/lib/]
+  ignore line: [COLLECT_GCC_OPTIONS='-v' '-o' 'cmTC_b95ce' '-rdynamic' '-shared-libgcc' '-mtune=generic' '-march=x86-64']
+  link line: [ /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2 -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper -plugin-opt=-fresolution=/tmp/ccLHoZ30.res -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lgcc --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -export-dynamic -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o cmTC_b95ce /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1 -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../.. CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o -lstdc++ -lm -lgcc_s -lgcc -lc -lgcc_s -lgcc /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o /usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o]
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/collect2] ==> ignore
+    arg [-plugin] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/liblto_plugin.so] ==> ignore
+    arg [-plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/lto-wrapper] ==> ignore
+    arg [-plugin-opt=-fresolution=/tmp/ccLHoZ30.res] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc_s] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc] ==> ignore
+    arg [-plugin-opt=-pass-through=-lc] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc_s] ==> ignore
+    arg [-plugin-opt=-pass-through=-lgcc] ==> ignore
+    arg [--build-id] ==> ignore
+    arg [--eh-frame-hdr] ==> ignore
+    arg [--hash-style=gnu] ==> ignore
+    arg [-m] ==> ignore
+    arg [elf_x86_64] ==> ignore
+    arg [-export-dynamic] ==> ignore
+    arg [-dynamic-linker] ==> ignore
+    arg [/lib64/ld-linux-x86-64.so.2] ==> ignore
+    arg [-o] ==> ignore
+    arg [cmTC_b95ce] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crt1.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crti.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtbegin.o] ==> ignore
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1]
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib]
+    arg [-L/lib/../lib] ==> dir [/lib/../lib]
+    arg [-L/usr/lib/../lib] ==> dir [/usr/lib/../lib]
+    arg [-L/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..] ==> dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..]
+    arg [CMakeFiles/cmTC_b95ce.dir/CMakeCXXCompilerABI.cpp.o] ==> ignore
+    arg [-lstdc++] ==> lib [stdc++]
+    arg [-lm] ==> lib [m]
+    arg [-lgcc_s] ==> lib [gcc_s]
+    arg [-lgcc] ==> lib [gcc]
+    arg [-lc] ==> lib [c]
+    arg [-lgcc_s] ==> lib [gcc_s]
+    arg [-lgcc] ==> lib [gcc]
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/crtend.o] ==> ignore
+    arg [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib/crtn.o] ==> ignore
+  remove lib [gcc_s]
+  remove lib [gcc]
+  remove lib [gcc_s]
+  remove lib [gcc]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1] ==> [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../../../lib] ==> [/usr/lib]
+  collapse library dir [/lib/../lib] ==> [/lib]
+  collapse library dir [/usr/lib/../lib] ==> [/usr/lib]
+  collapse library dir [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1/../../..] ==> [/usr/lib]
+  implicit libs: [stdc++;m;c]
+  implicit dirs: [/usr/lib/gcc/x86_64-pc-linux-gnu/6.1.1;/usr/lib;/lib]
+  implicit fwks: []
+
+
+
+
+Detecting CXX [-std=c++14] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_c4e64/fast"
+/usr/bin/make -f CMakeFiles/cmTC_c4e64.dir/build.make CMakeFiles/cmTC_c4e64.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building CXX object CMakeFiles/cmTC_c4e64.dir/feature_tests.cxx.o
+/usr/bin/c++     -std=c++14 -o CMakeFiles/cmTC_c4e64.dir/feature_tests.cxx.o -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.cxx
+Linking CXX executable cmTC_c4e64
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_c4e64.dir/link.txt --verbose=1
+/usr/bin/c++        CMakeFiles/cmTC_c4e64.dir/feature_tests.cxx.o  -o cmTC_c4e64 -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: CXX_FEATURE:1cxx_aggregate_default_initializers
+    Feature record: CXX_FEATURE:1cxx_alias_templates
+    Feature record: CXX_FEATURE:1cxx_alignas
+    Feature record: CXX_FEATURE:1cxx_alignof
+    Feature record: CXX_FEATURE:1cxx_attributes
+    Feature record: CXX_FEATURE:1cxx_attribute_deprecated
+    Feature record: CXX_FEATURE:1cxx_auto_type
+    Feature record: CXX_FEATURE:1cxx_binary_literals
+    Feature record: CXX_FEATURE:1cxx_constexpr
+    Feature record: CXX_FEATURE:1cxx_contextual_conversions
+    Feature record: CXX_FEATURE:1cxx_decltype
+    Feature record: CXX_FEATURE:1cxx_decltype_auto
+    Feature record: CXX_FEATURE:1cxx_decltype_incomplete_return_types
+    Feature record: CXX_FEATURE:1cxx_default_function_template_args
+    Feature record: CXX_FEATURE:1cxx_defaulted_functions
+    Feature record: CXX_FEATURE:1cxx_defaulted_move_initializers
+    Feature record: CXX_FEATURE:1cxx_delegating_constructors
+    Feature record: CXX_FEATURE:1cxx_deleted_functions
+    Feature record: CXX_FEATURE:1cxx_digit_separators
+    Feature record: CXX_FEATURE:1cxx_enum_forward_declarations
+    Feature record: CXX_FEATURE:1cxx_explicit_conversions
+    Feature record: CXX_FEATURE:1cxx_extended_friend_declarations
+    Feature record: CXX_FEATURE:1cxx_extern_templates
+    Feature record: CXX_FEATURE:1cxx_final
+    Feature record: CXX_FEATURE:1cxx_func_identifier
+    Feature record: CXX_FEATURE:1cxx_generalized_initializers
+    Feature record: CXX_FEATURE:1cxx_generic_lambdas
+    Feature record: CXX_FEATURE:1cxx_inheriting_constructors
+    Feature record: CXX_FEATURE:1cxx_inline_namespaces
+    Feature record: CXX_FEATURE:1cxx_lambdas
+    Feature record: CXX_FEATURE:1cxx_lambda_init_captures
+    Feature record: CXX_FEATURE:1cxx_local_type_template_args
+    Feature record: CXX_FEATURE:1cxx_long_long_type
+    Feature record: CXX_FEATURE:1cxx_noexcept
+    Feature record: CXX_FEATURE:1cxx_nonstatic_member_init
+    Feature record: CXX_FEATURE:1cxx_nullptr
+    Feature record: CXX_FEATURE:1cxx_override
+    Feature record: CXX_FEATURE:1cxx_range_for
+    Feature record: CXX_FEATURE:1cxx_raw_string_literals
+    Feature record: CXX_FEATURE:1cxx_reference_qualified_functions
+    Feature record: CXX_FEATURE:1cxx_relaxed_constexpr
+    Feature record: CXX_FEATURE:1cxx_return_type_deduction
+    Feature record: CXX_FEATURE:1cxx_right_angle_brackets
+    Feature record: CXX_FEATURE:1cxx_rvalue_references
+    Feature record: CXX_FEATURE:1cxx_sizeof_member
+    Feature record: CXX_FEATURE:1cxx_static_assert
+    Feature record: CXX_FEATURE:1cxx_strong_enums
+    Feature record: CXX_FEATURE:1cxx_template_template_parameters
+    Feature record: CXX_FEATURE:1cxx_thread_local
+    Feature record: CXX_FEATURE:1cxx_trailing_return_types
+    Feature record: CXX_FEATURE:1cxx_unicode_literals
+    Feature record: CXX_FEATURE:1cxx_uniform_initialization
+    Feature record: CXX_FEATURE:1cxx_unrestricted_unions
+    Feature record: CXX_FEATURE:1cxx_user_literals
+    Feature record: CXX_FEATURE:1cxx_variable_templates
+    Feature record: CXX_FEATURE:1cxx_variadic_macros
+    Feature record: CXX_FEATURE:1cxx_variadic_templates
+
+
+Detecting CXX [-std=c++11] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_0b75a/fast"
+/usr/bin/make -f CMakeFiles/cmTC_0b75a.dir/build.make CMakeFiles/cmTC_0b75a.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building CXX object CMakeFiles/cmTC_0b75a.dir/feature_tests.cxx.o
+/usr/bin/c++     -std=c++11 -o CMakeFiles/cmTC_0b75a.dir/feature_tests.cxx.o -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.cxx
+Linking CXX executable cmTC_0b75a
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_0b75a.dir/link.txt --verbose=1
+/usr/bin/c++        CMakeFiles/cmTC_0b75a.dir/feature_tests.cxx.o  -o cmTC_0b75a -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: CXX_FEATURE:0cxx_aggregate_default_initializers
+    Feature record: CXX_FEATURE:1cxx_alias_templates
+    Feature record: CXX_FEATURE:1cxx_alignas
+    Feature record: CXX_FEATURE:1cxx_alignof
+    Feature record: CXX_FEATURE:1cxx_attributes
+    Feature record: CXX_FEATURE:0cxx_attribute_deprecated
+    Feature record: CXX_FEATURE:1cxx_auto_type
+    Feature record: CXX_FEATURE:0cxx_binary_literals
+    Feature record: CXX_FEATURE:1cxx_constexpr
+    Feature record: CXX_FEATURE:0cxx_contextual_conversions
+    Feature record: CXX_FEATURE:1cxx_decltype
+    Feature record: CXX_FEATURE:0cxx_decltype_auto
+    Feature record: CXX_FEATURE:1cxx_decltype_incomplete_return_types
+    Feature record: CXX_FEATURE:1cxx_default_function_template_args
+    Feature record: CXX_FEATURE:1cxx_defaulted_functions
+    Feature record: CXX_FEATURE:1cxx_defaulted_move_initializers
+    Feature record: CXX_FEATURE:1cxx_delegating_constructors
+    Feature record: CXX_FEATURE:1cxx_deleted_functions
+    Feature record: CXX_FEATURE:0cxx_digit_separators
+    Feature record: CXX_FEATURE:1cxx_enum_forward_declarations
+    Feature record: CXX_FEATURE:1cxx_explicit_conversions
+    Feature record: CXX_FEATURE:1cxx_extended_friend_declarations
+    Feature record: CXX_FEATURE:1cxx_extern_templates
+    Feature record: CXX_FEATURE:1cxx_final
+    Feature record: CXX_FEATURE:1cxx_func_identifier
+    Feature record: CXX_FEATURE:1cxx_generalized_initializers
+    Feature record: CXX_FEATURE:0cxx_generic_lambdas
+    Feature record: CXX_FEATURE:1cxx_inheriting_constructors
+    Feature record: CXX_FEATURE:1cxx_inline_namespaces
+    Feature record: CXX_FEATURE:1cxx_lambdas
+    Feature record: CXX_FEATURE:0cxx_lambda_init_captures
+    Feature record: CXX_FEATURE:1cxx_local_type_template_args
+    Feature record: CXX_FEATURE:1cxx_long_long_type
+    Feature record: CXX_FEATURE:1cxx_noexcept
+    Feature record: CXX_FEATURE:1cxx_nonstatic_member_init
+    Feature record: CXX_FEATURE:1cxx_nullptr
+    Feature record: CXX_FEATURE:1cxx_override
+    Feature record: CXX_FEATURE:1cxx_range_for
+    Feature record: CXX_FEATURE:1cxx_raw_string_literals
+    Feature record: CXX_FEATURE:1cxx_reference_qualified_functions
+    Feature record: CXX_FEATURE:0cxx_relaxed_constexpr
+    Feature record: CXX_FEATURE:0cxx_return_type_deduction
+    Feature record: CXX_FEATURE:1cxx_right_angle_brackets
+    Feature record: CXX_FEATURE:1cxx_rvalue_references
+    Feature record: CXX_FEATURE:1cxx_sizeof_member
+    Feature record: CXX_FEATURE:1cxx_static_assert
+    Feature record: CXX_FEATURE:1cxx_strong_enums
+    Feature record: CXX_FEATURE:1cxx_template_template_parameters
+    Feature record: CXX_FEATURE:1cxx_thread_local
+    Feature record: CXX_FEATURE:1cxx_trailing_return_types
+    Feature record: CXX_FEATURE:1cxx_unicode_literals
+    Feature record: CXX_FEATURE:1cxx_uniform_initialization
+    Feature record: CXX_FEATURE:1cxx_unrestricted_unions
+    Feature record: CXX_FEATURE:1cxx_user_literals
+    Feature record: CXX_FEATURE:0cxx_variable_templates
+    Feature record: CXX_FEATURE:1cxx_variadic_macros
+    Feature record: CXX_FEATURE:1cxx_variadic_templates
+
+
+Detecting CXX [-std=c++98] compiler features compiled with the following output:
+Change Dir: /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp
+
+Run Build Command:"/usr/bin/make" "cmTC_624ba/fast"
+/usr/bin/make -f CMakeFiles/cmTC_624ba.dir/build.make CMakeFiles/cmTC_624ba.dir/build
+make[1] : on entre dans le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+Building CXX object CMakeFiles/cmTC_624ba.dir/feature_tests.cxx.o
+/usr/bin/c++     -std=c++98 -o CMakeFiles/cmTC_624ba.dir/feature_tests.cxx.o -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/feature_tests.cxx
+Linking CXX executable cmTC_624ba
+/usr/bin/cmake -E cmake_link_script CMakeFiles/cmTC_624ba.dir/link.txt --verbose=1
+/usr/bin/c++        CMakeFiles/cmTC_624ba.dir/feature_tests.cxx.o  -o cmTC_624ba -rdynamic 
+make[1] : on quitte le répertoire « /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/CMakeTmp »
+
+
+    Feature record: CXX_FEATURE:0cxx_aggregate_default_initializers
+    Feature record: CXX_FEATURE:0cxx_alias_templates
+    Feature record: CXX_FEATURE:0cxx_alignas
+    Feature record: CXX_FEATURE:0cxx_alignof
+    Feature record: CXX_FEATURE:0cxx_attributes
+    Feature record: CXX_FEATURE:0cxx_attribute_deprecated
+    Feature record: CXX_FEATURE:0cxx_auto_type
+    Feature record: CXX_FEATURE:0cxx_binary_literals
+    Feature record: CXX_FEATURE:0cxx_constexpr
+    Feature record: CXX_FEATURE:0cxx_contextual_conversions
+    Feature record: CXX_FEATURE:0cxx_decltype
+    Feature record: CXX_FEATURE:0cxx_decltype_auto
+    Feature record: CXX_FEATURE:0cxx_decltype_incomplete_return_types
+    Feature record: CXX_FEATURE:0cxx_default_function_template_args
+    Feature record: CXX_FEATURE:0cxx_defaulted_functions
+    Feature record: CXX_FEATURE:0cxx_defaulted_move_initializers
+    Feature record: CXX_FEATURE:0cxx_delegating_constructors
+    Feature record: CXX_FEATURE:0cxx_deleted_functions
+    Feature record: CXX_FEATURE:0cxx_digit_separators
+    Feature record: CXX_FEATURE:0cxx_enum_forward_declarations
+    Feature record: CXX_FEATURE:0cxx_explicit_conversions
+    Feature record: CXX_FEATURE:0cxx_extended_friend_declarations
+    Feature record: CXX_FEATURE:0cxx_extern_templates
+    Feature record: CXX_FEATURE:0cxx_final
+    Feature record: CXX_FEATURE:0cxx_func_identifier
+    Feature record: CXX_FEATURE:0cxx_generalized_initializers
+    Feature record: CXX_FEATURE:0cxx_generic_lambdas
+    Feature record: CXX_FEATURE:0cxx_inheriting_constructors
+    Feature record: CXX_FEATURE:0cxx_inline_namespaces
+    Feature record: CXX_FEATURE:0cxx_lambdas
+    Feature record: CXX_FEATURE:0cxx_lambda_init_captures
+    Feature record: CXX_FEATURE:0cxx_local_type_template_args
+    Feature record: CXX_FEATURE:0cxx_long_long_type
+    Feature record: CXX_FEATURE:0cxx_noexcept
+    Feature record: CXX_FEATURE:0cxx_nonstatic_member_init
+    Feature record: CXX_FEATURE:0cxx_nullptr
+    Feature record: CXX_FEATURE:0cxx_override
+    Feature record: CXX_FEATURE:0cxx_range_for
+    Feature record: CXX_FEATURE:0cxx_raw_string_literals
+    Feature record: CXX_FEATURE:0cxx_reference_qualified_functions
+    Feature record: CXX_FEATURE:0cxx_relaxed_constexpr
+    Feature record: CXX_FEATURE:0cxx_return_type_deduction
+    Feature record: CXX_FEATURE:0cxx_right_angle_brackets
+    Feature record: CXX_FEATURE:0cxx_rvalue_references
+    Feature record: CXX_FEATURE:0cxx_sizeof_member
+    Feature record: CXX_FEATURE:0cxx_static_assert
+    Feature record: CXX_FEATURE:0cxx_strong_enums
+    Feature record: CXX_FEATURE:1cxx_template_template_parameters
+    Feature record: CXX_FEATURE:0cxx_thread_local
+    Feature record: CXX_FEATURE:0cxx_trailing_return_types
+    Feature record: CXX_FEATURE:0cxx_unicode_literals
+    Feature record: CXX_FEATURE:0cxx_uniform_initialization
+    Feature record: CXX_FEATURE:0cxx_unrestricted_unions
+    Feature record: CXX_FEATURE:0cxx_user_literals
+    Feature record: CXX_FEATURE:0cxx_variable_templates
+    Feature record: CXX_FEATURE:0cxx_variadic_macros
+    Feature record: CXX_FEATURE:0cxx_variadic_templates
diff --git a/pepito/CMakeFiles/Makefile.cmake b/pepito/CMakeFiles/Makefile.cmake
new file mode 100644
index 0000000..16acf24
--- /dev/null
+++ b/pepito/CMakeFiles/Makefile.cmake
@@ -0,0 +1,45 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+# The generator used is:
+set(CMAKE_DEPENDS_GENERATOR "Unix Makefiles")
+
+# The top level Makefile was generated from the following files:
+set(CMAKE_MAKEFILE_DEPENDS
+  "CMakeCache.txt"
+  "CMakeFiles/3.5.2/CMakeCCompiler.cmake"
+  "CMakeFiles/3.5.2/CMakeCXXCompiler.cmake"
+  "CMakeFiles/3.5.2/CMakeSystem.cmake"
+  "CMakeLists.txt"
+  "/usr/share/cmake-3.5/Modules/CMakeCInformation.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeCXXInformation.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeCommonLanguageInclude.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeGenericSystem.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeLanguageInformation.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeSystemSpecificInformation.cmake"
+  "/usr/share/cmake-3.5/Modules/CMakeSystemSpecificInitialize.cmake"
+  "/usr/share/cmake-3.5/Modules/Compiler/GNU-C.cmake"
+  "/usr/share/cmake-3.5/Modules/Compiler/GNU-CXX.cmake"
+  "/usr/share/cmake-3.5/Modules/Compiler/GNU.cmake"
+  "/usr/share/cmake-3.5/Modules/Platform/Linux-GNU-C.cmake"
+  "/usr/share/cmake-3.5/Modules/Platform/Linux-GNU-CXX.cmake"
+  "/usr/share/cmake-3.5/Modules/Platform/Linux-GNU.cmake"
+  "/usr/share/cmake-3.5/Modules/Platform/Linux.cmake"
+  "/usr/share/cmake-3.5/Modules/Platform/UnixPaths.cmake"
+  )
+
+# The corresponding makefile is:
+set(CMAKE_MAKEFILE_OUTPUTS
+  "Makefile"
+  "CMakeFiles/cmake.check_cache"
+  )
+
+# Byproducts of CMake generate step:
+set(CMAKE_MAKEFILE_PRODUCTS
+  "CMakeFiles/CMakeDirectoryInformation.cmake"
+  )
+
+# Dependency information for all targets:
+set(CMAKE_DEPEND_INFO_FILES
+  "CMakeFiles/pepito.dir/DependInfo.cmake"
+  )
diff --git a/pepito/CMakeFiles/Makefile2 b/pepito/CMakeFiles/Makefile2
new file mode 100644
index 0000000..c83e791
--- /dev/null
+++ b/pepito/CMakeFiles/Makefile2
@@ -0,0 +1,108 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+# Default target executed when no arguments are given to make.
+default_target: all
+
+.PHONY : default_target
+
+# The main recursive all target
+all:
+
+.PHONY : all
+
+# The main recursive preinstall target
+preinstall:
+
+.PHONY : preinstall
+
+#=============================================================================
+# Special targets provided by cmake.
+
+# Disable implicit rules so canonical targets will work.
+.SUFFIXES:
+
+
+# Remove some rules from gmake that .SUFFIXES does not remove.
+SUFFIXES =
+
+.SUFFIXES: .hpux_make_needs_suffix_list
+
+
+# Suppress display of executed commands.
+$(VERBOSE).SILENT:
+
+
+# A target that is always out of date.
+cmake_force:
+
+.PHONY : cmake_force
+
+#=============================================================================
+# Set environment variables for the build.
+
+# The shell in which to execute make rules.
+SHELL = /bin/sh
+
+# The CMake executable.
+CMAKE_COMMAND = /usr/bin/cmake
+
+# The command to remove a file.
+RM = /usr/bin/cmake -E remove -f
+
+# Escaping for special characters.
+EQUALS = =
+
+# The top-level source directory on which CMake was run.
+CMAKE_SOURCE_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+# The top-level build directory on which CMake was run.
+CMAKE_BINARY_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+#=============================================================================
+# Target rules for target CMakeFiles/pepito.dir
+
+# All Build rule for target.
+CMakeFiles/pepito.dir/all:
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/depend
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/build
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=1,2,3,4,5 "Built target pepito"
+.PHONY : CMakeFiles/pepito.dir/all
+
+# Include target in all.
+all: CMakeFiles/pepito.dir/all
+
+.PHONY : all
+
+# Build rule for subdir invocation for target.
+CMakeFiles/pepito.dir/rule: cmake_check_build_system
+	$(CMAKE_COMMAND) -E cmake_progress_start /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles 5
+	$(MAKE) -f CMakeFiles/Makefile2 CMakeFiles/pepito.dir/all
+	$(CMAKE_COMMAND) -E cmake_progress_start /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles 0
+.PHONY : CMakeFiles/pepito.dir/rule
+
+# Convenience name for target.
+pepito: CMakeFiles/pepito.dir/rule
+
+.PHONY : pepito
+
+# clean rule for target.
+CMakeFiles/pepito.dir/clean:
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/clean
+.PHONY : CMakeFiles/pepito.dir/clean
+
+# clean rule for target.
+clean: CMakeFiles/pepito.dir/clean
+
+.PHONY : clean
+
+#=============================================================================
+# Special targets to cleanup operation of make.
+
+# Special rule to run CMake to check the build system integrity.
+# No rule that depends on this can have commands that come from listfiles
+# because they might be regenerated.
+cmake_check_build_system:
+	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
+.PHONY : cmake_check_build_system
+
diff --git a/pepito/CMakeFiles/TargetDirectories.txt b/pepito/CMakeFiles/TargetDirectories.txt
new file mode 100644
index 0000000..4d9e2a7
--- /dev/null
+++ b/pepito/CMakeFiles/TargetDirectories.txt
@@ -0,0 +1,7 @@
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/install.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/list_install_components.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/rebuild_cache.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/edit_cache.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/install/strip.dir
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/install/local.dir
diff --git a/pepito/CMakeFiles/cmake.check_cache b/pepito/CMakeFiles/cmake.check_cache
new file mode 100644
index 0000000..3dccd73
--- /dev/null
+++ b/pepito/CMakeFiles/cmake.check_cache
@@ -0,0 +1 @@
+# This file is generated by cmake for dependency checking of the CMakeCache.txt file
diff --git a/pepito/CMakeFiles/feature_tests.bin b/pepito/CMakeFiles/feature_tests.bin
new file mode 100755
index 0000000..e862e9e
Binary files /dev/null and b/pepito/CMakeFiles/feature_tests.bin differ
diff --git a/pepito/CMakeFiles/feature_tests.c b/pepito/CMakeFiles/feature_tests.c
new file mode 100644
index 0000000..6590dde
--- /dev/null
+++ b/pepito/CMakeFiles/feature_tests.c
@@ -0,0 +1,34 @@
+
+  const char features[] = {"\n"
+"C_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404
+"1"
+#else
+"0"
+#endif
+"c_function_prototypes\n"
+"C_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
+"1"
+#else
+"0"
+#endif
+"c_restrict\n"
+"C_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201000L
+"1"
+#else
+"0"
+#endif
+"c_static_assert\n"
+"C_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
+"1"
+#else
+"0"
+#endif
+"c_variadic_macros\n"
+
+};
+
+int main(int argc, char** argv) { (void)argv; return features[argc]; }
diff --git a/pepito/CMakeFiles/feature_tests.cxx b/pepito/CMakeFiles/feature_tests.cxx
new file mode 100644
index 0000000..b93418c
--- /dev/null
+++ b/pepito/CMakeFiles/feature_tests.cxx
@@ -0,0 +1,405 @@
+
+  const char features[] = {"\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 500 && __cplusplus >= 201402L
+"1"
+#else
+"0"
+#endif
+"cxx_aggregate_default_initializers\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_alias_templates\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 408 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_alignas\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 408 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_alignof\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 408 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_attributes\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_attribute_deprecated\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_auto_type\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_binary_literals\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_constexpr\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_contextual_conversions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_decltype\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_decltype_auto\n"
+"CXX_FEATURE:"
+#if ((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= 40801) && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_decltype_incomplete_return_types\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_default_function_template_args\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_defaulted_functions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_defaulted_move_initializers\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_delegating_constructors\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_deleted_functions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_digit_separators\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_enum_forward_declarations\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 405 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_explicit_conversions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_extended_friend_declarations\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_extern_templates\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_final\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_func_identifier\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_generalized_initializers\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_generic_lambdas\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 408 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_inheriting_constructors\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_inline_namespaces\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 405 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_lambdas\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_lambda_init_captures\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 405 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_local_type_template_args\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_long_long_type\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_noexcept\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_nonstatic_member_init\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_nullptr\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_override\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_range_for\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 405 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_raw_string_literals\n"
+"CXX_FEATURE:"
+#if ((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= 40801) && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_reference_qualified_functions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 500 && __cplusplus >= 201402L
+"1"
+#else
+"0"
+#endif
+"cxx_relaxed_constexpr\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 409 && __cplusplus > 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_return_type_deduction\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_right_angle_brackets\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_rvalue_references\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_sizeof_member\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_static_assert\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_strong_enums\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && __cplusplus
+"1"
+#else
+"0"
+#endif
+"cxx_template_template_parameters\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 408 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_thread_local\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_trailing_return_types\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_unicode_literals\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_uniform_initialization\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 406 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_unrestricted_unions\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 407 && __cplusplus >= 201103L
+"1"
+#else
+"0"
+#endif
+"cxx_user_literals\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 500 && __cplusplus >= 201402L
+"1"
+#else
+"0"
+#endif
+"cxx_variable_templates\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_variadic_macros\n"
+"CXX_FEATURE:"
+#if (__GNUC__ * 100 + __GNUC_MINOR__) >= 404 && (__cplusplus >= 201103L || (defined(__GXX_EXPERIMENTAL_CXX0X__) && __GXX_EXPERIMENTAL_CXX0X__))
+"1"
+#else
+"0"
+#endif
+"cxx_variadic_templates\n"
+
+};
+
+int main(int argc, char** argv) { (void)argv; return features[argc]; }
diff --git a/pepito/CMakeFiles/pepito.dir/C.includecache b/pepito/CMakeFiles/pepito.dir/C.includecache
new file mode 100644
index 0000000..4279e02
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/C.includecache
@@ -0,0 +1,112 @@
+#IncludeRegexLine: ^[ 	]*#[ 	]*(include|import)[ 	]*[<"]([^">]+)([">])
+
+#IncludeRegexScan: ^.*$
+
+#IncludeRegexComplain: ^$
+
+#IncludeRegexTransform: 
+
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c
+signal.h
+-
+stdio.h
+-
+stdlib.h
+-
+strings.h
+-
+unistd.h
+-
+sys/stat.h
+-
+pepito.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/pepito.h
+daemon.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.h
+network.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.h
+
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c
+stdio.h
+-
+stdlib.h
+-
+string.h
+-
+unistd.h
+-
+pepito.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/pepito.h
+network.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.h
+daemon.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.h
+utils.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.h
+recipes.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/recipes.h
+secret.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/secret.h
+supersecret.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/supersecret.h
+
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c
+unistd.h
+-
+stdio.h
+-
+string.h
+-
+sys/socket.h
+-
+sys/stat.h
+-
+sys/types.h
+-
+netinet/in.h
+-
+pepito.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/pepito.h
+network.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.h
+utils.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.h
+
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c
+fcntl.h
+-
+stdio.h
+-
+stdlib.h
+-
+string.h
+-
+unistd.h
+-
+pepito.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/pepito.h
+utils.h
+/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.h
+
+includes/daemon.h
+
+includes/network.h
+sys/socket.h
+-
+sys/stat.h
+-
+sys/types.h
+-
+netinet/in.h
+-
+
+includes/pepito.h
+
+includes/recipes.h
+
+includes/secret.h
+
+includes/supersecret.h
+
+includes/utils.h
+
diff --git a/pepito/CMakeFiles/pepito.dir/DependInfo.cmake b/pepito/CMakeFiles/pepito.dir/DependInfo.cmake
new file mode 100644
index 0000000..cee3493
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/DependInfo.cmake
@@ -0,0 +1,24 @@
+# The set of languages for which implicit dependencies are needed:
+set(CMAKE_DEPENDS_LANGUAGES
+  "C"
+  )
+# The set of files for implicit dependencies of each language:
+set(CMAKE_DEPENDS_CHECK_C
+  "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c" "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/src/daemon.o"
+  "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c" "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/src/main.o"
+  "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c" "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/src/network.o"
+  "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c" "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/src/utils.o"
+  )
+set(CMAKE_C_COMPILER_ID "GNU")
+
+# The include file search paths:
+set(CMAKE_C_TARGET_INCLUDE_PATH
+  "includes"
+  )
+
+# Targets to which this target links.
+set(CMAKE_TARGET_LINKED_INFO_FILES
+  )
+
+# Fortran module output directory.
+set(CMAKE_Fortran_TARGET_MODULE_DIR "")
diff --git a/pepito/CMakeFiles/pepito.dir/build.make b/pepito/CMakeFiles/pepito.dir/build.make
new file mode 100644
index 0000000..e323980
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/build.make
@@ -0,0 +1,196 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+# Delete rule output on recipe failure.
+.DELETE_ON_ERROR:
+
+
+#=============================================================================
+# Special targets provided by cmake.
+
+# Disable implicit rules so canonical targets will work.
+.SUFFIXES:
+
+
+# Remove some rules from gmake that .SUFFIXES does not remove.
+SUFFIXES =
+
+.SUFFIXES: .hpux_make_needs_suffix_list
+
+
+# Suppress display of executed commands.
+$(VERBOSE).SILENT:
+
+
+# A target that is always out of date.
+cmake_force:
+
+.PHONY : cmake_force
+
+#=============================================================================
+# Set environment variables for the build.
+
+# The shell in which to execute make rules.
+SHELL = /bin/sh
+
+# The CMake executable.
+CMAKE_COMMAND = /usr/bin/cmake
+
+# The command to remove a file.
+RM = /usr/bin/cmake -E remove -f
+
+# Escaping for special characters.
+EQUALS = =
+
+# The top-level source directory on which CMake was run.
+CMAKE_SOURCE_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+# The top-level build directory on which CMake was run.
+CMAKE_BINARY_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+# Include any dependencies generated for this target.
+include CMakeFiles/pepito.dir/depend.make
+
+# Include the progress variables for this target.
+include CMakeFiles/pepito.dir/progress.make
+
+# Include the compile flags for this target's objects.
+include CMakeFiles/pepito.dir/flags.make
+
+CMakeFiles/pepito.dir/src/daemon.o: CMakeFiles/pepito.dir/flags.make
+CMakeFiles/pepito.dir/src/daemon.o: src/daemon.c
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/pepito.dir/src/daemon.o"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/daemon.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c
+
+CMakeFiles/pepito.dir/src/daemon.i: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/daemon.i"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c > CMakeFiles/pepito.dir/src/daemon.i
+
+CMakeFiles/pepito.dir/src/daemon.s: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/daemon.s"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c -o CMakeFiles/pepito.dir/src/daemon.s
+
+CMakeFiles/pepito.dir/src/daemon.o.requires:
+
+.PHONY : CMakeFiles/pepito.dir/src/daemon.o.requires
+
+CMakeFiles/pepito.dir/src/daemon.o.provides: CMakeFiles/pepito.dir/src/daemon.o.requires
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/daemon.o.provides.build
+.PHONY : CMakeFiles/pepito.dir/src/daemon.o.provides
+
+CMakeFiles/pepito.dir/src/daemon.o.provides.build: CMakeFiles/pepito.dir/src/daemon.o
+
+
+CMakeFiles/pepito.dir/src/main.o: CMakeFiles/pepito.dir/flags.make
+CMakeFiles/pepito.dir/src/main.o: src/main.c
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/pepito.dir/src/main.o"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/main.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c
+
+CMakeFiles/pepito.dir/src/main.i: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/main.i"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c > CMakeFiles/pepito.dir/src/main.i
+
+CMakeFiles/pepito.dir/src/main.s: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/main.s"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c -o CMakeFiles/pepito.dir/src/main.s
+
+CMakeFiles/pepito.dir/src/main.o.requires:
+
+.PHONY : CMakeFiles/pepito.dir/src/main.o.requires
+
+CMakeFiles/pepito.dir/src/main.o.provides: CMakeFiles/pepito.dir/src/main.o.requires
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/main.o.provides.build
+.PHONY : CMakeFiles/pepito.dir/src/main.o.provides
+
+CMakeFiles/pepito.dir/src/main.o.provides.build: CMakeFiles/pepito.dir/src/main.o
+
+
+CMakeFiles/pepito.dir/src/network.o: CMakeFiles/pepito.dir/flags.make
+CMakeFiles/pepito.dir/src/network.o: src/network.c
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/pepito.dir/src/network.o"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/network.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c
+
+CMakeFiles/pepito.dir/src/network.i: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/network.i"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c > CMakeFiles/pepito.dir/src/network.i
+
+CMakeFiles/pepito.dir/src/network.s: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/network.s"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c -o CMakeFiles/pepito.dir/src/network.s
+
+CMakeFiles/pepito.dir/src/network.o.requires:
+
+.PHONY : CMakeFiles/pepito.dir/src/network.o.requires
+
+CMakeFiles/pepito.dir/src/network.o.provides: CMakeFiles/pepito.dir/src/network.o.requires
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/network.o.provides.build
+.PHONY : CMakeFiles/pepito.dir/src/network.o.provides
+
+CMakeFiles/pepito.dir/src/network.o.provides.build: CMakeFiles/pepito.dir/src/network.o
+
+
+CMakeFiles/pepito.dir/src/utils.o: CMakeFiles/pepito.dir/flags.make
+CMakeFiles/pepito.dir/src/utils.o: src/utils.c
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/pepito.dir/src/utils.o"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/utils.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c
+
+CMakeFiles/pepito.dir/src/utils.i: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/utils.i"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c > CMakeFiles/pepito.dir/src/utils.i
+
+CMakeFiles/pepito.dir/src/utils.s: cmake_force
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/utils.s"
+	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c -o CMakeFiles/pepito.dir/src/utils.s
+
+CMakeFiles/pepito.dir/src/utils.o.requires:
+
+.PHONY : CMakeFiles/pepito.dir/src/utils.o.requires
+
+CMakeFiles/pepito.dir/src/utils.o.provides: CMakeFiles/pepito.dir/src/utils.o.requires
+	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/utils.o.provides.build
+.PHONY : CMakeFiles/pepito.dir/src/utils.o.provides
+
+CMakeFiles/pepito.dir/src/utils.o.provides.build: CMakeFiles/pepito.dir/src/utils.o
+
+
+# Object files for target pepito
+pepito_OBJECTS = \
+"CMakeFiles/pepito.dir/src/daemon.o" \
+"CMakeFiles/pepito.dir/src/main.o" \
+"CMakeFiles/pepito.dir/src/network.o" \
+"CMakeFiles/pepito.dir/src/utils.o"
+
+# External object files for target pepito
+pepito_EXTERNAL_OBJECTS =
+
+pepito: CMakeFiles/pepito.dir/src/daemon.o
+pepito: CMakeFiles/pepito.dir/src/main.o
+pepito: CMakeFiles/pepito.dir/src/network.o
+pepito: CMakeFiles/pepito.dir/src/utils.o
+pepito: CMakeFiles/pepito.dir/build.make
+pepito: lib/libsecret.so
+pepito: lib/libsupersecret.so
+pepito: CMakeFiles/pepito.dir/link.txt
+	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable pepito"
+	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pepito.dir/link.txt --verbose=$(VERBOSE)
+
+# Rule to build all files generated by this target.
+CMakeFiles/pepito.dir/build: pepito
+
+.PHONY : CMakeFiles/pepito.dir/build
+
+CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/daemon.o.requires
+CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/main.o.requires
+CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/network.o.requires
+CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/utils.o.requires
+
+.PHONY : CMakeFiles/pepito.dir/requires
+
+CMakeFiles/pepito.dir/clean:
+	$(CMAKE_COMMAND) -P CMakeFiles/pepito.dir/cmake_clean.cmake
+.PHONY : CMakeFiles/pepito.dir/clean
+
+CMakeFiles/pepito.dir/depend:
+	cd /home/qwebify/rendu/secu/2016_P3p1t0/pepito && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/DependInfo.cmake --color=$(COLOR)
+.PHONY : CMakeFiles/pepito.dir/depend
+
diff --git a/pepito/CMakeFiles/pepito.dir/cmake_clean.cmake b/pepito/CMakeFiles/pepito.dir/cmake_clean.cmake
new file mode 100644
index 0000000..2787058
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/cmake_clean.cmake
@@ -0,0 +1,13 @@
+file(REMOVE_RECURSE
+  "CMakeFiles/pepito.dir/src/daemon.o"
+  "CMakeFiles/pepito.dir/src/main.o"
+  "CMakeFiles/pepito.dir/src/network.o"
+  "CMakeFiles/pepito.dir/src/utils.o"
+  "pepito.pdb"
+  "pepito"
+)
+
+# Per-language clean rules from dependency scanning.
+foreach(lang C)
+  include(CMakeFiles/pepito.dir/cmake_clean_${lang}.cmake OPTIONAL)
+endforeach()
diff --git a/pepito/CMakeFiles/pepito.dir/depend.internal b/pepito/CMakeFiles/pepito.dir/depend.internal
new file mode 100644
index 0000000..881c2a2
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/depend.internal
@@ -0,0 +1,26 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+CMakeFiles/pepito.dir/src/daemon.o
+ /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c
+ includes/daemon.h
+ includes/network.h
+ includes/pepito.h
+CMakeFiles/pepito.dir/src/main.o
+ /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c
+ includes/daemon.h
+ includes/network.h
+ includes/pepito.h
+ includes/recipes.h
+ includes/secret.h
+ includes/supersecret.h
+ includes/utils.h
+CMakeFiles/pepito.dir/src/network.o
+ /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c
+ includes/network.h
+ includes/pepito.h
+ includes/utils.h
+CMakeFiles/pepito.dir/src/utils.o
+ /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c
+ includes/pepito.h
+ includes/utils.h
diff --git a/pepito/CMakeFiles/pepito.dir/depend.make b/pepito/CMakeFiles/pepito.dir/depend.make
new file mode 100644
index 0000000..5c58e97
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/depend.make
@@ -0,0 +1,26 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+CMakeFiles/pepito.dir/src/daemon.o: src/daemon.c
+CMakeFiles/pepito.dir/src/daemon.o: includes/daemon.h
+CMakeFiles/pepito.dir/src/daemon.o: includes/network.h
+CMakeFiles/pepito.dir/src/daemon.o: includes/pepito.h
+
+CMakeFiles/pepito.dir/src/main.o: src/main.c
+CMakeFiles/pepito.dir/src/main.o: includes/daemon.h
+CMakeFiles/pepito.dir/src/main.o: includes/network.h
+CMakeFiles/pepito.dir/src/main.o: includes/pepito.h
+CMakeFiles/pepito.dir/src/main.o: includes/recipes.h
+CMakeFiles/pepito.dir/src/main.o: includes/secret.h
+CMakeFiles/pepito.dir/src/main.o: includes/supersecret.h
+CMakeFiles/pepito.dir/src/main.o: includes/utils.h
+
+CMakeFiles/pepito.dir/src/network.o: src/network.c
+CMakeFiles/pepito.dir/src/network.o: includes/network.h
+CMakeFiles/pepito.dir/src/network.o: includes/pepito.h
+CMakeFiles/pepito.dir/src/network.o: includes/utils.h
+
+CMakeFiles/pepito.dir/src/utils.o: src/utils.c
+CMakeFiles/pepito.dir/src/utils.o: includes/pepito.h
+CMakeFiles/pepito.dir/src/utils.o: includes/utils.h
+
diff --git a/pepito/CMakeFiles/pepito.dir/flags.make b/pepito/CMakeFiles/pepito.dir/flags.make
new file mode 100644
index 0000000..54235f7
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/flags.make
@@ -0,0 +1,10 @@
+# CMAKE generated file: DO NOT EDIT!
+# Generated by "Unix Makefiles" Generator, CMake Version 3.5
+
+# compile C with /usr/bin/cc
+C_FLAGS = -g  
+
+C_DEFINES = 
+
+C_INCLUDES = -I/home/qwebify/rendu/secu/2016_P3p1t0/pepito/includes 
+
diff --git a/pepito/CMakeFiles/pepito.dir/link.txt b/pepito/CMakeFiles/pepito.dir/link.txt
new file mode 100644
index 0000000..905dd3a
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/link.txt
@@ -0,0 +1 @@
+/usr/bin/cc  -g   CMakeFiles/pepito.dir/src/daemon.o CMakeFiles/pepito.dir/src/main.o CMakeFiles/pepito.dir/src/network.o CMakeFiles/pepito.dir/src/utils.o  -o pepito -rdynamic lib/libsecret.so lib/libsupersecret.so 
diff --git a/pepito/CMakeFiles/pepito.dir/progress.make b/pepito/CMakeFiles/pepito.dir/progress.make
new file mode 100644
index 0000000..33e6bff
--- /dev/null
+++ b/pepito/CMakeFiles/pepito.dir/progress.make
@@ -0,0 +1,6 @@
+CMAKE_PROGRESS_1 = 1
+CMAKE_PROGRESS_2 = 2
+CMAKE_PROGRESS_3 = 3
+CMAKE_PROGRESS_4 = 4
+CMAKE_PROGRESS_5 = 5
+
diff --git a/pepito/CMakeFiles/pepito.dir/src/daemon.o b/pepito/CMakeFiles/pepito.dir/src/daemon.o
new file mode 100644
index 0000000..b426648
Binary files /dev/null and b/pepito/CMakeFiles/pepito.dir/src/daemon.o differ
diff --git a/pepito/CMakeFiles/pepito.dir/src/main.o b/pepito/CMakeFiles/pepito.dir/src/main.o
new file mode 100644
index 0000000..13f4f8e
Binary files /dev/null and b/pepito/CMakeFiles/pepito.dir/src/main.o differ
diff --git a/pepito/CMakeFiles/pepito.dir/src/network.o b/pepito/CMakeFiles/pepito.dir/src/network.o
new file mode 100644
index 0000000..4007382
Binary files /dev/null and b/pepito/CMakeFiles/pepito.dir/src/network.o differ
diff --git a/pepito/CMakeFiles/pepito.dir/src/utils.o b/pepito/CMakeFiles/pepito.dir/src/utils.o
new file mode 100644
index 0000000..6e85a5a
Binary files /dev/null and b/pepito/CMakeFiles/pepito.dir/src/utils.o differ
diff --git a/pepito/CMakeFiles/progress.marks b/pepito/CMakeFiles/progress.marks
new file mode 100644
index 0000000..7ed6ff8
--- /dev/null
+++ b/pepito/CMakeFiles/progress.marks
@@ -0,0 +1 @@
+5
diff --git a/pepito/CMakeLists.txt b/pepito/CMakeLists.txt
new file mode 100644
index 0000000..7269536
--- /dev/null
+++ b/pepito/CMakeLists.txt
@@ -0,0 +1,32 @@
+if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
+    set(warnings "-fno-stack-protector")
+elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
+    set(warnings "-fno-address-sanitizer -fno-memsafety")
+endif()
+
+set(CMAKE_C_FLAGS   "${warnings}"
+        CACHE STRING "Flags used by the compiler during all build types." FORCE)
+
+project(pepito)
+set(CMAKE_BUILD_TYPE Debug)
+include_directories(${CMAKE_CURRENT_SOURCE_DIR}/includes)
+
+set(CMAKE_SKIP_BUILD_RPATH true)
+
+find_library(
+        LIBSECRET NAMES secret
+#        PATHS ${CMAKE_BINARY_DIR}/private/libsecret/ NO_DEFAULT_PATH
+        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib/ NO_DEFAULT_PATH
+)
+
+find_library(
+        LIBSUPERSECRET NAMES supersecret
+    #        PATHS ${CMAKE_BINARY_DIR}/private/libsecret/ NO_DEFAULT_PATH
+        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib/ NO_DEFAULT_PATH
+)
+
+add_executable(pepito src/daemon.c src/main.c src/network.c src/utils.c)
+
+target_link_libraries(pepito ${LIBSECRET} ${LIBSUPERSECRET})
+
+install(TARGETS pepito DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/)
\ No newline at end of file
diff --git a/pepito/Makefile b/pepito/Makefile
new file mode 100644
index 0000000..385ba35
--- /dev/null
+++ b/pepito/Makefile
@@ -0,0 +1,43 @@
+##
+## Makefile for  in
+##
+## Made by Jean PLANCHER
+## Login   <planch_j@epitech.net>
+##
+## Started on  Thu Apr 28 06:00:21 2016 Jean PLANCHER
+## Last update Tue May 10 17:01:09 2016 Jean PLANCHER
+##
+
+CC	= gcc
+
+RM	= rm -f
+
+CFLAGS	+= -I../sources/includes
+LDFLAGS	= -L../sources/lib -lsecret -lsupersecret -Wl,-rpath,../sources/lib
+
+NAME	= pepito
+
+FOLDER	= ../sources/src/
+
+SRCS	= $(addprefix $(FOLDER), \
+	  main.c \
+	  daemon.c \
+	  network.c \
+	  utils.c)
+
+OBJS	= $(SRCS:.c=.o)
+
+$(NAME): $(OBJS)
+	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)
+
+all: $(NAME)
+
+clean:
+	$(RM) $(OBJS)
+
+fclean:	clean
+	$(RM) $(NAME)
+
+re: fclean all
+
+.PHONY: all clean fclean re
diff --git a/pepito/client.py b/pepito/client.py
new file mode 100755
index 0000000..9962533
--- /dev/null
+++ b/pepito/client.py
@@ -0,0 +1,108 @@
+#!/usr/bin/env python2
+
+import socket
+import sys
+
+###############################
+############### Client Class ##
+
+def is_ascii(s):
+    return all(ord(c) < 128 for c in s)
+
+class Client:
+    def __init__(self, host='127.0.0.1', port='31337'):
+        self.host = host
+        self.port = port
+
+    def send(self, command):
+        cmdString = command[0]
+        for e in command[1:]:
+            cmdString +=  " " + str(len(e)) + e
+        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+        sock.connect((self.host, int(self.port)))
+        sock.send(cmdString)
+        sock.setblocking(0)
+        sock.settimeout(1.0)
+        ret = sock.recv(4096)
+        while ret != "":
+            for l in ret:
+                if l != None:
+                    if is_ascii(l):
+                        sys.stdout.write(l)
+                    else:
+                        print l.encode('hex')
+            ret = sock.recv(4096)
+        sock.close()
+
+
+    def interactiveMode(self):
+        stop = 0
+        while stop == 0:
+            sys.stdout.write("pepitoCLI>")
+            line = sys.stdin.readline()
+            if line == "":
+                stop = 1
+                print("  \nBye.")
+            elif line != "\n":
+                command = line.strip('\n').split('"')
+                print command
+                if command.count(""):
+                    command.remove("")
+                if len(command) > 1:
+                    last = command[-1]
+                    tmp = [c.split(" ") for c in command[:-1] if c != ""]
+                    command = []
+                    for c in tmp:
+                        command.extend(c)
+                    command.append(last)
+                    if command.count(""):
+                        command.remove("")
+                else:
+                    command = command[0]
+                    command = line.strip("\n").split(" ")
+                if command[0] == "help":
+                    self.printUsage()
+                else:
+                    self.send(command)
+
+    def printUsage(self):
+        usage = """Commands (<command number> <parameter> (<parameter> ...)) :
+\tChange password :
+\t\t0 <old_password> <new_password> (User & Admin)
+\tDisplay recipes :
+\t\t1 <password> (User & Admin)
+\tDisplay stock :
+\t\t2 <password> (User & Admin)
+\tMake recipe :
+\t\t3 <password> <"recipe name"> (Admin only)
+\tMake secret recipe :
+\t\t4 <password> (Admin only)
+\tSell granolas :
+\t\t5 <password> <"recipe name"> (User & Admin)
+\tBuy ingredients :
+\t\t6 <password> <ingredient_name> <amount> (Admin only)
+\tMake super secret recipe :
+\t\t7 <password> (Admin only)
+"""
+        print(usage)
+
+###############################
+
+###############################
+################ Main Source ##
+
+
+def main():
+    if len(sys.argv) < 3:
+        print("Usage :\n%s <host IP address> <port>" % sys.argv[0])
+        sys.exit()
+    try:
+        client = Client(sys.argv[1], sys.argv[2])
+        client.interactiveMode()
+    except Exception as e:
+        print(e)
+
+if __name__ == "__main__":
+    main()
+
+###############################
diff --git a/pepito/cmake_install.cmake b/pepito/cmake_install.cmake
new file mode 100644
index 0000000..7d9182e
--- /dev/null
+++ b/pepito/cmake_install.cmake
@@ -0,0 +1,68 @@
+# Install script for directory: /home/qwebify/rendu/secu/2016_P3p1t0/pepito
+
+# Set the install prefix
+if(NOT DEFINED CMAKE_INSTALL_PREFIX)
+  set(CMAKE_INSTALL_PREFIX "/usr/local")
+endif()
+string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
+
+# Set the install configuration name.
+if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
+  if(BUILD_TYPE)
+    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
+           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
+  else()
+    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
+  endif()
+  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
+endif()
+
+# Set the component getting installed.
+if(NOT CMAKE_INSTALL_COMPONENT)
+  if(COMPONENT)
+    message(STATUS "Install component: \"${COMPONENT}\"")
+    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
+  else()
+    set(CMAKE_INSTALL_COMPONENT)
+  endif()
+endif()
+
+# Install shared libraries without execute permission?
+if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
+  set(CMAKE_INSTALL_SO_NO_EXE "0")
+endif()
+
+if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
+  if(EXISTS "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito" AND
+     NOT IS_SYMLINK "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito")
+    file(RPATH_CHECK
+         FILE "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito"
+         RPATH "")
+  endif()
+  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
+   "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito")
+  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
+    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
+  endif()
+  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
+    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
+  endif()
+file(INSTALL DESTINATION "/home/qwebify/rendu/secu/2016_P3p1t0/pepito" TYPE EXECUTABLE FILES "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito")
+  if(EXISTS "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito" AND
+     NOT IS_SYMLINK "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito")
+    if(CMAKE_INSTALL_DO_STRIP)
+      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/home/qwebify/rendu/secu/2016_P3p1t0/pepito/pepito")
+    endif()
+  endif()
+endif()
+
+if(CMAKE_INSTALL_COMPONENT)
+  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
+else()
+  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
+endif()
+
+string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
+       "${CMAKE_INSTALL_MANIFEST_FILES}")
+file(WRITE "/home/qwebify/rendu/secu/2016_P3p1t0/pepito/${CMAKE_INSTALL_MANIFEST}"
+     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
diff --git a/pepito/includes/daemon.h b/pepito/includes/daemon.h
new file mode 100644
index 0000000..2cf3d64
--- /dev/null
+++ b/pepito/includes/daemon.h
@@ -0,0 +1,25 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#ifndef		__DAEMON_H__
+# define	__DAEMON_H__
+
+#define NORMAL 0
+#define DEBUG  1
+
+int			runDaemon(int debug);
+int			stopDaemon(void);
+
+int			savePid(void);
+int			checkOtherProcess(void);
+void			sigHandler(int sig);
+
+#endif	    /* !__DAEMON_H__ */
diff --git a/pepito/includes/network.h b/pepito/includes/network.h
new file mode 100644
index 0000000..be2027a
--- /dev/null
+++ b/pepito/includes/network.h
@@ -0,0 +1,29 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#ifndef			_NETWORK_H__
+# define		_NETWORK_H__
+
+#include <sys/socket.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+
+#include <netinet/in.h>
+
+void			initConnection(struct sockaddr_in *sa);
+int			acceptClient(struct sockaddr_in *sa);
+int			getPacket(void *packetPtr, size_t *packetSize);
+void			sendLogMessage(char *msg);
+
+void			setClient(int fd);
+void			setSock(int fd);
+
+#endif		    /* !_NETWORK_H__ */
diff --git a/pepito/includes/pepito.h b/pepito/includes/pepito.h
new file mode 100644
index 0000000..2bdcb0f
--- /dev/null
+++ b/pepito/includes/pepito.h
@@ -0,0 +1,34 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#ifndef		__PEPITO_H__
+# define	__PEPITO_H__
+
+#define PACKETLEN	0x1000
+#define PORT		0x7a6a
+
+#define PASSWD_CHANGE		"Password successfully changed\n"
+#define AD_CHANGE		"Advertisement successfully changed\n"
+#define PASSWD_FAIL		"Wrong password\n"
+
+#define INGREDIENT_BOUGHT	"Ingredient successfully acquired.\n"
+#define UNKNOWN_INGREDIENT	"Unknown ingredient.\n"
+#define UNKNOWN_RECIPE		"Unknown recipe.\n"
+
+#define NOBODY		0
+#define ADMIN		1
+#define USER		2
+
+int			checkPassword(char *password);
+
+int			handlePacket(void *packetPtr, size_t packetSize);
+
+#endif
diff --git a/pepito/includes/pepito.h.gch b/pepito/includes/pepito.h.gch
new file mode 100644
index 0000000..35f36b6
Binary files /dev/null and b/pepito/includes/pepito.h.gch differ
diff --git a/pepito/includes/recipes.h b/pepito/includes/recipes.h
new file mode 100644
index 0000000..89e9822
--- /dev/null
+++ b/pepito/includes/recipes.h
@@ -0,0 +1,41 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Djo wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#ifndef           __RECIPES_H__
+# define          __RECIPES_H__
+
+# define Recipe_MDMA    0
+# define Recipe_Whisky  1
+# define Recipe_Cum     2
+# define Recipe_LSD     3
+# define Secret_Recipe  4
+
+# define MDMA           0
+# define WHISKY         1
+# define CUM            2
+# define LSD            3
+# define CHOCOLATE      4
+# define FLOUR          5
+
+/* tableau de structure des recettes */
+typedef struct    s_recipes
+{
+  char            *name;          /* nom de la recette */
+  int             quantity;       /* nombre de recette faite */
+}                 t_recipes;
+
+typedef struct    s_stock
+{
+  char            *name;
+  int             quantity;
+}                 t_stock;
+
+#endif     /* !__RECIPES_H__ */
diff --git a/pepito/includes/secret.h b/pepito/includes/secret.h
new file mode 100644
index 0000000..788fb26
--- /dev/null
+++ b/pepito/includes/secret.h
@@ -0,0 +1,7 @@
+
+#ifndef   SECRET_H
+# define    SECRET_H
+
+int handlerMakeSecretRecipes(void *packetPtr, size_t packetSize);
+
+#endif     /* !SECRET_H */
diff --git a/pepito/includes/supersecret.h b/pepito/includes/supersecret.h
new file mode 100644
index 0000000..85adb5c
--- /dev/null
+++ b/pepito/includes/supersecret.h
@@ -0,0 +1,6 @@
+#ifndef   SUPERSECRET_H
+# define    SUPERSECRET_H
+
+int handlerMakeSuperSecretRecipes(void *packetPtr, size_t packetSize);
+
+#endif     /* !SECRET_H */
diff --git a/pepito/includes/utils.h b/pepito/includes/utils.h
new file mode 100644
index 0000000..9f6797d
--- /dev/null
+++ b/pepito/includes/utils.h
@@ -0,0 +1,21 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Mota, The Polish Plumber and Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy us [:drinks:]*
+** in return.
+*/
+
+#ifndef		__UTILS_H__
+# define	__UTILS_H__
+
+void			die(char *fctName);
+
+char			getChar(void **p);
+int 			getNumber(void **p, size_t *packetSize);
+char 			*getStr(void **p, size_t *l);
+
+#endif
diff --git a/pepito/lib/libsecret.so b/pepito/lib/libsecret.so
new file mode 100644
index 0000000..4785bf5
Binary files /dev/null and b/pepito/lib/libsecret.so differ
diff --git a/pepito/lib/libsupersecret.so b/pepito/lib/libsupersecret.so
new file mode 100644
index 0000000..c8715e6
Binary files /dev/null and b/pepito/lib/libsupersecret.so differ
diff --git a/pepito/peda-session-pepito.txt b/pepito/peda-session-pepito.txt
new file mode 100644
index 0000000..69a4569
--- /dev/null
+++ b/pepito/peda-session-pepito.txt
@@ -0,0 +1,25 @@
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
diff --git a/pepito/peny.py b/pepito/peny.py
new file mode 100755
index 0000000..f6d4a7d
--- /dev/null
+++ b/pepito/peny.py
@@ -0,0 +1,81 @@
+#!/usr/bin/env python2
+
+import socket
+import sys
+
+###############################
+############### Client Class ##
+
+class Client:
+    def __init__(self, host='127.0.0.1', port='31337'):
+        self.host = host
+        self.port = port
+
+    def send(self, command):
+        cmdString = command[0]
+        for e in command[1:]:
+            cmdString +=  " " + str(len(e)) + e
+        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+        sock.connect((self.host, int(self.port)))
+        sock.send(cmdString)
+        sock.setblocking(0)
+        sock.settimeout(1.0)
+        ret = sock.recv(4096)
+        while ret != "":
+            for l in ret:
+                if l != None:
+                    sys.stdout.write(l)
+            ret = sock.recv(4096)
+        sock.close()
+
+
+    def interactiveMode(self):
+        command = '1 '+'x'*1024
+        print command
+        self.send(command)
+
+    def printUsage(self):
+        usage = """Commands (<command number> <parameter> (<parameter> ...)) :
+\tChange password :
+\t\t0 <old_password> <new_password> (User & Admin)
+\tDisplay recipes :
+\t\t1 <password> (User & Admin)
+\tDisplay stock :
+\t\t2 <password> (User & Admin)
+\tMake recipe :
+\t\t3 <password> <"recipe name"> (Admin only)
+\tMake secret recipe :
+\t\t4 <password> (Admin only)
+\tSell granolas :
+\t\t5 <password> <"recipe name"> (User & Admin)
+\tBuy ingredients :
+\t\t6 <password> <ingredient_name> <amount> (Admin only)
+\tMake super secret recipe :
+\t\t7 <password> (Admin only)
+"""
+        print(usage)
+
+###############################
+
+###############################
+################ Main Source ##
+
+
+def main():
+    if len(sys.argv) < 3:
+        client = Client('127.0.0.7', '31337')
+    else:
+        client = Client(sys.argv[1], sys.argv[2])
+
+        # print("Usage :\n%s <host IP address> <port>" % sys.argv[0])
+        # sys.exit()
+
+    client.interactiveMode()
+    # try:
+    # except Exception as e:
+    #     print(e)
+
+if __name__ == "__main__":
+    main()
+
+###############################
diff --git a/pepito/pepito b/pepito/pepito
new file mode 100755
index 0000000..210e1bf
Binary files /dev/null and b/pepito/pepito differ
diff --git a/pepito/pepito.pid b/pepito/pepito.pid
new file mode 100644
index 0000000..c60a622
--- /dev/null
+++ b/pepito/pepito.pid
@@ -0,0 +1 @@
+20992
\ No newline at end of file
diff --git a/pepito/ressources/gdb_doc.txt b/pepito/ressources/gdb_doc.txt
new file mode 100644
index 0000000..dba63e8
--- /dev/null
+++ b/pepito/ressources/gdb_doc.txt
@@ -0,0 +1,360 @@
+Introduction à GDB
+
+###############################################################################
+
+
+* Cible
+*******
+
+Les exécutables que vous désirez debugger peuvent posséder des symboles.
+Les symboles sont des informations stockés dans l'exécutable qui permettent, à
+partir d'une adresse, de connaitre le nom et la signification d'une zone mémoire.
+Sous UNIX, pour lister les symboles d'un exécutable, il faut utiliser la
+commande nm(1).
+Cette commande permet de connaitre l'adresse, le nom ainsi que le type de
+symbole.
+La signification des lettres est disponible sur la page de manuel de nm (man
+nm).
+
+Afin d'avoir un maximum d'information sur un exécutable, il est préférable
+d'utiliser l'option de compilation "-ggdb<n>", n allant de 0 a 3.
+Cette option force gcc à rajouter des symboles spéciaux interpretables par gdb.
+(Note: L'option -g<n> est également possible, mais ces informations de debug
+seront dans un autre format).
+Pour savoir si un exécutable dispose de ce genre de symbole, vous pouvez
+utiliser la commande suivante:
+
+Avec:
+[/tmp]% nm -a hello_gdb | grep ' N '
+00000000 N .debug_abbrev
+00000000 N .debug_aranges
+00000000 N .debug_frame
+00000000 N .debug_info
+00000000 N .debug_line
+00000000 N .debug_loc
+00000000 N .debug_macinfo
+00000000 N .debug_str
+
+Sans:
+[/tmp]% nm -a hello | grep ' N '
+[/tmp]%
+
+Enfin, la plupart des exécutables de base ne possède pas de symbole:
+[/tmp]% nm -a /bin/ls
+nm: /bin/ls: no symbols
+
+Pour retirer les symboles d'un exécutable, il faut utiliser la commande
+strip(1):
+[/tmp]% strip hello_gdb
+[/tmp]% nm hello_gdb
+nm: hello_gdb: no symbols
+
+###############################################################################
+
+
+* Utilisation
+*************
+
+GDB permet de debugger les exécutables de différente façon, ici seules 3
+méthodes seront données:
+
+** Normal
+*********
+
+On fournit un exécutable en paramètre et on démarre manuellement
+l'executable.
+
+gdb /bin/ls
+
+On peut également spécifier des paramètres en utilisant --args
+gdb --args /bin/ls -l
+
+** Attachement d'un processus
+*****************************
+
+L'exécutable est déjà démarré, on demande à gdb de s'attacher sur l'exécutable.
+Cette méthode est pratique pour les exécutables qui utilisent les termcaps ou
+sont trop bavards
+
+[/tmp]% cat
+^Z
+zsh: suspended  cat
+[/tmp]% pidof cat
+2006
+[/tmp]% gdb /bin/cat 2006
+
+'pidof' permet de récupérer les pids à partir d'un nom de processus.
+
+** Coredump
+***********
+
+L'exécutable reçoit un signal qui provoque son arret (e.g.: SIGSEGV ou
+segfault) et le shell est configuré pour dumper la mémoire à cet instant.
+
+[/tmp]% ulimit -c unlimited
+[/tmp]% ./segfault
+zsh: segmentation fault (core dumped)  ./segfault
+[/tmp]% gdb ./segfault core
+
+ulimit -c unlimited permet d'activer les coredumps sous zsh.
+Sous tcsh il faut utiliser la commande limit coredump unlimited (à verifier)
+
+Note: Il n'est pas possible de continuer l'exécution à partir d'un coredump,
+vous devez redémarrer votre programme.
+
+###############################################################################
+
+* Contrôle du flux d'exécution
+******************************
+
+Afin de pouvoir debugger un programme, il faut pouvoir l'instrumentaliser.
+L'idée est de définir à quel moment le programme doit s'arrêter et donner la
+main à gdb et pouvoir observer ce qu'il se passe.
+Généralement, ça se déroule en deux étapes: On definit un endroit ou s'arrêter,
+puis on avance pas-à-pas pour voir ce qui se passe en détail.
+
+** Breakpoint
+*************
+
+Le breakpoint permet de prendre le contrôle avant qu'une adresse donnée soit
+executée.
+Il y a plusieurs façons de donner une adresse
+
+- Par symbole
+  (gdb) b main
+  Breakpoint 1 at 0x839c: file hello.c, line 5.
+  (gdb) r
+  Starting program: /tmp/hello_gdb
+
+  Breakpoint 1, main () at hello.c:5
+  5         puts("hello");
+
+
+- Par adresse
+  (gdb) b *0x82e8
+  Breakpoint 1 at 0x82e8
+  (gdb) r
+  Starting program: /tmp/hello_gdb
+
+- Par ligne
+  (gdb) list main
+  1       #include <stdio.h>
+  2
+  3       int main(void)
+  4       {
+  5         puts("hello");
+  6         return 0;
+  7       }
+  (gdb) b 6
+  Breakpoint 1 at 0x83a4: file hello.c, line 6.
+  (gdb) r
+  Starting program: /tmp/hello_gdb
+  hello
+  Breakpoint 1, main () at hello.c:6
+  6         return 0;
+  Breakpoint 1, 0x000082e8 in _start ()
+
+** Déplacement du flux d'exécution
+**********************************
+
+Trois commandes sont disponibles pour se déplacer dans le code
+
+- step
+  La commande s(step) permet de se déplacer d'une ligne de code en entrant dans
+  les sous-fonctions.
+  (gdb) b main
+  Breakpoint 1 at 0x400555: file debug_me.c, line 13.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, main () at debug_me.c:13
+  13        n = -1;
+  (gdb) s
+  14        my_inc(&n);
+  (gdb)
+  my_inc (i=0x7fffffffe8a4) at debug_me.c:5
+  5         (*i)++;
+  (gdb)
+  6       }
+  (gdb)
+  main () at debug_me.c:15
+  15        printf("n=%d\n", n);
+
+- next
+  La commande n(next) permet de se déplacer d'une ligne de code mais sans
+  entrer dans les sous-fonctions.
+  (gdb) b main
+  Breakpoint 1 at 0x400555: file debug_me.c, line 13.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, main () at debug_me.c:13
+  13        n = -1;
+  (gdb) n
+  14        my_inc(&n);
+  (gdb)
+  15        printf("n=%d\n", n);
+
+- return
+  La commande return permet de sortir de la fonction courante.
+  (gdb) b my_inc
+  Breakpoint 1 at 0x40053c: file debug_me.c, line 5.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, my_inc (i=0x7fffffffe8a4) at debug_me.c:5
+  5         (*i)++;
+  (gdb) return
+  Make my_inc return now? (y or n) y
+  #0  main () at debug_me.c:15
+  15        printf("n=%d\n", n);
+
+** Watchpoint
+*************
+
+Le watchpoint permet de "surveiller" une zone mémoire.
+Sa capacité dépend fortement de l'architecture utilisé, il se peut même que
+les watchpoints ne soint pas disponibles.
+
+watch permet de surveiller les affectations:
+  (gdb) b main
+  Breakpoint 1 at 0x400505: file debug_me.c, line 12.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, main () at debug_me.c:12
+  12        n = -1;
+  (gdb) watch n
+  Hardware watchpoint 2: n
+  (gdb) c
+  Continuing.
+  n=0
+  Hardware watchpoint 2: n
+
+  Old value = 0
+  New value = -1
+  main () at debug_me.c:17
+  17        printf("n=%d\n", n);
+
+rwatch permet de surveiller les lectures:
+  (gdb) b main
+  Breakpoint 1 at 0x400505: file debug_me.c, line 12.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, main () at debug_me.c:12
+  12        n = -1;
+  (gdb) rwatch n
+  Hardware read watchpoint 2: n
+  (gdb) c
+  Continuing.
+  Hardware read watchpoint 2: n
+
+  Value = 0
+  0x000000000040051b in main () at debug_me.c:14
+  14        printf("n=%d\n", n);
+  (gdb) c
+  Continuing.
+  n=0
+  Hardware read watchpoint 2: n
+
+  Value = -1
+  0x0000000000400539 in main () at debug_me.c:17
+  17        printf("n=%d\n", n);
+
+awatch permet de surveiller les lectures/écritures:
+  (gdb) b main
+  Breakpoint 1 at 0x400505: file debug_me.c, line 12.
+  (gdb) r
+  Starting program: /tmp/debug_me
+
+  Breakpoint 1, main () at debug_me.c:12
+  12        n = -1;
+  (gdb) awatch n
+  Hardware access (read/write) watchpoint 2: n
+  (gdb) c
+  Continuing.
+  Hardware access (read/write) watchpoint 2: n
+
+  Old value = 0
+  New value = -1
+  0x00000000004004f2 in my_inc (i=0x7fffffffe8ac) at debug_me.c:5
+  5         (*i)++;
+  (gdb) c
+  Continuing.
+  Hardware access (read/write) watchpoint 2: n
+
+  Old value = -1
+  New value = 0
+  my_inc (i=0x7fffffffe8ac) at debug_me.c:6
+  6       }
+
+** Manipulation des breakpoints et watchpoints
+**********************************************
+
+Commande      Signification
+
+i b           Permet de lister les break/watchs
+d       <no>  Permet de supprimer un break/watch
+disable <no>  Permet de désactiver un break/watch
+enable  <no>  Permet d'activer un break/watch
+
+###############################################################################
+
+* Contrôle de la mémoire
+************************
+
+** Afficher la mémoire
+**********************
+
+GDB dispose de deux façons d'observer la mémoire:
+
+- Afficher
+  La commande 'p' (print) afficher la valeur d'une variable
+
+  (gdb) p n
+  $3 = 0
+
+- Dumper
+  La commande 'x' permet de déréférencer une variable pour afficher son contenu.
+  (gdb) x i
+  0x7fffffffe8ac: 0xffffffff
+  (gdb) n
+  6       }
+  (gdb) x i
+  0x7fffffffe8ac: 0x00000000
+
+  Cette commande accepte une taille en paramètre pour dumper plusieurs elements.
+  (gdb) x/2 i
+  0x7fffffffe8ac: 0x00000000      0x00000000
+
+- Formatage
+  Les commandes précédentes peuvent prendre des options de formatage.
+  (gdb) n
+  17        s = "hello";
+  (gdb)
+  19        n = -1;
+  (gdb) x/s s
+  0x4006b2:        "hello"
+  (gdb) x/6x s
+  0x4006b2:       0x68    0x65    0x6c    0x6c    0x6f    0x00
+
+
+** Modifier la mémoire
+**********************
+
+Il est possible de modifier la memoire avec gdb, il existe deux méthodes:
+
+- Variable
+  (gdb) set variable n = 4
+  (gdb) p n
+  $1 = 4
+
+- Par adresse
+  (gdb) p &n
+  $2 = (int *) 0x7fffffffe8a4
+  (gdb) set *(int *)0x7fffffffe8a4 = 0
+  (gdb) p n
+  $3 = 0
+
+###############################################################################
diff --git a/pepito/ressources/virtual_memory.txt b/pepito/ressources/virtual_memory.txt
new file mode 100644
index 0000000..bdc8877
--- /dev/null
+++ b/pepito/ressources/virtual_memory.txt
@@ -0,0 +1,151 @@
+Epitech Security Laboratory                            L. `Zerk' Michaux
+
+
+                        Epitech 1 - B2 Securite
+          Introduction to memory segmentation - IA32 Architecture
+
+                                                             Febuary 2012
+
+______Figure 0_________________________________________________________/
+
+                              Memory
+                                                 Higher Memory Addresses
+                 +-----------------------------+
+                 |        kernel space         |
+  [1] 0xc0000000 +-----------------------------+
+                 |~~~~~~~ random offset ~~~~~~~|
+                 +-----------------------------+
+                 | |                           |
+                 | v          Stack            |
+                 +-----------------------------+
+                 | / / / / / / / / / / / / / / |
+                 +-----------------------------+
+                 | |                           |
+                 | v      Shared memory        |
+                 +-----------------------------+
+                 | / / / / / / / / / / / / / / |
+             brk +-----------------------------+
+                 | ^                           |
+                 | |          Heap             |
+       Start brk +-----------------------------+
+                 |~~~~~~~ random offset ~~~~~~~|
+                 +-----------------------------+
+                 |             bss             |
+                 +-----------------------------+
+                 |            data             |
+                 +-----------------------------+
+                 |            text             |
+  [2] 0x08048000 +-----------------------------+
+                 | / / / / / / / / / / / / / / |
+      0x00000000 +-----------------------------+
+                                                  Lower Memory Addresses
+
+
+
+______Code sample - Figure 1 & 2_______________________________________/
+
+|  int func1(int le, int et, char *input)
+|  {
+|    char buf[4];
+|    int  value;
+|
+|    value = le + et;
+|    strcpy(buf, input);
+|    printf("%s : %i\n", buf, value);
+|    return (value);
+|  }
+|
+|  int func0(char *in)
+|  {
+|    return (func1(13, 37, in));
+|  }
+
+
+______Figure 1_________________________________________________________/
+
+                             Stack
+                                                 Higher Memory Addresses
+                 |              .               |
+                 |              .               |
+                 |              .               |
+                 +------------------------------+
+		 |    Parameters of func0()     |
+                 +------------------------------+
+                 |  Return address of func0()   | -> eip [4]
+		 +------------------------------+
+		 |      SFP[3] of func0()       | -> ebp [4]
+		 +------------------------------+
+                 |     Locales of func0()       |
+         ebp [4] +------------------------------+ --+
+		 |    Parameters of func1()     |   |
+		 +------------------------------+   |
+		 |  Return address of func1()   |   |
+		 +------------------------------+   | Figure 2
+		 |      SFP[3] of func1()       |   |
+		 +------------------------------+   |
+		 |     Locales of func1()       |   |
+         esp [4] +------------------------------+ --+
+                 |              |               |
+		 |              v               |
+		                                  Lower Memory Addresses
+
+
+______Figure 2_________________________________________________________/
+
+
+		     Stack context for func1()
+					          Higher Memory Addresses
+                 |              .               |
+		 |              .               |
+		 +------------------------------+ --+
+                 |            input             |   |
+		 +------------------------------+   |
+		 |             et               |   | Parameters
+		 +------------------------------+   |
+		 |             le               |   |
+		 +------------------------------+ --+
+		 |        Return address        |
+	 	 +------------------------------+
+                 |             SFP              |
+		 +------------------------------+ --+
+		 |             buf              |   |
+		 +------------------------------+   | Local variables
+		 |            value             |   |
+		 +------------------------------+ --+
+		 |              |               |
+		 |              v               |
+					          Lower Memory addresses
+
+
+______Notes____________________________________________________________/
+
+[1], [2] : Ces adresses peuvent changer en fonction du systeme ou de
+           l'architecture sur lesquels le processus est actif.
+	   Les adresses donnees sont valides sur la plupart des unices
+	   sous x86.
+
+[3]      : SFP, Saved Frame Pointer. Il s'agit du "pointeur de base
+           sauvegarde. L'adresse contenue a cet endroit sera placee dans
+           ebp a la fin de l'execution de la fonction courante.
+
+[4]      : eip, ebp, esp, registres de processeur x86.
+
+	   - eip : Extended Instruction Pointer, contient l'adresse de
+	   l'instruction actuellement executee dans ce processus.
+	   Generalement ce registre pointe sur une adresse contenue dans
+	   le segment de code (text).
+
+	   - ebp : Extended Base Pointer, contient l'adresse de la "base"
+	   du contexte de la fonction courante. A la fin de l'execution
+	   de la fonction courante l'adresse contenue dans ebp sera
+	   placee dans esp.
+
+	   - esp : Extended Stack Pointer, contient l'adresse de la "fin"
+	   du contexte de la fonction courante, et par la meme la fin de
+	   la pile.
+
+
+______Bibliography_____________________________________________________/
+
+"Smashing the stack for fun and profit" ~ Aleph One
+                       http://www.phrack.org/issues.html?id=14&issue=49
diff --git a/pepito/src/daemon.c b/pepito/src/daemon.c
new file mode 100644
index 0000000..6e3eb99
--- /dev/null
+++ b/pepito/src/daemon.c
@@ -0,0 +1,127 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#include <signal.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <strings.h>
+#include <unistd.h>
+
+#include <sys/stat.h>
+
+#include "pepito.h"
+
+#include "daemon.h"
+#include "network.h"
+
+/* Main daemon functions ---------------------------------------- */
+
+/* sig */
+
+void
+sigHandler(int sig)
+{
+  switch (sig) {
+  case SIGINT:
+    fprintf(stderr, "Process received SIGINT.\n" \
+	    "Exiting\n");
+    break;
+  case SIGTERM:
+    fprintf(stderr, "Process received SIGTERM.\n" \
+	    "Exiting\n");
+    break;
+  }
+  remove("pepito.pid");
+  exit(EXIT_SUCCESS);
+}
+
+/* run */
+
+int
+checkOtherProcess(void)
+{
+  struct stat		buf;
+
+  if (stat("pepito.pid", &buf) == 0) {
+    fprintf(stderr, "Daemon is already running.\n"	  \
+	    "If it's not, please check 'pepito.pid'.\n"	  \
+	    "Exiting\n");
+    return -1;
+  }
+  return 0;
+}
+
+int
+savePid(void)
+{
+  FILE*			pidFile;
+  pid_t			pid;
+
+  if (!(pidFile = fopen("pepito.pid", "w"))) {
+    fprintf(stderr, "Cannot save process id.\n" \
+	    "Exiting\n");
+    return -1;
+  }
+  pid = getpid();
+  fprintf(pidFile, "%i", pid);
+  fclose(pidFile);
+  return 0;
+}
+
+int
+runDaemon(int debug)
+{
+  char			packetPtr[PACKETLEN];
+  size_t	       	packetSize;
+  struct sockaddr_in	sa;
+
+  if (checkOtherProcess())
+    return (EXIT_FAILURE);
+  signal(SIGTERM, sigHandler);
+  signal(SIGINT, sigHandler);
+  signal(SIGUSR1, sigHandler);
+
+  if (!debug) {
+    daemon(1, 1);
+    if (savePid())
+      return EXIT_FAILURE;
+  }
+
+  fprintf(stderr, "Daemon started\n");
+
+  initConnection(&sa);
+  while (1) {
+    setClient(acceptClient(&sa)); //check if clien of
+    bzero(packetPtr, PACKETLEN); //set PACKETLEN of packetPtr to 0
+    getPacket(packetPtr, &packetSize); //check if size > 0
+    handlePacket(packetPtr, packetSize);
+    setClient(-1);
+  }
+  setSock(-1);
+  return EXIT_SUCCESS;
+}
+
+/* stop */
+
+int
+stopDaemon(void)
+{
+  int			pid;
+  FILE*			pidFile;
+
+  if ((pidFile = fopen("pepito.pid", "r")) == NULL)
+    return EXIT_SUCCESS;
+  fscanf(pidFile, "%i", &pid);
+  kill(pid, SIGUSR1);
+  fprintf(stderr, "Stopping daemon (%i)\n", pid);
+  remove("pepito.pid");
+  return EXIT_SUCCESS;
+}
diff --git a/pepito/src/daemon.o b/pepito/src/daemon.o
new file mode 100644
index 0000000..548ff80
Binary files /dev/null and b/pepito/src/daemon.o differ
diff --git a/pepito/src/main.c b/pepito/src/main.c
new file mode 100644
index 0000000..c62b72d
--- /dev/null
+++ b/pepito/src/main.c
@@ -0,0 +1,379 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk and Djo wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy us some belgian
+** beers in return.
+*/
+
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "pepito.h"
+#include "network.h"
+#include "daemon.h"
+#include "utils.h"
+#include "recipes.h"
+#include "secret.h"
+#include "supersecret.h"
+
+static char		adminPassword[512] = "\x25\x20\x21\x34\x3c\x3b\x38\x3a\x3b\x05\x05\x16"; /* putainmonPPC */
+static char		userPassword[512] = "jt3d1l4t3";
+static char    		xorKey = 0x55;
+static int    		money = 11110;
+
+t_recipes               tab_recipes[] = // 0x00000000006045c6
+{
+  {"Granola with some MDMA", 0},
+  {"Granola with some Whisky", 0},
+  {"Granola with some Cum", 0},
+  {"Granola with some LSD", 0},
+  {"Secret Granola", 0},
+  {NULL, 0}
+};
+
+t_stock                 stock[] =
+{
+  {"MDMA",       10},
+  {"Whisky",     10},
+  {"Cum",        10},
+  {"LSD",        10},
+  {"Chocolate",  10},
+  {"Flour",      10},
+  {NULL,         0}
+};
+
+/* --- checkPassword() ---------------------------------------------- */
+
+int
+checkPassword(char *password) // 0x000000000040199f
+{
+  char			savePassword[64] = {0};
+  char			*logMessage;
+  int			isUser = 0;
+  int			isAdmin = 0;
+  int			i;
+
+  if (!strcmp(password, userPassword))
+    isUser = 1;
+  strcpy(savePassword, password);
+  for (i = 0; password[i]; ++i)
+    password[i] ^= xorKey;
+  if (!strcmp(password, adminPassword))
+    isAdmin = 1;
+
+  if (!(isAdmin | isUser)) {
+    logMessage = malloc(sizeof(*logMessage) * (strlen(password) + 21));
+    memset(logMessage, 0, strlen(password) + 21);
+    strcat(logMessage, "Invalid password : ");
+    strcat(logMessage, savePassword);
+    strcat(logMessage, "\n");
+    sendLogMessage(logMessage);
+    free(logMessage);
+  }
+  return isAdmin ? ADMIN : isUser ? USER : NOBODY;
+}
+
+/* --- change*Password() -------------------------------------------- */
+
+static void
+changeUserPassword(char *password)
+{
+  if (password)
+    {
+      strcpy(userPassword, password);
+      for (int i = 0; i < 512 && adminPassword[i]; i++)
+	fprintf(stderr, "%c", adminPassword[i]);
+      fprintf(stderr, "adm passwd:%s\n", adminPassword);
+      sendLogMessage(PASSWD_CHANGE);
+    }
+}
+
+static void
+changeAdminPassword(char *password)
+{
+  int			i;
+
+  if (password) {
+    for (i = 0; password[i]; ++i)
+      password[i] ^= xorKey;
+    strcpy(adminPassword, password);
+    sendLogMessage(PASSWD_CHANGE);
+  }
+}
+
+/* --- Packet handlers ---------------------------------------------- */
+
+static int
+handlerChangePassword(void *packetPtr, size_t packetSize)
+{
+  int			identity = NOBODY;
+  char			*newPassword;
+  char			*oldPassword;
+
+  oldPassword = getStr(&packetPtr, &packetSize);
+  newPassword = getStr(&packetPtr, &packetSize);
+  if ((identity = checkPassword(oldPassword)) == ADMIN)
+    changeAdminPassword(newPassword);
+  else if (identity == USER)
+    changeUserPassword(newPassword);
+  if (newPassword)
+    free(newPassword);
+  if (oldPassword)
+    free(oldPassword);
+  return 0;
+}
+
+/* --- Display all Recipes ------------------------------------------ */
+
+static int
+handlerDisplayRecipes(void *packetPtr, size_t packetSize)
+{
+  int			i;
+  int			user = NOBODY;
+  char			msg[256] = {0};
+  char			*password = NULL;
+
+  password = getStr(&packetPtr, &packetSize);
+  user = checkPassword(password);
+  if (user == USER || user == ADMIN) {
+    sendLogMessage("Lists of Recipes\n================\n");
+    for (i = 0; tab_recipes[i].name; ++i) {
+      snprintf(msg, sizeof(msg), "[%d] - %s\n", i, tab_recipes[i].name);
+      sendLogMessage(msg);
+    }
+  }
+  free(password);
+  return 0;
+}
+
+/* --- Display Stock of Granola Corp --------------------------------- */
+
+static int
+handlerDisplayStock(void *packetPtr, size_t packetSize)
+{
+  int			i;
+  int			user = NOBODY;
+  char			msg[256] = {0};
+  char			*password = NULL;
+
+  password = getStr(&packetPtr, &packetSize);
+  if ((user = checkPassword(password)) == USER || user == ADMIN) {
+    snprintf(msg, sizeof(msg), "Money : %d\n", money);
+    sendLogMessage(msg);
+    sendLogMessage("\nIngredient stock\n================\n");
+    for (i = 0; stock[i].name; ++i) {
+      snprintf(msg, sizeof(msg), "[%d] - %s\n", stock[i].quantity, stock[i].name);
+      sendLogMessage(msg);
+    }
+    sendLogMessage("\nFor sale\n========\n");
+    for (i = 0; tab_recipes[i].name; ++i) {
+      if (tab_recipes[i].quantity) {
+	snprintf(msg, sizeof(msg), "%d x %s\n", tab_recipes[i].quantity, tab_recipes[i].name);
+	sendLogMessage(msg);
+      }
+    }
+  }
+  free(password);
+  return 0;
+}
+
+/* --- Make Recipes -------------------------------------------------- */
+
+static int
+_checkIngredient(unsigned int id)
+{
+  if (id > sizeof(stock) / sizeof(t_stock))
+    return -1;
+  return 0;
+}
+
+static char *
+_checkStock(int id)
+{
+  if (stock[CHOCOLATE].quantity - 1 < 0)
+    return "Need more Chocolate";
+  if (stock[FLOUR].quantity - 1 < 0)
+    return "Need more Flour";
+  if (id == MDMA && stock[MDMA].quantity - 1 < 0)
+    return "Need more MDMA";
+  if (id == WHISKY && stock[WHISKY].quantity - 1 < 0)
+    return "Need more WHISKY";
+  if (id == CUM && stock[CUM].quantity - 1 < 0)
+    return "Need more CUM";
+  if (id == LSD && stock[LSD].quantity - 1 < 0)
+    return "Need more LSD";
+  return NULL;
+}
+
+static void
+_useIngredient(int MagicIngredient)
+{
+  stock[CHOCOLATE].quantity		-= 1;
+  stock[FLOUR].quantity			-= 1;
+  stock[MagicIngredient].quantity	-= 1;
+  tab_recipes[MagicIngredient].quantity += 1;
+}
+
+static int
+handlerMakeRecipes(void *packetPtr, size_t packetSize)
+{
+  int			id = 0;
+  char			*recipe;
+  char			*log;
+  char			msg[256];
+  char			*password = NULL;
+
+  password = getStr(&packetPtr, &packetSize);
+  if (checkPassword(password) == ADMIN) {
+    recipe = getStr(&packetPtr, &packetSize);
+    if ((log = _checkStock(id))) {
+      sendLogMessage(log);
+      return -1;
+    }
+    fprintf(stderr, "Recipe : '%s'\n", recipe);
+    for (id = 0; tab_recipes[id].name != NULL
+	   && strcmp(tab_recipes[id].name, recipe); ++id);
+    if (tab_recipes[id].name == NULL) {
+      sendLogMessage(UNKNOWN_RECIPE);
+      return -1;
+    }
+
+    if (_checkIngredient(id)) {
+      sendLogMessage(UNKNOWN_INGREDIENT);
+      return -1;
+    }
+    _useIngredient(id);
+    snprintf(msg, sizeof(msg), "%s was made\n", tab_recipes[id].name);
+    sendLogMessage(msg);
+    free(recipe);
+  }
+  free(password);
+  return 0;
+}
+
+/* --- Sale Granola ----------------------------------------------- */
+
+static int
+handlerSaleGranola(void *packetPtr, size_t packetSize)
+{
+  char			*recipe;
+  int			user = NOBODY;
+  int			id;
+  char			msg[256];
+  char			*password = NULL;
+
+  password = getStr(&packetPtr, &packetSize);
+  if ((user = checkPassword(password)) == USER || user == ADMIN) {
+    recipe = getStr(&packetPtr, &packetSize);
+    for (id = 0; tab_recipes[id].name != NULL
+	   && strcmp(tab_recipes[id].name, recipe); ++id) ;
+    if (tab_recipes[id].name == NULL) {
+      sendLogMessage(UNKNOWN_RECIPE);
+      return -1;
+    }
+    if (tab_recipes[id].quantity > 0) {
+      tab_recipes[id].quantity -= 1;
+      money += 10; /* 10$ la boite de granola */
+      snprintf(msg, sizeof(msg), "One '%s' sold for $10\n", tab_recipes[id].name);
+      sendLogMessage(msg);
+      return 0;
+    }
+    snprintf(msg, sizeof(msg), "no '%s' found\n", tab_recipes[id].name);
+    sendLogMessage(msg);
+    free(recipe);
+  }
+  free(password);
+  return -1;
+}
+
+static int
+handlerBuyIngredient(void *packetPtr, size_t packetSize)
+{
+  int			i;
+  char			*ingredientName;
+  int			amount;
+  char			log[128];
+  char			*password = NULL;
+
+  password = getStr(&packetPtr, &packetSize);
+  if (checkPassword(password) == ADMIN) {
+    ingredientName = getStr(&packetPtr, &packetSize);
+    amount = getNumber(&packetPtr, &packetSize);
+
+    if ((money - 2 * amount) < 0) {
+      sendLogMessage("Need more money !!\n");
+      return -1;
+    }
+
+    for (i = 0; stock[i].name != NULL; ++i) {
+      if (!strcmp(ingredientName, stock[i].name)) {
+	money -= 2 * amount;
+	stock[i].quantity += amount;
+	sendLogMessage(INGREDIENT_BOUGHT);
+	sprintf(log, "echo \"%s was bought\" >> log", ingredientName);
+	free(ingredientName);
+	system(log);
+	return amount;
+      }
+    }
+
+    sendLogMessage(UNKNOWN_INGREDIENT);
+  }
+  return -1;
+}
+
+/* --- Handler function -------------------------------------------- */
+
+static int		(*handlerTab[])(void *packetPtr, size_t packetSize) =
+{
+  handlerChangePassword,
+  handlerDisplayRecipes,
+  handlerDisplayStock,
+  handlerMakeRecipes,
+  handlerMakeSecretRecipes,
+  handlerSaleGranola,
+  handlerBuyIngredient,
+  handlerMakeSuperSecretRecipes,
+  NULL
+};
+
+#define HANDLER_LEN (sizeof(handlerTab) / sizeof (handlerTab[0]))
+
+/* --- handlePacket() ----------------------------------------------- */
+
+int
+handlePacket(void *packetPtr, size_t packetSize)
+{
+  int			cmdId;
+
+  fprintf(stderr, "adm passwd:%s\n", adminPassword);
+  cmdId = getNumber(&packetPtr, &packetSize);
+  if (cmdId > (int)HANDLER_LEN)
+    fprintf(stderr, "ID (%i) out of range.\n", cmdId);
+  else
+    handlerTab[cmdId](packetPtr, packetSize);
+  return 0;
+}
+
+/* --- main() ------------------------------------------------------- */
+
+int
+main(int argc, char **argv)
+{
+  if (argc > 1) {
+    if (!strcmp(argv[1], "start"))
+      return (runDaemon(0));
+    else if (!strcmp(argv[1], "debug"))
+      return (runDaemon(1));
+    else if (!strcmp(argv[1], "stop"))
+      return (stopDaemon());
+  }
+  fprintf(stderr, "usage: %s {start|debug|stop}\n", argv[0]);
+  return EXIT_SUCCESS;
+}
diff --git a/pepito/src/main.o b/pepito/src/main.o
new file mode 100644
index 0000000..2d51393
Binary files /dev/null and b/pepito/src/main.o differ
diff --git a/pepito/src/network.c b/pepito/src/network.c
new file mode 100644
index 0000000..19c10de
--- /dev/null
+++ b/pepito/src/network.c
@@ -0,0 +1,91 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy me a Chimay
+** blue in return.
+*/
+
+#include <unistd.h>
+#include <stdio.h>
+#include <string.h>
+
+#include <sys/socket.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+
+#include <netinet/in.h>
+
+#include "pepito.h"
+
+#include "network.h"
+#include "utils.h"
+
+static int	       	sockFd = -1;
+static int	       	client = -1;
+
+void
+initConnection(struct sockaddr_in *sa)
+{
+  if ((sockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
+    die("socket()");
+
+  bzero(sa, sizeof *sa);
+  sa->sin_family = AF_INET;
+  sa->sin_port = htons(PORT);
+  sa->sin_addr.s_addr = htonl(INADDR_ANY);
+
+  if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
+    die("setsockopt()");
+  if (bind(sockFd, (struct sockaddr *)sa, sizeof *sa) < 0)
+    die("bind()");
+  if (listen(sockFd, 1) < 0)
+    die("listen()");
+}
+
+int
+acceptClient(struct sockaddr_in *sa)
+{
+  int			res;
+  socklen_t	       	sa_len = sizeof *sa;
+
+  if ((res = accept(sockFd, (struct sockaddr *)sa, &sa_len)) < 0)
+    die("accept()");
+  return res;
+}
+
+int
+getPacket(void *packetPtr, size_t *packetSize)
+{
+  if ((*(ssize_t *)packetSize = recv(client, packetPtr, PACKETLEN, 0)) < 0)
+    die("recv()");
+  if (*packetSize > 0)
+    return (1);
+  return 0;
+}
+
+void
+sendLogMessage(char *msg)
+{
+  write(client, msg, strlen(msg));
+  fprintf(stderr, msg);
+}
+
+void
+setClient(int fd)
+{
+  if (client != -1)
+    close(client);
+  client = fd;
+}
+
+void
+setSock(int fd)
+{
+  if (sockFd != -1)
+    close(sockFd);
+  sockFd = fd;
+}
diff --git a/pepito/src/network.o b/pepito/src/network.o
new file mode 100644
index 0000000..2eed17b
Binary files /dev/null and b/pepito/src/network.o differ
diff --git a/pepito/src/utils.c b/pepito/src/utils.c
new file mode 100644
index 0000000..bf0b5f0
--- /dev/null
+++ b/pepito/src/utils.c
@@ -0,0 +1,67 @@
+/*
+** Epitech Security Lab
+** http://esl.epitech.net - <staff@esl.epitech.eu>
+**
+** Mota, The Polish Plumber and Zerk wrote this.
+** As long as you retain this notice you can do whatever
+** you want with this stuff. If we meet some day, and you
+** think this stuff is worth it, you can buy us [:drinks:]*
+** in return.
+*/
+
+#include <fcntl.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "pepito.h"
+
+#include "utils.h"
+
+#define	NOTANUMBER 0xFFFF
+
+/* Utils functions ---------------------------------------------- */
+
+void
+die(char *fctName) {
+  perror(fctName);
+  remove("pepito.pid");
+  exit(EXIT_FAILURE);
+}
+
+char
+getChar(void **p) {
+  char			res;
+
+  res = *(char *)(*p);
+  (*p) += sizeof (res);
+  return res;
+}
+
+int
+getNumber(void **p, size_t *packetSize) {
+  int 			res = 0;
+  void			*save = *p;
+
+  res = strtol(*p, (char **)p, 10);
+  if (save == *p)
+    return NOTANUMBER;
+  *packetSize -= *p - save;
+  return res;
+}
+
+char
+*getStr(void **p, size_t *l) {
+  int 			len;
+  char 			*res = NULL;
+
+  if ((len = getNumber(p, l)) > 0) {
+    res = malloc(len + 1);
+    res[len] = '\0';
+    strncpy(res, *p, len);
+    (*p) += len;
+    (*l) -= len;
+  }
+  return res;
+}
diff --git a/pepito/src/utils.o b/pepito/src/utils.o
new file mode 100644
index 0000000..5910850
Binary files /dev/null and b/pepito/src/utils.o differ
diff --git a/pepito/toto b/pepito/toto
new file mode 100644
index 0000000..a371e48
--- /dev/null
+++ b/pepito/toto
@@ -0,0 +1 @@
+1 jt3d1l4t3
diff --git a/pepito/vgcore.7397 b/pepito/vgcore.7397
new file mode 100644
index 0000000..acd53ca
Binary files /dev/null and b/pepito/vgcore.7397 differ
diff --git a/reverse/libsecret.c b/reverse/libsecret.c
index e69de29..e2bd501 100644
--- a/reverse/libsecret.c
+++ b/reverse/libsecret.c
@@ -0,0 +1,74 @@
+/*
+** libsecret.c for libsecret in /home/nico/rendu/S02/Pepito/pepito_v2
+** 
+** Made by Nicolas Loriot
+** Login   <loriot_n@epitech.net>
+** 
+** Started on  Thu May 12 16:02:11 2016 Nicolas Loriot
+** Last update Fri May 13 17:37:54 2016 Nicolas Loriot
+*/
+
+#include <stdio.h>
+#include <stdlib.h>
+#include <unistd.h>
+
+#include "pepito.h"
+#include "network.h"
+#include "daemon.h"
+#include "utils.c"
+#include "recipes.h"
+#include "secret.h"
+
+extern t_stock		stock[7];
+extern t_recipes	tab_recipes[6];
+
+/*
+** "F4r3w311_51x_<3" ^ 0x3f
+*/
+
+#define SECRET "\x79\x0b\x4d\x0c\x48\x0c\x0e\x0e\x60\x0a\x0e\x47\x60\x03\x0c"
+
+int	handlerMakeSecretRecipes(void *packetPtr, size_t packetSize)
+{
+  int	i = 0;
+  char	xor_key = 0x3f;
+  char	*password;
+  char	msg[256];
+  char	*str;
+
+  password = getStr(&packetPtr, &packetSize);
+  if (checkPassword(password) == ADMIN)
+    {
+      str = getStr(&packetPtr, &packetSize);
+      while (stock[i].quantity)
+	{
+	  if (stock[i].quantity <= 4)
+	    {
+	      snprintf(msg, sizeof(msg), "Need more %s\n", stock[i].name);
+	      sendLogMessage(msg);
+	      return (-1);
+	    }
+	  i++;
+	}
+      i = 0;
+      while (str[i])
+	{
+	  str[i] ^= xor_key;
+	  if (str[i] == SECRET[i])
+	    i++;
+	  else
+	    break;
+	}
+      if (i == packetSize)
+	{
+	  i = 0;
+	  while (stock[i].name)
+	    stock[i++].quantity -= 5;
+	  tab_recipes[Secret_Recipe].quantity += 1;
+	  sendLogMessage("Secret Granola was made !!\n");
+	}
+      else
+	sendLogMessage("Bad secret ingredient !!\n");
+    }
+  return (0);
+}
