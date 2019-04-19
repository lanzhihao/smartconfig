#ifndef __SMART_CONFIG_H__
#define __SMART_CONFIG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>  // for struct sockaddr_in
#include <fcntl.h> //for msleep
#include <unistd.h> // for close
#include <arpa/inet.h> // for close
#include <sys/time.h> //for set_timer
#include <signal.h> //for set_timers

#define PORT 10000
#define SSID "Bhu-500Env"
#define PASSWORD "gome1234"

typedef struct{
	unsigned char index;
	unsigned char byte_l;
	unsigned char byte_h;
}PkgUnit;

#endif
