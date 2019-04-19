//关于组播地址：239.0.0.0～239.255.255.255 为本地管理组播地址，仅在特定的本地范围内有效。
#include "smart_config.h"


const char *broadcastip = "255.255.255.255";
char data[3] = {0xAA, 0xCD, 0x12};
char mcip[16] = {0};
PkgUnit *package = NULL;
static int secCount = 0;
int roundCount = 0;
static struct itimerval oldtv;


// 定时任务
void set_timer()  
{  
    struct itimerval itv;  
    itv.it_interval.tv_sec = 1;  
    itv.it_interval.tv_usec = 0;  
    itv.it_value.tv_sec = 1;  
    itv.it_value.tv_usec = 0;  
    setitimer(ITIMER_REAL, &itv, &oldtv);  
}  
   
void signal_handler(int m)  
{  
    secCount++;  
    printf("[%d]send %d rounds, Password: %s\n", secCount, roundCount, PASSWORD);  
}  
   
void monitorInit()
{
	signal(SIGALRM, signal_handler);  
    set_timer(); 
}

int smartconfig_socket(void)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == sockfd)
	{
		printf("[initUdpMultiCastSender]socket fail\n");
		return -1;
	}
	return sockfd;
}

size_t encode_package(PkgUnit **pack_p, char *password)
{
	size_t pwdlen = strlen(password);
	size_t tmplen = 0;
    int i;
	int idx = 0;
    
    if(pwdlen%2)
    {
        tmplen = pwdlen + 1;
    }
    else
    {
        tmplen = pwdlen + 2;
    }

    char *tmppwd = malloc(tmplen);
    memset(tmppwd, 0, tmplen);
    memcpy(tmppwd, password, strlen(password));
    
	size_t packageNum = (tmplen/2);
	(*pack_p) = (PkgUnit *)malloc(packageNum * sizeof(PkgUnit));
    memset(*pack_p, 0, packageNum * sizeof(PkgUnit));    
	
	for (i = 0; i < packageNum; i++)
	{
		(*pack_p)[i].index = i;
		(*pack_p)[i].byte_l = tmppwd[idx];
		(*pack_p)[i].byte_h = tmppwd[idx+1];
		idx = idx + 2;
	}
    free(tmppwd);
    
	return packageNum;
}

unsigned char checksum_2b(PkgUnit unit)// 对3个字节进行2个bit长度的校验
{
	unsigned char chk = unit.index;
	chk ^= unit.byte_l;
	chk ^= unit.byte_h;
	chk = chk ^ (chk<<2) ^ (chk<<4) ^ (chk<<6 &0xFF);
	chk = chk >> 1;
	unsigned char result = ((chk&0x60) | (unit.index & 0x1F))&0xFF;
	
	return result&0xFF;
}

uint32_t get_broadcast_ip(const char *p)
{   
    struct in_addr bdip_n; 
    
    inet_aton(p, &bdip_n);
    
    return bdip_n.s_addr;
}

uint32_t get_multicast_ip(int index, char *p)
{   
	unsigned char ip[4];
    struct in_addr mcip_n; 
    
	ip[0] = 239;
	ip[1] = checksum_2b(package[index]);
	ip[2] = package[index].byte_l;
	ip[3] = package[index].byte_h;           
    sprintf(p, "239.%d.%d.%d", ip[1], ip[2], ip[3]); 
    inet_aton(p, &mcip_n);
    
    return mcip_n.s_addr;
}


int sendUdp(int sockfd, uint32_t targetIp, uint16_t port, void *data, uint32_t len)
{
	struct sockaddr_in destAddr;
    
	destAddr.sin_family = AF_INET;
	destAddr.sin_addr.s_addr = targetIp;
	destAddr.sin_port = htons(port);
	int sendLen = sendto(sockfd,data,len,0,(struct sockaddr *)(&destAddr),sizeof(struct sockaddr));
    
	return sendLen;
}

int main(int argc, char const *argv[])
{ 
    uint32_t net_mcip = 0,net_bcip = 0;
    size_t i;
    
    monitorInit(); 
	int sockfd = smartconfig_socket();
    net_bcip = get_broadcast_ip(broadcastip); 
	size_t packageLen = encode_package(&package, PASSWORD);	    

	while(1)
	{
        sendUdp(sockfd, net_bcip, PORT, data, 3); //广播发送0xABCD
		usleep(5000);//休眠5ms
		
		for (i = 0; i < packageLen; i++)
		{        
            net_mcip = get_multicast_ip(i, mcip);  
			sendUdp(sockfd, net_mcip, PORT, "0", strlen("0")); //组播发送
			usleep(5000);//休眠5ms
		}
		roundCount++;
	}

	if(sockfd)
	{
		close(sockfd);
	}
	return 0;
}
