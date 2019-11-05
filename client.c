//#include "contiki.h"
#include "cfs.h"
//#include "lib/random.h"
//#include "sys/ctimer.h"
//#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
//#include "net/ip/uip-udp-packet.h"
//#include "sys/ctimer.h"

//#include <stdio.h>
//#include <string.h>
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define UDP_EXAMPLE_ID  190
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

//#ifndef PERIOD
//#define PERIOD 60
//#endif

///#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		( 60 * CLOCK_CONF_SECOND)
//#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
//#define MAX_PAYLOAD_LEN		30

//#include "dev/sha1.h"
//#define SHA_BLOCK_SIZE 20
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
PROCESS(new,"Client");
AUTOSTART_PROCESSES(&new);
//static char buf[21]="Welcome to Dark World";
static char cor[8]="Corrupt";
//static char buf1[32];
static int code(int flag)
{
	int fd;	
	//BYTE buf1[SHA1_BLOCK_SIZE];
	/*if(flag==-1){	
		fd = cfs_open("code", CFS_WRITE);
		if(fd>=0){
			//int idx;
    			//BYTE data = (BYTE *)buf;
			//SHA1_CTX ctx;
    			//sha1_init(&ctx);
    			//sha1_update(&ctx, buf, strlen(data));
    			//sha1_final(&ctx, buf1);			
			cfs_write(fd,buf,sizeof(buf));
			cfs_close(fd);
			uip_udp_packet_sendto(client_conn, buf, strlen(buf),&server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
		}
	}
	else*/ 
	if(flag ==4){
		fd = cfs_open("code", CFS_WRITE + CFS_APPEND);
		cfs_write(fd,cor,8);
		cfs_close(fd);
		static char buf1[32];
		fd = cfs_open("code", CFS_READ );
		cfs_read(fd,buf1,sizeof(buf1));
		uip_udp_packet_sendto(client_conn, buf1, sizeof(buf1),&server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
		cfs_close(fd);
	}
	else{ 
		fd = cfs_open("code", CFS_READ );
		if(fd>=0){
			static char buf1[32];			
			cfs_read(fd,buf1,sizeof(buf1));
			uip_udp_packet_sendto(client_conn, buf1, sizeof(buf1),&server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
			cfs_close(fd);
		}
		
	}
	flag++;
	return flag;	
}
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

/* The choice of server address determines its 6LoPAN header compression.
 * (Our address will be compressed Mode 3 since it is derived from our link-local address)
 * Obviously the choice made here must also be selected in udp-server.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 *
 * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}
PROCESS_THREAD(new,ev,data){
	
	static struct etimer periodic;
  	
	static int flag=-1;
	PROCESS_BEGIN();

  	PROCESS_PAUSE();

  	set_global_address();
  
  	PRINTF("UDP client process started\n");

  	print_local_addresses();
  	/* new connection with remote host */
  	client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
  	if(client_conn == NULL) {
    		PRINTF("No UDP connection available, exiting the process!\n");
    		PROCESS_EXIT();
  	}
  	udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

  	PRINTF("Created a connection with the server ");
  	PRINT6ADDR(&client_conn->ripaddr);
  	PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  	etimer_set(&periodic, SEND_INTERVAL);
  	while(1) {
    		PROCESS_YIELD();
    		if(ev == PROCESS_EVENT_TIMER) {
			printf("\nFlag= %d\n\n",flag);      			
			flag=code(flag);
			etimer_reset(&periodic);
    		}
    	}

  	PROCESS_END();
}

