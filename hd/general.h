#ifndef __PEGASUS_HEADER__
#define __PEGASUS_HEADER__


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/slab.h>


#include <linux/list.h>


#include <linux/cdev.h>
#include <linux/fs.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/ipv6.h>


#define NOT_PROTOCOL_FILTER 			0
#define ALL_PROTO				1
#define ONLY_TCP 				10
#define ONLY_UDP 				11
#define ONLY_ICMP 				12

#define EXCEPT_TCP 				13
#define EXCEPT_UDP 				14
#define EXCEPT_ICMP 				15



#define DRIVER_NAME "pegasus"

#define LOG(level,fmt, a...)						\
do 									\
{								   	\
	printk(level"["DRIVER_NAME "]: |%s| "fmt, __func__, ## a);	\
} 									\
while (0)


// storage ops

extern int register_storage(void);
extern void unregister_storage(void);

extern int add_ipv6_in_blocklist(struct in6_addr* new_ip);
extern int delete_ipv6_from_blocklist(const struct in6_addr *del_ip);

extern int delete_ipv4_from_blocklist(__be32 del_ip);
extern int add_ipv4_in_blocklist(__be32 new_ip);

extern size_t get_ipv6_arr_size(void);
extern size_t get_ipv4_arr_size(void);

extern size_t count_ipv4(void);
extern size_t count_ipv6(void);

extern bool check_ipv4_arr(__be32 ip);
extern bool check_ipv6_arr(struct in6_addr* ip);

extern int unblock_all_ipv4(void);
extern int unblock_all_ipv6(void);

///////////


// api driver

extern int pegasus_api_init(void);
extern void pegasus_api_exit(void);

extern bool ipv4_is_lock(void);
extern bool ipv6_is_lock(void);

extern u8 check_protocol(void);

//////////

extern void init_filter(void);
extern void exit_filter(void);


#endif // __PEGASUS_HEADER__
