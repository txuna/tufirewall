#ifndef _COMMON_H
#define _COMMON_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include <linux/ioctl.h>

#include <linux/list.h>

#define MAXINUM_RULE_NAME 45

#define TU_RULE_MATCH 1 
#define TU_RULE_NONE_MATCH 2

#define WHEN_IN_ZONE 1
#define WHEN_OUT_ZONE  2

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

struct rule_data
{
	char name[MAXINUM_RULE_NAME];
	__u8 action; //NF_ACCEPT, NF_DROP
	__u8 protocol; 
	__u8 when;   //determin NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT

	__u32 ip;
	__u16 port;
};

struct rule_list
{
	struct rule_data *data;
	struct list_head list;	
};

#endif
