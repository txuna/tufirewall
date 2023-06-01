#include "common.h"
#include "rule_list.h"

// add rule 
#define ADD_RULE _IOW('a','a',struct rule_data*)

// remove rule
#define DELETE_RULE _IOW('b','b', __u32*)

struct rule_list tu_rules;

struct nf_hook_ops *tu_nf_local_in_ops = NULL;
struct nf_hook_ops *tu_nf_local_out_ops = NULL;

dev_t dev = 0;
static struct class *dev_class;
static struct cdev etx_cdev;

static int tu_inet_pton_ipv4(const char* ip_str, __u32* ip_addr);
static int packet_in_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int packet_out_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int processing_hook(void);
static void setup_testrule(void);
static int rule_match_icmp(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match_tcp(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match_udp(int zone, struct sk_buff *skb, struct rule_data *rule);

static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);
static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static int etx_release(struct inode *inode, struct file *file);
static int etx_open(struct inode *inode, struct file *file);
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/*
* File operation sturcture
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = etx_read,
        .write          = etx_write,
        .open           = etx_open,
        .unlocked_ioctl = etx_ioctl,
        .release        = etx_release,
};

static int etx_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Device File Opened\n");
	return 0;
}

static int etx_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Device File Closed\n");
	return 0;
}

static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	printk(KERN_INFO "Read Function\n");
	return 0;
}

static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	printk(KERN_INFO "Write Function\n");
	return 0;
}

static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	__u32 value;
	struct rule_data rule_arg;  
	switch(cmd)
	{
		case ADD_RULE:
			if(copy_from_user(&rule_arg, (struct rule_data *)arg, sizeof(struct rule_data)))
			{
				printk(KERN_INFO "No Rule Data From Userspace\n");
				break;
			}

			printk(KERN_INFO "Received value from user space\n");
			printk(KERN_INFO "RULE NAME : %s\n", rule_arg.name);
			break; 

		case DELETE_RULE:
			if(copy_from_user(&value, (__u32*)arg, sizeof(value)))
			{
				printk(KERN_INFO "Error Delete Command\n");
				break;
			}
			printk(KERN_INFO "Delete All Rules\n");
			break;

		default:
			break;
	}

	return 0;
}


static int packet_in_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct list_head *pos = NULL; 
	struct rule_list *cur_rule = NULL;
	struct sk_buff *sb = NULL;

	if(!skb)
	{
		return NF_ACCEPT;
	}

	sb = skb;

	list_for_each(pos, &tu_rules.list)
	{
		cur_rule = list_entry(pos, struct rule_list, list); 
		if(cur_rule->data->when == WHEN_IN_ZONE)
		{
			if(rule_match(WHEN_IN_ZONE, sb, cur_rule->data) == TU_RULE_MATCH)
			{
				if(cur_rule->data->action == NF_ACCEPT)
				{
					printk(KERN_INFO "[TU FIREWALL] [IN ZONE] ACCEPT RULE : %s\n", cur_rule->data->name);
				}

				else if(cur_rule->data->action == NF_DROP)
				{
					printk(KERN_INFO "[TU FIREWALL] [IN ZONE] DROP RULE : %s\n", cur_rule->data->name);
				}

				return cur_rule->data->action;
			}
		}
	}
    
	return NF_ACCEPT;
}


static int packet_out_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct list_head *pos = NULL; 
	struct rule_list *cur_rule = NULL;
	struct sk_buff *sb = NULL;

	if(!skb)
	{
		return NF_ACCEPT;
	}

	sb = skb;

	list_for_each(pos, &tu_rules.list)
	{
		cur_rule = list_entry(pos, struct rule_list, list);
		if(cur_rule->data->when == WHEN_OUT_ZONE)
		{
			if(rule_match(WHEN_OUT_ZONE, sb, cur_rule->data) == TU_RULE_MATCH)
			{
				if(cur_rule->data->action == NF_ACCEPT)
				{
					printk(KERN_INFO "[TU FIREWALL] [OUT ZONE] ACCEPT RULE : %s\n", cur_rule->data->name);
				}

				else if(cur_rule->data->action == NF_DROP)
				{
					printk(KERN_INFO "[TU FIREWALL] [OUT ZONE] DROP RULE : %s\n", cur_rule->data->name);
				}
				return cur_rule->data->action;
			}
		}
	}
	
	return NF_ACCEPT;
}


static int rule_match(int zone, struct sk_buff *skb, struct rule_data *rule)
{
	struct iphdr *iph = NULL;
	iph = ip_hdr(skb);

	if(iph == NULL)
	{
		printk(KERN_INFO "IP Header has NULL in rule_match()\n");
		return TU_RULE_NONE_MATCH;
	}

	if(iph->protocol != rule->protocol)
	{
		return TU_RULE_NONE_MATCH;
	}

	if(iph->protocol == IPPROTO_ICMP)
	{
		return rule_match_icmp(zone, skb, rule);
	}

	else if(iph->protocol == IPPROTO_TCP)
	{
		return rule_match_tcp(zone, skb, rule);
	}

	else if(iph->protocol == IPPROTO_UDP)
	{
		return rule_match_udp(zone, skb, rule);
	}

	return TU_RULE_NONE_MATCH;
}

static int rule_match_icmp(int zone, struct sk_buff *skb, struct rule_data *rule)
{
	struct iphdr *iph = NULL;
	__u32 sip, dip = 0; 
	iph = ip_hdr(skb); 
	sip = ntohl(iph->saddr); 
	dip = ntohl(iph->daddr);

	if(zone == WHEN_IN_ZONE)
	{
		if(sip == rule->ip)
		{
			return TU_RULE_MATCH;
		}
	}

	else if(zone == WHEN_OUT_ZONE)
	{
		if(dip == rule->ip)
		{
			return TU_RULE_MATCH;
		}
	}

	return TU_RULE_NONE_MATCH;
}

static int rule_match_tcp(int zone, struct sk_buff *skb, struct rule_data *rule)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	__u32 sip = ntohl(iph->saddr); 
	__u32 dip = ntohl(iph->daddr);
	__u16 dport = ntohs(tcph->dest);

	if(zone == WHEN_IN_ZONE)
	{
		if(sip == rule->ip && dport == rule->port)
		{
			return TU_RULE_MATCH;
		}
	}

	else if(zone == WHEN_OUT_ZONE)
	{		
		if(dip == rule->ip && dport == rule->port)
		{
			return TU_RULE_MATCH;
		}
	}

	return TU_RULE_NONE_MATCH;
}

static int rule_match_udp(int zone, struct sk_buff *skb, struct rule_data *rule)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *udph = tcp_hdr(skb);
	__u32 sip = ntohl(iph->saddr); 
	__u32 dip = ntohl(iph->daddr);
	__u16 dport = ntohs(udph->dest);

	if(zone == WHEN_IN_ZONE)
	{
		if(sip == rule->ip && dport == rule->port)
		{
			return TU_RULE_MATCH;
		}
	}

	else if(zone == WHEN_OUT_ZONE)
	{		
		if(dip == rule->ip && dport == rule->port)
		{
			return TU_RULE_MATCH;
		}
	}

	return TU_RULE_NONE_MATCH;
}


// when에 따라 IN, OUT 세팅
static int processing_hook(void)
{
	unsigned int out_priority = NF_IP_PRI_FIRST; 
	unsigned int in_priority = NF_IP_PRI_FIRST;

	tu_nf_local_in_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(tu_nf_local_in_ops == NULL)
	{
		printk(KERN_INFO "kcalloc(): Failed Allocate nf_local_in_ops in kernelspace\n");	
		return -1;
	}

	tu_nf_local_in_ops->hook = (nf_hookfn*)packet_in_zone_handler; 
	tu_nf_local_in_ops->hooknum = NF_INET_LOCAL_IN; 
	tu_nf_local_in_ops->pf = NFPROTO_IPV4; 
	tu_nf_local_in_ops->priority = in_priority;

	tu_nf_local_out_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(tu_nf_local_out_ops == NULL)
	{
		printk(KERN_INFO "kcalloc(): Failed Allocate nf_local_out_ops in kernelspace\n");	
		kfree(tu_nf_local_in_ops);
		return -1;
	}

	tu_nf_local_out_ops->hook = (nf_hookfn*)packet_out_zone_handler;
	tu_nf_local_out_ops->hooknum= NF_INET_LOCAL_OUT;
	tu_nf_local_out_ops->pf = NFPROTO_IPV4; 
	tu_nf_local_out_ops->priority = out_priority;

	return 0;
}

static void setup_testrule(void)
{
	struct rule_data *rule = NULL;
	__u32 ip_value = 0;
	
	rule = (struct rule_data *)kcalloc(1, sizeof(struct rule_data), GFP_KERNEL); 

	if(rule != NULL)
	{
		if(tu_inet_pton_ipv4("8.8.8.8", &ip_value) == 0)
		{
			kfree(rule);
			return;
		}
		strncpy(rule->name, "[name server icmp accept rule]", strlen("[name server icmp accept rule]"));
		rule->action = NF_ACCEPT; 
		rule->protocol = IPPROTO_ICMP; 
		rule->when = WHEN_OUT_ZONE;
		rule->ip = ip_value;
		push_rule(&tu_rules.list, rule);
	}

	rule = (struct rule_data *)kcalloc(1, sizeof(struct rule_data), GFP_KERNEL); 

	if(rule != NULL)
	{
		if(tu_inet_pton_ipv4("1.1.1.1", &ip_value) == 0)
		{
			kfree(rule);
			return;
		}
		strncpy(rule->name, "[google name server drop]", strlen("[google name server drop]"));
		rule->action = NF_DROP; 
		rule->protocol = IPPROTO_ICMP; 
		rule->when = WHEN_OUT_ZONE;
		rule->ip = ip_value;
		push_rule(&tu_rules.list, rule);
	}
	
	rule = (struct rule_data *)kcalloc(1, sizeof(struct rule_data), GFP_KERNEL); 

	if(rule != NULL)
	{
		if(tu_inet_pton_ipv4("200.200.200.200", &ip_value) == 0)
		{
			kfree(rule);
			return;
		}
		strncpy(rule->name, "[home rule]", strlen("[home rule]"));
		rule->action = NF_DROP; 
		rule->protocol = IPPROTO_TCP; 
		rule->when = WHEN_IN_ZONE;
		rule->ip = ip_value;
		rule->port = 50000;
		push_rule(&tu_rules.list, rule);
	}
}

static int tu_inet_pton_ipv4(const char* ip_str, __u32* ip_addr) {
    __u32 result = 0;
    unsigned long octet;
    int shift = 24;
	int i=0;

    for (i=0; i < 4; i++) {
        int num = 0;
        while (*ip_str && *ip_str != '.') {
            if (*ip_str >= '0' && *ip_str <= '9') {
                num = num * 10 + (*ip_str - '0');
            } else {
                return 0;  // 유효하지 않은 문자가 포함된 경우
            }
            ip_str++;
        }
        if (num < 0 || num > 255) {
            return 0;  // 유효하지 않은 숫자 범위
        }
        octet = num;
        result |= (octet << shift);
        shift -= 8;
        if (*ip_str) {
            ip_str++;  // '.' 문자 건너뛰기
        }
    }
    *ip_addr = result;
	
    return 1;
}

static int __init tu_firewall_init(void)
{
	int ret = 0;
	printk(KERN_INFO "load module : tu firewall"); 

	if((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) < 0)
	{
		printk(KERN_INFO "Cannot allocate major number\n");
		return -1;
	}

	printk(KERN_INFO "Major = %d Minor = %d\n", MAJOR(dev), MINOR(dev));

	// Creating cdev structure 
	cdev_init(&etx_cdev, &fops);

	// Adding character device to the system 
	if((cdev_add(&etx_cdev, dev, 1)) < 0)
	{
		printk(KERN_INFO "Cannot add the device to the system\n");
		goto r_class; 
	}

	// Creating struct class 
	if(IS_ERR(dev_class = class_create(THIS_MODULE, "etx_class")))
	{
		printk(KERN_INFO "Cannot create the struct class\n");
		goto r_class; 
	}

	// Creating Device 
	if(IS_ERR(device_create(dev_class, NULL, dev, NULL, "etx_device")))
	{
		printk(KERN_INFO "Cannot create the Device\n");
		goto r_device; 
	}

	printk(KERN_INFO "Successfully Device Driver Insert\n");

	INIT_LIST_HEAD(&tu_rules.list);
	
	// rule processing 
	//setup_testrule();

	ret = processing_hook();
	if(ret != -1)
	{
		nf_register_net_hook(&init_net, tu_nf_local_in_ops); 
		nf_register_net_hook(&init_net, tu_nf_local_out_ops);
	}

	return 0;

r_device:
	class_destroy(dev_class); 

r_class:
	unregister_chrdev_region(dev, 1);
	return -1;
}

static void __exit tu_firewall_exit(void)
{
	printk(KERN_INFO "unload module : tu firewall");

	device_destroy(dev_class, dev);
	class_destroy(dev_class); 
	cdev_del(&etx_cdev); 
	unregister_chrdev_region(dev, 1); 
	//delete and free rules and unregister hook
	del_all_rules(&tu_rules.list);

	nf_unregister_net_hook(&init_net, tu_nf_local_in_ops);
	nf_unregister_net_hook(&init_net, tu_nf_local_out_ops);

	kfree(tu_nf_local_in_ops);
	kfree(tu_nf_local_out_ops);
}

module_init(tu_firewall_init); 
module_exit(tu_firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tuuna");
MODULE_DESCRIPTION("Firewall"); 
MODULE_VERSION("1.0.0");
