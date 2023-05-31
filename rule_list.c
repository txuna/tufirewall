#include "rule_list.h"

int push_rule(struct list_head *head, struct rule_data *data)
{
	struct rule_list *rule = (struct rule_list *)kmalloc(sizeof(struct rule_list), GFP_KERNEL);
	if(rule == NULL)
	{
		printk(KERN_INFO "kmalloc(): Failed Allocate Rule\n");
		return 1; 
	}

	rule->data = data;
	list_add_tail(&rule->list, head);
	printk(KERN_INFO "Push Rule\n");

	return 0;
}

void show_all_rules(struct list_head *head)
{
	struct rule_list *temp = NULL; 
	struct list_head *pos = NULL; 

	list_for_each(pos, head)
	{
		temp = list_entry(pos, struct rule_list, list); 
		printk(KERN_INFO "RULE NAME: %s", temp->data->name);
	}
	return;
}

void del_all_rules(struct list_head *head)
{
	struct rule_list *temp = NULL; 
	struct list_head *pos = NULL;
	struct list_head *next = NULL;

	list_for_each_safe(pos, next, head)
	{
		temp = list_entry(pos, struct rule_list, list); 
		printk(KERN_INFO "DELETE RULE : %s", temp->data->name);
		list_del(pos);
		kfree(temp->data);
		kfree(temp);
	}
}

