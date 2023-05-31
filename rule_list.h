#ifndef _RULE_LIST_H
#define _RULE_LIST_H

#include "common.h"

int push_rule(struct list_head *head, struct rule_data *data);

void show_all_rules(struct list_head *head);

void del_all_rules(struct list_head *head);

#endif
