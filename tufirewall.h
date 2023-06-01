

static int tu_inet_pton_ipv4(const char* ip_str, __u32* ip_addr);
static int packet_in_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int packet_out_zone_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int processing_hook(void);
static void setup_testrule(void);
static int rule_match_icmp(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match_tcp(int zone, struct sk_buff *skb, struct rule_data *rule);
static int rule_match_udp(int zone, struct sk_buff *skb, struct rule_data *rule);
