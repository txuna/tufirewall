#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define MAX_RULES 100

#define 	NF_DROP   0
#define 	NF_ACCEPT   1

#define IPPROTO_UDP 17 
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6 

#define WHEN_IN_ZONE 1
#define WHEN_OUT_ZONE  2

#define MAXINUM_RULE_NAME 45

// add rule 
#define ADD_RULE _IOW('a','a',struct Rule*)

// remove rule
#define DELETE_RULE _IOW('b','b', __uint32_t*)

const char* path = "../tu.conf";

struct Rule
{
    char name[MAXINUM_RULE_NAME];
    __uint8_t action;
    __uint8_t protocol; 
    __uint8_t when;

    __uint32_t ip;
    __uint16_t port;
    
};


int processing_parse_line(char *buf, struct Rule *rule);
int is_end_rule(char *buf);
int is_start_rule(char *buf);
void skip_whitespace(char *buf, int *pos);
char* fetch_token(char *buf, int *pos);
int is_comment_line(char *buf);
char* read_rules(const char* filename);
long get_file_size(FILE* file);
int create_rule(char *key, char *value, struct Rule *rule);
char* load_line(char *buf, int *pos);
int parse_rules(const char *filename, struct Rule *rules);
void DumpHex(const void* data, int size);
int tu_inet_pton_ipv4(const char* ip_str, __uint32_t* ip_addr);
int add_rule_to_kernel(int fd, struct Rule *rule);
int delete_all_rule_to_kernel(int fd);


long get_file_size(FILE* file)
{
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    rewind(file);
    return size;
}

char* read_rules(const char* filename)
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        return 0;
    }

    int file_size = get_file_size(file);
    char* file_buf = (char*)malloc(sizeof(char) * file_size); 
    if(file_buf == NULL)
    {
        printf("malloc(): Failed Allocate Memory in Userspace\n");
        return NULL;
    }

    size_t bytesRead = fread(file_buf, sizeof(char), file_size, file);
    if (bytesRead != file_size) {
        printf("fread(): Failed to read file: %s\n", filename);
        free(file_buf);
        fclose(file);
        return NULL;
    }
    file_buf[file_size] = '\0';

    DumpHex(file_buf, file_size);

    fclose(file);
    return file_buf;
}

// #이나 개행이라면 패스
int is_comment_line(char *buf)
{
    int pos = 0;
    if(buf[pos] == '#' || buf[pos] == '\n')
    {
        return 1;
    }

    return 0;
}

char* fetch_token(char *buf, int *pos)
{
    int first_pos = *pos;

    if(buf[*pos] == '\0')
    {
        return NULL;
    }

    //space, tab, new line, null까지 읽음 
    while(1)
    {
        if(buf[*pos] == ' ' || buf[*pos] == '\t' || buf[*pos] == '\n' || buf[*pos] == '\0')
        {
            break; 
        }
        *pos += 1;
    }

    char *str = (char*)calloc(1, sizeof(char) * (*pos - first_pos) + 1);
    if(str == NULL)
    {
        return NULL;
    }

    strncpy(str, &buf[first_pos], *pos-first_pos);
    str[*pos - first_pos] = '\0';

    return str;
}

void skip_whitespace(char *buf, int *pos)
{
    if(buf[*pos] == '\0')
    {
        return;
    }

    while(buf[*pos] == ' ' || buf[*pos] == '\t')
    {
        *pos += 1;
    }
}

// 룰의 시작인지 확인
int is_start_rule(char *buf)
{
    if(strncmp(buf, "[rule]", strlen("[rule]")) == 0)
    {
        return 1;
    }
    return 0;
}

// 룰의 끝인지 
int is_end_rule(char *buf)
{
    if(strncmp(buf, "[end]", strlen("[end]")) == 0)
    {
        return 1;
    }
    return 0;
}

// key = value 
int processing_parse_line(char *buf, struct Rule *rule)
{
    int pos = 0;
    char *key = NULL; 
    char *value = NULL;
    char *assign = NULL;

    skip_whitespace(buf, &pos); 
    // read key
    key = fetch_token(buf, &pos); 
    if(key == NULL)
    {
        return 0;
    }

    skip_whitespace(buf, &pos); 
    // read = 
    assign = fetch_token(buf, &pos); 
    if(assign == NULL)
    {
        free(key);
        return 0;
    }

    skip_whitespace(buf, &pos); 
    // read value
    value = fetch_token(buf, &pos);
    if(value == NULL)
    {
        free(key); 
        free(assign);
        return 0;
    } 

    if(create_rule(key, value, rule) == 0)
    {
        free(key);
        free(assign); 
        free(value);

        printf("Config file Syntax Error, Invalid Key = Value\n");
        return 0;
    }
    free(key);
    free(assign); 
    free(value);

    return 1;
}

int create_rule(char *key, char *value, struct Rule *rule)
{
    if(strncmp(key, "WHEN", strlen("WHEN")) == 0)
    {
        if(strncmp(value, "INPUT", strlen("INPUT")) == 0)
        {
            rule->when = WHEN_IN_ZONE; 
        }
        else if(strncmp(value, "OUTPUT", strlen("OUTPUT")) == 0)
        {
            rule->when = WHEN_OUT_ZONE;
        }
        else
        {
            return 0;
        }
    }

    else if(strncmp(key, "ACTION", strlen("ACTION")) == 0)
    {
        if(strncmp(value, "DROP", strlen("DROP")) == 0)
        {
            rule->action = NF_DROP; 
        }
        else if(strncmp(value, "ACCEPT", strlen("ACCEPT")) == 0)
        {
            rule->action = NF_ACCEPT;
        }
        else
        {
            return 0;
        }
    }

    else if(strncmp(key, "IP", strlen("IP")) == 0)
    {
        __uint32_t ip_long = 0;
        if(tu_inet_pton_ipv4(value, &ip_long) == 0)
        {
            return 0;
        }
        rule->ip = ip_long;
    }

    else if(strncmp(key, "PROTOCOL", strlen("PROTOCOL")) == 0)
    {
        if(strncmp(value, "TCP", strlen("TCP")) == 0)
        {
            rule->protocol = IPPROTO_TCP;
        }
        else if(strncmp(value, "UDP", strlen("UDP")) == 0)
        {
            rule->protocol = IPPROTO_UDP;
        }
        else if(strncmp(value, "ICMP", strlen("ICMP")) == 0)
        {
            rule->protocol = IPPROTO_ICMP;
        }
        else
        {
            return 0;
        }
    }

    else if(strncmp(key, "PORT", strlen("PORT")) == 0)
    {
        printf("port string : %s\n", value);
        long int port = strtol(value, NULL, 10);
        if(port == 0)
        {
            return 0;
        }
        if(port > 65536)
        {
            return 0;
        }
        rule->port = (__uint16_t)port;
    }

    else if(strncmp(key, "NAME", strlen("NAME")) == 0)
    {
        memset(rule->name, 0, MAXINUM_RULE_NAME);
        strncpy(rule->name, value, MAXINUM_RULE_NAME - 1);
    }

    return 1;
}

// return one line in buffer
char* load_line(char *buf, int *pos)
{
    char* line = NULL;
    int first_pos = *pos; 

    if(buf[*pos] == '\0')
    {
        return NULL; 
    }

    while(buf[*pos] != '\n')
    {
        if(buf[*pos] == '\0')
        {
            break; 
        }

        *pos += 1;
    }

    if(buf[*pos] == '\n')
    {
        *pos += 1;
    }
    
    line = (char*)calloc(1, sizeof(char) * (*pos - first_pos) + 1);
    if(line == NULL)
    {
        return NULL;
    }

    strncpy(line, &buf[first_pos], *pos-first_pos);
    
    line[*pos - first_pos] = '\0';
    return line;
}

int parse_rules(const char *filename, struct Rule *rules)
{
    char* line = NULL;
    char* file_buf = read_rules(filename);
    int is_parsing_rule = 0;
    int rule_count = 0;
    int pos = 0;
    struct Rule rule;

    if(file_buf == NULL)
    {
        printf("Cannot read file : %s\n", filename);
        return 0;
    }

    
    while(file_buf[pos] != '\0')
    {
        line = load_line(file_buf, &pos);
        if(line == NULL)
        {
            break; 
        }
        
        // comment라인이 아니라면 파서 실행
        if(is_comment_line(line) == 1)
        {
            free(line);
            continue;
        }

        // rule start시 현재 rule 파서중인지 확인할 필요 있음
        // is_current_rule_parsing이 0이라면 룰 파싱 시도 
        // 1이라면 이전에 진행했던 룰 파싱 검증
        if(is_start_rule(line) == 1)
        {
            if(is_parsing_rule == 1)
            {
                printf("Config file Syntax Error, Exptected [end]\n");
                free(line); 
                break;
            }
            memset(&rule, 0, sizeof(struct Rule));
            is_parsing_rule = 1;
        }

        else if(is_end_rule(line) == 1)
        {
            if(is_parsing_rule == 0)
            {
                printf("Config file Syntax Error, Expected [rule]\n");
                free(line);
                break;
            }
            // rule 검증 
            
            rules[rule_count] = rule;
            printf("Parsing Rule\n");
            rule_count += 1;
            is_parsing_rule = 0;
            memset(&rule, 0, sizeof(struct Rule));
        }
        else
        {
            if(is_parsing_rule != 1)
            {
                printf("Config file Syntax Error, Expected [rule]\n");
                free(line);
                break;
            }

            if(processing_parse_line(line, &rule) == 0)
            {
                free(line); 
                break;
            }
            
        }
        free(line);
    }

    free(file_buf);
    return rule_count;
}

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

int tu_inet_pton_ipv4(const char* ip_str, __uint32_t* ip_addr) {
    __uint32_t result = 0;
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

int delete_all_rule_to_kernel(int fd)
{
    __uint32_t value = 3; 
    ioctl(fd, DELETE_RULE, (__uint32_t*)&value);
}

int add_rule_to_kernel(int fd, struct Rule *rule)
{
    ioctl(fd, ADD_RULE, (struct Rule*)rule); 
}

int main() 
{
    struct Rule *rules = (struct Rule *)calloc(1, sizeof(struct Rule) * MAX_RULES);
    if(rules == NULL)
    {
        printf("calloc(): Failed Allocate Memory In Userspace\n");
        return 1;
    }

    int ruleCount = parse_rules(path, rules);
    printf("Parsing Rule Count : %d\n", ruleCount);
    if (ruleCount == 0) 
    {
        printf("No rules found or error occurred.\n");
        return 1;
    }

    for(int i=0;i<ruleCount;i++)
    {
        printf("RULE NAME : %s\n", rules[i].name);
        printf("RULE PROTOCOL : %d\n", rules[i].protocol);
        printf("RULE IP : %d\n", rules[i].ip);
        printf("RULE WHEN : %d\n", rules[i].when);
        printf("RULE ACTION : %d\n", rules[i].action);
        if(rules[i].protocol != IPPROTO_ICMP)
        {
            printf("RULE PORT : %hu\n", rules[i].port);
        }
        printf("\n");
    }

    int fd; 
    fd = open("/dev/etx_device", O_RDWR); 
    if(fd < 0)
    {
        printf("Cannot open device file\n"); 
        printf("Please check your permission\n");
        return 0;
    }

    printf("DELETE ALL RULES\n");
    delete_all_rule_to_kernel(fd);
    sleep(3);

    printf("ADD RULES\n");
    for(int i=0;i<ruleCount;i++)
    {
        add_rule_to_kernel(fd, &rules[i]);
    }
    free(rules);
    return 0;
}