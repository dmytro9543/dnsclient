#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>

#define QR_MASK        0x8000 // Query/Response flag (bit 15)
#define OPCODE_MASK    0x7800 // Opcode (bits 11-14)
#define AA_MASK        0x0400 // Authoritative Answer (bit 10)
#define TC_MASK        0x0200 // TrunCation (bit 9)
#define RD_MASK        0x0100 // Recursion Desired (bit 8)
#define RA_MASK        0x0080 // Recursion Available (bit 7)
#define Z_MASK         0x0070 // Reserved (bit 4-6)
#define RCODE_MASK     0x000F // Response Code (bits 0-3)

#define SET_QR(flags, value)        ((flags) = ((flags) & ~QR_MASK) | (((value) & 0x1) << 15))
#define SET_OPCODE(flags, value)    ((flags) = ((flags) & ~OPCODE_MASK) | (((value) & 0xF) << 11))
#define SET_AA(flags, value)        ((flags) = ((flags) & ~AA_MASK) | (((value) & 0x1) << 10))
#define SET_TC(flags, value)        ((flags) = ((flags) & ~TC_MASK) | (((value) & 0x1) << 9))
#define SET_RD(flags, value)        ((flags) = ((flags) & ~RD_MASK) | (((value) & 0x1) << 8))
#define SET_RA(flags, value)        ((flags) = ((flags) & ~RA_MASK) | (((value) & 0x1) << 7))
#define SET_Z(flags, value)         ((flags) = ((flags) & ~Z_MASK) | (((value) & 0x7) << 4))
#define SET_RCODE(flags, value)     ((flags) = ((flags) & ~RCODE_MASK) | ((value) & 0xF))

#define GET_QR(flags)        ((flags & QR_MASK) >> 15)
#define GET_OPCODE(flags)    ((flags & OPCODE_MASK) >> 11)
#define GET_AA(flags)        ((flags & AA_MASK) >> 10)
#define GET_TC(flags)        ((flags & TC_MASK) >> 9)
#define GET_RD(flags)        ((flags & RD_MASK) >> 8)
#define GET_RA(flags)        ((flags & RA_MASK) >> 7)
#define GET_Z(flags)         ((flags & Z_MASK) >> 4)
#define GET_RCODE(flags)     (flags & RCODE_MASK)

#define DNS_PORT 53

#define BUF_SIZE 99999

struct dnsheader_s
{
  unsigned short id;
  unsigned short flags;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
};

struct qeustion_s
{
  unsigned short qtype;
  unsigned short qclass;
};

struct resquestion_s
{
  unsigned char *name;
  struct qeustion_s *ques;
};

struct resource_s
{
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short data_len;
}__attribute__((packed));

struct resrecord_s
{
  unsigned char *name;
  struct resource_s *resource;
  unsigned char *rdata;
};

static unsigned char* GetNameAndLength(unsigned char* ptr, int* len)
{
  unsigned char *name;
  int i = 0 , j, a;

  *len = 1;
  name = (unsigned char*)calloc(256, sizeof(unsigned char));
  while(*ptr != 0) {
    a = *ptr;
    for(j = 0;j<a;j++) {
      name[i++] = *(++ptr);
      (*len)++;
    }
    name[i++] = '.';
    ptr++;
    (*len)++;
    if(*ptr == 0xc0) {
      (*len)++;
      break;
    }
  }
  name[i-1] = '\0';
  return name;
}

int main( int argc , char *argv[])
{
  char dnsserver[128];
  unsigned char buffer[BUF_SIZE];
  int sockfd;
  int retry;
  char *host;
  unsigned char*qname;

  struct resquestion_s question;
  struct resrecord_s answers,authority,additional; 

  struct dnsheader_s *dnshdr = NULL;
  struct qeustion_s *questiondata = NULL;

  struct sockaddr_in dnsaddr;

  if(argc < 2)
  {
    printf("Usage:\n\t%s <hostname>\n", argv[0]);
    return 0;
  }

  //strcpy(dnsserver , "8.8.8.8");
  strcpy(dnsserver, "192.168.2.101");

  host = argv[1];

  printf("Preparing DNS query..\n");

  srand(time(NULL));

  dnshdr = (struct dnsheader_s *)buffer;

  srand(time(NULL));

  dnshdr->id = (unsigned short) htons(rand() % 65536);
  
  int flags = 0;
  SET_QR(flags, 0);
  SET_OPCODE(flags, 0);
  SET_AA(flags, 0);
  SET_TC(flags, 0);
  SET_RD(flags, 1);
  SET_RA(flags, 0);
  SET_Z(flags, 0);
  SET_RCODE(flags, 0);
  dnshdr->flags = htons(flags);
  
  dnshdr->qdcount = htons(1); 
  dnshdr->ancount = 0;
  dnshdr->nscount = 0;
  dnshdr->arcount = 0;

  qname  = (unsigned char*)(buffer + sizeof(struct dnsheader_s));

  unsigned char *ptrname = qname;
  int offset = 0;
  for(int i = 0 ; i <= strlen((char*)host) ; i++) 
  {
    if(host[i] == '.' || i == strlen((char*)host)) 
    {
      *(ptrname++) = i-offset;
      for(;offset<i;offset++) 
        *(ptrname++) = host[offset];
      offset++; 
    }
  }
  
  questiondata  = (struct qeustion_s*)(buffer + sizeof(struct dnsheader_s) + (strlen((const char*)qname) + 1));

  questiondata->qtype = htons(1); 
  questiondata->qclass = htons(1); 

  printf("Contacting DNS server %s\n",dnsserver);

  sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); 

  dnsaddr.sin_family = AF_INET;
  dnsaddr.sin_port = htons(DNS_PORT);
  dnsaddr.sin_addr.s_addr = inet_addr(dnsserver); 

  for(retry = 0; retry < 3; retry++) {
    printf("Sending DNS query..\n");
    if( sendto(sockfd,buffer,sizeof(struct dnsheader_s) + (strlen((const char*)qname) + 1) + sizeof(struct qeustion_s),0,(struct sockaddr*)&dnsaddr,sizeof(dnsaddr)) < 0) {
      continue;
    }

    size_t sz = sizeof(dnsaddr);
    if(recvfrom (sockfd,buffer , sizeof(buffer) , 0 , (struct sockaddr*)&dnsaddr , (socklen_t*)&sz ) < 0) {
      continue;
    }
    printf("DNS response received\n");
    break;
  }

  if(retry >= 3) {
    return 0;
  }

  printf("Processing DNS response..\n");
  printf("----------------------------------------------------------------------------\n");

  dnshdr = (struct dnsheader_s*) buffer;
  
  if (GET_RCODE(ntohs(dnshdr->flags)) == 0) {
    int i, namelen; 
    unsigned char *ptr_res;
    unsigned int *paddr;
    struct sockaddr_in resolvedip;
    
    ptr_res = (unsigned char*)(buffer + sizeof(struct dnsheader_s));

    printf("header.ID = %d\n", ntohs(dnshdr->id));
    printf("header.QR = %d\n", GET_QR(ntohs(dnshdr->flags)));
    printf("header.OPCODE = %d\n", GET_OPCODE(ntohs(dnshdr->flags)));
    printf("header.AA = %d\n", GET_AA(ntohs(dnshdr->flags)));
    printf("header.TC = %d\n", GET_TC(ntohs(dnshdr->flags)));
    printf("header.RD = %d\n", GET_RD(ntohs(dnshdr->flags)));
    printf("header.RA = %d\n", GET_RA(ntohs(dnshdr->flags)));
    printf("header.Z = %d\n", GET_Z(ntohs(dnshdr->flags)));
    printf("header.RCODE = %d\n", GET_RCODE(ntohs(dnshdr->flags)));
    printf("header.QDCOUNT = %d\n", ntohs(dnshdr->qdcount));
    printf("header.ANCOUNT = %d\n", ntohs(dnshdr->ancount));
    printf("header.NSCOUNT = %d\n", ntohs(dnshdr->nscount));
    printf("header.ARCOUNT = %d\n", ntohs(dnshdr->arcount));

    namelen = 0;

    for(i = 0; i < ntohs(dnshdr->qdcount); i++)
    {
      question.name = GetNameAndLength(ptr_res,&namelen); 
      ptr_res = ptr_res + namelen;

      question.ques = (struct qeustion_s*)(ptr_res);
      ptr_res = ptr_res + sizeof(struct qeustion_s);

      printf("question.QNAME = %s\n", question.name);
      printf("question.QTYPE = %d\n", htons(question.ques->qtype));
      printf("question.QCLASS = %d\n", htons(question.ques->qclass));
    }

    for(i = 0; i < ntohs(dnshdr->ancount); i++)
    {
      if(*ptr_res == 0xc0) {
        answers.name = (unsigned char*)strdup(host);
        namelen = 2;
      } else {
        answers.name = GetNameAndLength(ptr_res,&namelen);
      }
      ptr_res = ptr_res + namelen;
      answers.resource = (struct resource_s*)(ptr_res);
      ptr_res = ptr_res + sizeof(struct resource_s);

      printf("answer.NAME = %s\n",answers.name);
      printf("answer.TYPE = %d\n", htons(answers.resource->type));
      printf("answer.CLASS = %d\n", htons(answers.resource->class));
      printf("answer.TTL = %d\n", htonl(answers.resource->ttl));
      if(ntohs(answers.resource->type) == 1)
      {
        answers.rdata = (unsigned char*)malloc(ntohs(answers.resource->data_len));
        memcpy(answers.rdata, ptr_res, ntohs(answers.resource->data_len));
        paddr = (unsigned int*)answers.rdata;
        resolvedip.sin_addr.s_addr = (*paddr); 
        printf("answer.RDATA = %s\n", inet_ntoa(resolvedip.sin_addr));
      } else {
        printf("answer.RDATA =\n");
      }
      ptr_res += ntohs(answers.resource->data_len);
    }

    for(i = 0; i < ntohs(dnshdr->nscount); i++)
    {
      if(*ptr_res == 0xc0) {
        authority.name = (unsigned char*)strdup(host);
        namelen = 2;
      } else {
        authority.name = GetNameAndLength(ptr_res,&namelen); 
      }
      ptr_res += namelen;
      authority.resource = (struct resource_s*)(ptr_res);
      ptr_res += sizeof(struct resource_s);

      printf("authority.NAME = %s\n",authority.name);
      printf("authority.TYPE = %d\n", htons(authority.resource->type));
      printf("authority.CLASS = %d\n", htons(authority.resource->class));
      printf("authority.TTL = %d\n", htonl(authority.resource->ttl));
      if(ntohs(authority.resource->type) == 1)
      {
        authority.rdata = (unsigned char*)malloc(ntohs(authority.resource->data_len));
        memcpy(authority.rdata, ptr_res, ntohs(authority.resource->data_len));
        paddr = (unsigned int*)authority.rdata;
        resolvedip.sin_addr.s_addr = (*paddr); 
        printf("authority.RDATA = %s\n", inet_ntoa(resolvedip.sin_addr));
      } else {
        printf("authority.RDATA =\n");
      }
      ptr_res += ntohs(authority.resource->data_len);
    }

    for(i = 0; i < ntohs(dnshdr->arcount); i++)
    {
      if(*ptr_res == 0xc0) {
        additional.name = (unsigned char*)strdup(host);
        namelen = 2;
      } else {
        additional.name = GetNameAndLength(ptr_res,&namelen); 
      }
      ptr_res += namelen;
      additional.resource = (struct resource_s*)(ptr_res);
      ptr_res += sizeof(struct resource_s);

      printf("additional.NAME = %s\n",additional.name);
      printf("additional.TYPE = %d\n", htons(additional.resource->type));
      printf("additional.CLASS = %d\n", htons(additional.resource->class));
      printf("additional.TTL = %d\n", htonl(additional.resource->ttl));
      if(ntohs(additional.resource->type) == 1)
      {
        additional.rdata = (unsigned char*)malloc(ntohs(additional.resource->data_len));
        memcpy(additional.rdata, ptr_res, ntohs(additional.resource->data_len));
        paddr = (unsigned int*)additional.rdata;
        resolvedip.sin_addr.s_addr = (*paddr); 
        printf("additional.RDATA = %s\n", inet_ntoa(resolvedip.sin_addr));
      } else {
        printf("additional.RDATA =\n");
      }
      ptr_res += ntohs(additional.resource->data_len);
    }
  }

  return 0;
}

