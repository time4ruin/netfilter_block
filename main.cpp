#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <cstring>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct id_accept
{
      uint32_t id;
      int isaccept;
};

char *host, *parameter;
int dump(unsigned char *buf, int size)
{
      int i;
      const char http_method[6][10] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "};
      const int http_methodlen[6]={4,5,5,4,7,8};
      
      i=0;
      if (buf[i] == 0x45){ //if ipv4
            if (buf[i + 9] == 0x6){ //if tcp
                  i += 20; //goto start of tcp
                  i += (buf[i + 12] >> 4) * 4; //go to start of http
                  int ok=0;
                  for (int j=0;j<6;j++){
                        if (memcmp(&buf[i], http_method[j], http_methodlen[j])==0){
                              printf("(HTTP %s method found)\n", http_method[j]);
                              ok=1;
                        }
                  }
                  if (ok==1){
                        /*for (int j = 0; j < size - i; j++)
                        {
                              if ((j % 16 == 0) && (j!=0))
                                    printf("\n");
                              printf("%02x ", buf[i + j]);
                        }*/
                        for (int j=i;j<size;j++){
                              if (buf[j]=='H'){
                                    if (memcmp(&buf[j], "Host: ", 6)==0){
                                          for (int k=0;k<strlen(parameter);k++){
                                                host[k] = buf[j + 6 + k];
                                          }
                                          printf("Host: %s\n",host);
                                          if (memcmp(host, parameter, strlen(parameter))==0){
                                                if (buf[j + 6 + strlen(parameter)]=='\r' || buf[j + 6 + strlen(parameter)]=='/')
                                                      return 0;
                                                else return 1;
                                          }
                                          else return 1;
                                    }
                              }
                        }
                  }
            }
      }
      return 1;
}

/* returns packet id */
static struct id_accept *print_pkt(struct nfq_data *tb, struct id_accept *id)
{
      struct nfqnl_msg_packet_hdr *ph;
      struct nfqnl_msg_packet_hw *hwph;
      u_int32_t mark, ifi;
      int ret;
      unsigned char *data;

      ph = nfq_get_msg_packet_hdr(tb);
      if (ph)
      {
            id->id = ntohl(ph->packet_id);
            printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id->id);
      }

      hwph = nfq_get_packet_hw(tb);
      if (hwph)
      {
            int i, hlen = ntohs(hwph->hw_addrlen);

            printf("hw_src_addr=");
            for (i = 0; i < hlen - 1; i++)
                  printf("%02x:", hwph->hw_addr[i]);
            printf("%02x ", hwph->hw_addr[hlen - 1]);
      }

      mark = nfq_get_nfmark(tb);
      if (mark)
            printf("mark=%u ", mark);

      ifi = nfq_get_indev(tb);
      if (ifi)
            printf("indev=%u ", ifi);

      ifi = nfq_get_outdev(tb);
      if (ifi)
            printf("outdev=%u ", ifi);
      ifi = nfq_get_physindev(tb);
      if (ifi)
            printf("physindev=%u ", ifi);

      ifi = nfq_get_physoutdev(tb);
      if (ifi)
            printf("physoutdev=%u ", ifi);

      ret = nfq_get_payload(tb, &data);
      if (ret >= 0)
      {
            printf("payload_len=%d ", ret);
            id->isaccept = dump(data, ret);
            printf("dump ret: %d\n",id->isaccept);
      }

      fputc('\n', stdout);

      return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
      //malloc-free
      struct id_accept *id_accept = (struct id_accept *)malloc(sizeof(struct id_accept));
      id_accept = print_pkt(nfa, id_accept);
      int id = id_accept->id;
      int isaccept = id_accept->isaccept;
      free(id_accept);
      printf("entering callback\n");
      if (isaccept == 1) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
      else if (isaccept == 0) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void usage()
{
	printf("syntax: syntax : netfilter_block <host>\n");
	printf("sample: sample : netfilter_block test.gilgil.net\n");
}

int main(int argc, char **argv)
{
      if (argc != 2)
	{
		usage();
		return -1;
	}

      host = (char *)malloc(strlen(argv[1]));
      parameter = (char *)malloc(strlen(argv[1]));
      memcpy(parameter, argv[1], strlen(argv[1]));

      struct nfq_handle *h;
      struct nfq_q_handle *qh;
      struct nfnl_handle *nh;
      int fd;
      int rv;
      char buf[4096] __attribute__((aligned));

      printf("opening library handle\n");
      h = nfq_open();
      if (!h)
      {
            fprintf(stderr, "error during nfq_open()\n");
            exit(1);
      }

      printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
      if (nfq_unbind_pf(h, AF_INET) < 0)
      {
            fprintf(stderr, "error during nfq_unbind_pf()\n");
            exit(1);
      }

      printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
      if (nfq_bind_pf(h, AF_INET) < 0)
      {
            fprintf(stderr, "error during nfq_bind_pf()\n");
            exit(1);
      }

      printf("binding this socket to queue '0'\n");
      qh = nfq_create_queue(h, 0, &cb, NULL);
      if (!qh)
      {
            fprintf(stderr, "error during nfq_create_queue()\n");
            exit(1);
      }

      printf("setting copy_packet mode\n");
      if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
      {
            fprintf(stderr, "can't set packet_copy mode\n");
            exit(1);
      }

      fd = nfq_fd(h);

      for (;;)
      {
            if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
            {
                  printf("pkt received\n");
                  nfq_handle_packet(h, buf, rv);
                  continue;
            }
            /* if your application is too slow to digest the packets that
       * are sent from kernel-space, the socket buffer that we use
       * to enqueue packets may fill up returning ENOBUFS. Depending
       * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
       * the doxygen documentation of this library on how to improve
       * this situation.
       */
            if (rv < 0 && errno == ENOBUFS)
            {
                  printf("losing packets!\n");
                  continue;
            }
            perror("recv failed");
            break;
      }

      printf("unbinding from queue 0\n");
      nfq_destroy_queue(qh);

#ifdef INSANE
      /* normally, applications SHOULD NOT issue this command, since
    * it detaches other programs/sockets from AF_INET, too ! */
      printf("unbinding from AF_INET\n");
      nfq_unbind_pf(h, AF_INET);
#endif

      printf("closing library handle\n");
      nfq_close(h);

      free(host); free(parameter);
      exit(0);
}
