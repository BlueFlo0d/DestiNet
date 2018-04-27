#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "util.h"
#define DNF_CLIENT_CONNECT 0x1
#define VERSION_SIZE 3
struct evdns_base *dnsbase = NULL;
SSL_CTX *sslctx = NULL;
typedef struct _listener_state{
        struct event_base *base;
        struct bufferevent *out_pbev;
        struct bufferevent *in_pbev;
        int flag;
        char version[VERSION_SIZE];
} listener_state;

static inline void close_listener_state(listener_state *ls){
        if(ls->out_pbev){
        		bufferevent_free(ls->out_pbev);
        }
        bufferevent_free(ls->in_pbev);
        free(ls);
}
static inline void response_client_listener_state(listener_state *ls,const char *_response_buf){
        size_t _response_len = strlen(_response_buf);
        char *response_buf = (char *)malloc(_response_len);
        strncpy(response_buf, _response_buf, _response_len);
        if(strlen(ls->version)){
                strncpy(response_buf+5, ls->version, VERSION_SIZE);
        }
        bufferevent_write(ls->in_pbev, response_buf, _response_len);
}
void out_socket_event_callback(struct bufferevent *pbev,short events, void *arg){
        listener_state *ls = (listener_state *)arg;
        if(events&BEV_EVENT_CONNECTED){
                dn_info3("Remote connection established.");
                if(ls->flag&DNF_CLIENT_CONNECT){
                        dn_info4("Responding to CONNECT.");
                        response_client_listener_state(ls, "HTTP/1.1 200 OK\r\n\r\n");
                }
        }
        else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)){
                if (events & BEV_EVENT_ERROR) {
                        int err = bufferevent_socket_get_dns_error(pbev);
                        if (err)
                                dn_err("DNS error: %s\n", evutil_gai_strerror(err));
                        response_client_listener_state(ls, "HTTP/1.1 400 Bad request\r\nConnection: close\r\n\r\n");
                }
                //dn_info3("Connection closed");
                //close_listener_state(ls);
        }
}
void out_socket_read_callback(struct bufferevent *pbev, void *arg){
        dn_info4("Remote data received.");
        listener_state *ls = (listener_state *)arg;
#ifdef DN_VERBOSE_5
        struct evbuffer *output_buf = bufferevent_get_input(ls->out_pbev);
        size_t output_len = evbuffer_get_length(output_buf);
        char *output_str = (char *)malloc(output_len+1);
        output_str[output_len]='\0';
        dn_info4("Remote data:\n%s\n",output_str);
        dn_info4("Remote data HEX:");
        for (int i = 0; i < output_len; i ++) {
                printf(" %02x", output_str[i]);
        }
        dn_info4("End HEX.");
        free(output_str);
#endif

        evbuffer_add_buffer(bufferevent_get_output(ls->in_pbev), bufferevent_get_input(ls->out_pbev));
}
void socket_read_callback(struct bufferevent *pbev, void *arg){
        listener_state *ls = (listener_state *)arg;
        struct evbuffer *inbuf = bufferevent_get_input(pbev);
        dn_info4("Local data received.");
        if(!ls->out_pbev){
                dn_info4("Trying to establish remote connection.");
                size_t len,del_len;
                struct evbuffer_ptr pos = evbuffer_search_eol(inbuf, NULL, &del_len, EVBUFFER_EOL_CRLF);
                len = pos.pos;
                char *linebuf = (char *)malloc(len+1);
                evbuffer_copyout(inbuf, linebuf, len);
                linebuf[len]='\0';
                dn_info4("%s",linebuf);
                dn_info4("Got header line:%s",linebuf);
                if(!strncmp("CONNECT",linebuf,7)){
                        ls->flag|=DNF_CLIENT_CONNECT;
                        strncpy(ls->version, linebuf+len-VERSION_SIZE, VERSION_SIZE);
                }
                free(linebuf);
                pos.pos+=del_len;
                evbuffer_ptr_set(inbuf, &pos, del_len, EVBUFFER_PTR_ADD);
                struct evbuffer_ptr new_pos ;
                while((new_pos = evbuffer_search_eol(inbuf, &pos, &del_len, EVBUFFER_EOL_CRLF)).pos!=-1){
                        len = new_pos.pos-pos.pos;
                        if(len < 4){
                                dn_info4("Skip short line.");
                                pos = new_pos;
                                evbuffer_ptr_set(inbuf, &pos, del_len, EVBUFFER_PTR_ADD);
                                continue;
                        }
                        int errcode = 0;
                        linebuf = (char *)malloc(len+1);
                        evbuffer_copyout_from(inbuf, &pos, linebuf, len);
                        pos = new_pos;
                        evbuffer_ptr_set(inbuf, &pos, del_len, EVBUFFER_PTR_ADD);
                        linebuf[len]='\0';
                        if(strncmp("Host", linebuf, 4)){
                                dn_info4("Skip line:%s.",linebuf);
                                free(linebuf);
                                continue;
                        }
                        ls->out_pbev = bufferevent_socket_new(ls->base, -1, BEV_OPT_CLOSE_ON_FREE);
                        bufferevent_setcb(ls->out_pbev, out_socket_read_callback, NULL, out_socket_event_callback, ls);
                        errcode |= bufferevent_enable(ls->out_pbev, EV_READ|EV_PERSIST);
                        char *tok_ctx = NULL;
                        dn_info4("Got header line:\n%s",linebuf);
                        char *hostname = strchr(linebuf, ' ');
                        char *_port = strchr(hostname, ':');
                        dn_info4("Raw port:%s",_port);
                        int port = 80;
                        if(_port){
                                *_port='\0';
                                port = atoi(_port+1);
                        }
                        hostname++;
                        errcode |= bufferevent_socket_connect_hostname(ls->out_pbev,dnsbase, AF_UNSPEC, hostname,port);
                        dn_info3("Hostname:%s",hostname);
                        dn_info3("Port:%d",port);
                        free(linebuf);
                        if(errcode){
                                goto con_error;
                        }
                        if(ls->flag&DNF_CLIENT_CONNECT){
                                size_t buf_len = evbuffer_get_length(inbuf);
#ifdef DN_VERBOSE_4
                                char *debug_data = (char *)malloc(buf_len);
                                evbuffer_remove(inbuf, debug_data, buf_len);
                                dn_info4("What we have discarded:");
                                fwrite(debug_data, 1, buf_len, stdout);
                                fputc('\n', stdout);
#else
                                evbuffer_drain(inbuf, buf_len);
#endif
                        }
                        else {
                                evbuffer_add_buffer(bufferevent_get_output(ls->out_pbev), bufferevent_get_input(ls->in_pbev));
                        }
                        return;
                }
        con_error:
                response_client_listener_state(ls, "HTTP/1.1 400 Bad request\r\n\r\n");
                dn_err("Cannot determine HTTP host.");
                close_listener_state(ls);
                return;
        }
        else {
                dn_info4("Sending data to remote.");
#ifdef DN_VERBOSE_5
                struct evbuffer *output_buf = bufferevent_get_input(ls->in_pbev);
                size_t output_len = evbuffer_get_length(output_buf);
                char *output_str = (char *)malloc(output_len+1);
                output_str[output_len]='\0';
                dn_info4("Local data:\n%s\n",output_str);
                dn_info4("Local data HEX:");
                for (int i = 0; i < output_len; i ++) {
                        printf(" %02x", output_str[i]);
                }
                dn_info4("End HEX.");
                free(output_str);
#endif
                evbuffer_add_buffer(bufferevent_get_output(ls->out_pbev), bufferevent_get_input(ls->in_pbev));
        }
}
void socket_err_callback(struct bufferevent *pbev, short events, void *arg){
        listener_state *ls = (listener_state *)arg;
        if(events&(BEV_EVENT_EOF|BEV_EVENT_ERROR)){
                if(events&BEV_EVENT_ERROR){
                        dn_err("Client socket error.");
                        int err = bufferevent_get_openssl_error(pbev);
                        if(err){
                                dn_err("SSL Error(%d)",err);
                        }
                        err = EVUTIL_SOCKET_ERROR();
                        if(err){
                                dn_err("Socket Error(%d): %s",err,evutil_socket_error_to_string(err));
                        }
                        err = bufferevent_socket_get_dns_error(pbev);
                        if(err){
                                dn_err("DNS Error(%d): %s",err,evutil_gai_strerror(err));
                        }
                }
                dn_info3("Connection closed from client.");
                close_listener_state(ls);
        }
}
void listener_callback(struct evconnlistener *listener, evutil_socket_t fd,struct sockaddr *sock, int socklen, void *arg){
        dn_info4("Local client detected.");
        struct event_base *base = (struct event_base *)arg;
        struct ssl_st *client_sslctx = SSL_new(sslctx);
        //struct bufferevent *pbev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        struct bufferevent *pbev = bufferevent_openssl_socket_new(base, fd, client_sslctx, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
        listener_state *ls = (listener_state *)malloc(sizeof(listener_state));
        listener_state als = {base,NULL,pbev,0,""};
        *ls = als;
        bufferevent_setcb(pbev, socket_read_callback, NULL, socket_err_callback, ls);
        bufferevent_enable(pbev, EV_READ|EV_PERSIST);
}
int exitus_daemon(int port){
        struct sockaddr_in server_addr={0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htons(INADDR_ANY);
        server_addr.sin_port = htons(port);
        struct event_base *pevb = event_base_new();
        dnsbase = evdns_base_new(pevb, 2);
		SSL_library_init();
        SSL_load_error_strings();
        if (!RAND_poll())
                return -1;
        sslctx = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
        if (! SSL_CTX_use_certificate_chain_file(sslctx, "scert") ||
            ! SSL_CTX_use_PrivateKey_file(sslctx, "spkey", SSL_FILETYPE_PEM)) {
                puts("Couldn't read 'spkey' or 'scert' file.  To generate a key\n"
                     "and self-signed certificate, run:\n"
                     "  openssl genrsa -out spkey 2048\n"
                     "  openssl req -new -key spkey -out scert.req\n"
                     "  openssl x509 -req -days 365 -in scert.req -signkey spkey -out scert");
                return -1;
        }
        struct evconnlistener *pevl = evconnlistener_new_bind(pevb, listener_callback, pevb, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 1024, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
        event_base_dispatch(pevb);
        evconnlistener_free(pevl);
        event_base_free(pevb);
        return 0;
}
void signal_handler(int sig){
        dn_err("Received signal %d. Ignoring...",sig);
}
int main(){
        signal(SIGPIPE, signal_handler);
        dn_info("Starting daemon.");
        return exitus_daemon(8880);
}
