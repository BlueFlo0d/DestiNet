#include <microhttpd.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
CURL *curl;
char *buf=NULL;
size_t buf_size=0;
int recv_callback(char *recv,size_t size,size_t nmemb,void *usr){
        struct MHD_Connection *pcon=(struct MHD_Connection *)usr;
        size_t delta_size = size*nmemb;
        dn_info4("Recv %s.",recv);
        if(!buf){
                buf = (char *)malloc(delta_size);
        }
        else {
                buf = (char *)realloc(buf, buf_size+delta_size);
        }
        memccpy(buf+buf_size, recv, 1, delta_size);
        buf_size+=delta_size;
        return size*nmemb;
}
int connection_callback(void *cls, struct MHD_Connection *pcon,const char *url,const char *method,const char *ver,const char *up_data,size_t *up_data_size,void **con_cls){
        dn_info3("Method %s.",method);
        dn_info3("Url %s.",url);
        dn_info3("Version %s.",ver);
        dn_info3("Content %s.",up_data);
        if(!strcmp(method,"CONNECT")){

        }
        /*
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, pcon);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_callback);
        curl_easy_perform(curl);
        struct MHD_Response *res = MHD_create_response_from_buffer(buf_size, buf, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(pcon, MHD_HTTP_OK, res);
        MHD_destroy_response(res);*/
        dn_info3("Connection closed.");
        return MHD_HTTP_OK;
}
int main(){
        struct MHD_Daemon *pdae;
        curl = curl_easy_init();
        pdae = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 8888, NULL, NULL, connection_callback, NULL, MHD_OPTION_END);
        if (NULL == pdae){
                dn_err("Failed to start local proxy daemon.");
                return 1;
        }
        getchar();
        MHD_stop_daemon(pdae);
        curl_easy_cleanup(curl);
        return 0;
}
