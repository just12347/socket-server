#include <iostream>
#include <string>
#include <cstring>
#include <string.h>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sstream>
#include "openssl/ssl.h"
#include "openssl/err.h"

using namespace std;


struct User
{
	char* id;
	char* port;
	char* ip;
	char* output; 
	struct User * next;
};

struct User *head = new User;
struct User *tail = new User;
int num = 0;

struct Data
{
	int* fd;
	SSL* ssl;
};
bool finduser(User* list,char* name)
{
	bool re=false;
	if(list->next==NULL)
		return false;
	else
		list=list->next;
	for(int i=0;i<num;i++)
	{
		if(strncmp(list->id,name,sizeof(name))==0&&sizeof(name)==sizeof(list->id))
			re=true;
		list=list->next;
	}

	return re;
}

void adduser(User* list,char* usrname,char* ip,char* port,char* output)
{
	User* tmp = new User;
	tmp->id=usrname;
	tmp->ip=ip;
	tmp->port=port;
	tmp->output=output;

	if(head->next==NULL)
	{
		tmp->next=head->next;
		head->next=tmp;
		tail=tmp;
	}
	else
	{
		tmp->next=list->next;	
		list->next=tmp;
		tail=tmp;
	}
	//count++;
}

char* getlist(User* list)
{
	char result[4000];
	bzero(result,4000);
	list=list->next;
	for(int i=0;i<num;i++)
	{
		strcat(result,list->output);
		strcat(result,"\r\n");
		list=list->next;
	}
	return result;
}
void ShowCerts(SSL* ssl);
void * handle( void * arg)
{
	struct Data* data = (Data*)arg;
	struct sockaddr_in tmp;
	int length = sizeof(tmp);
	//int sock = *(int *)curthread->fd;
	int* fd;
    fd=(int *) arg;
    int sock=*fd;

    SSL* ssl;
    ssl=(SSL *)data->ssl;
   // int *ptr=fd;
    //cout<<sock;
	char buffer [2000];
	int size;
	//cout<<"shit";
	if(SSL_accept(ssl)==-1)
	{
		cout<<"error"<<endl;
	}
	else
	{
		ShowCerts(ssl);
	}
		//cout<<"jjj";
		
		char * cut = "#";
		char * endcut = "\r\n";
		
	
		while((size=SSL_read(ssl,buffer,2000))>0)
		{
			if(strncmp("REGISTER#",buffer,9)==0)
			{
				
				//cout<<"herre";
				strtok(buffer,cut);
				char * usrname =strtok(NULL,cut);
				usrname = strtok(usrname,endcut);
				char ip[20];
                strcpy(ip, inet_ntoa(tmp.sin_addr));
                char port[10];
                sprintf(port, "%d", ntohs(tmp.sin_port));
                char namee[20];
                strcpy(namee,usrname);
               
				char output[100];
                strcpy(output,usrname);
                strcat(output,"#");
                strcat(output,ip);
                strcat(output,"#");
                strcat(output,port);

                if(finduser(head,namee)==false)
                {
                	adduser(tail,namee,ip,port,output);
                	SSL_write(ssl,"100 ok\r\n",strlen("100 ok\r\n"));
                	num++;
                }
                else
                {
                	SSL_write(ssl,"210 fail\r\n",strlen("210 fail\r\n"));
                }
                bzero(buffer,2000);
			}
			else if(strncmp("List",buffer,4)==0)
			{
				char sender[4000];
				char total[10];
				sprintf(total,"%d",num);
				strcpy(sender,total);
				strcat(sender,endcut);
				strcat(sender,getlist(head));
				SSL_write(ssl,sender,strlen(sender));
				bzero(sender,4000);
				bzero(buffer,2000);
			}
			else if(strncmp("Exit",buffer,4)==0)
			{
				
				SSL_write(ssl,"Bye\r\n",strlen("Bye\r\n"));
				cout<<"End connection!!!"<<endl;
				bzero(buffer,2000);
				int sd = SSL_get_fd(ssl);
				SSL_free(ssl);
				close(sd);
				break;
			}
			else
			{
				strtok(buffer,cut);
			}

		

		//free(ptr);
	}
	
}



SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();/* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}




int main ()
{
	
	SSL_CTX *ctx;
	int sockfd;
	int connectfd;
	struct sockaddr_in serv;
	struct sockaddr_in client;
	socklen_t length;
	struct Data data;

	SSL_library_init();
	ctx= InitServerCTX();
	LoadCertificates(ctx, "mycert.pem", "mykey.pem");

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int prt=5901;

	bzero(&serv,sizeof(serv));

	serv.sin_family=AF_INET;
    serv.sin_addr.s_addr=INADDR_ANY;
    serv.sin_port=htons(prt);
    int on = 1;
	int status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));



    while(bind(sockfd,(struct sockaddr *)&serv,sizeof(serv))<0)
    {	
    	cout<<"Bind fail!"<<endl;
	}
	cout<<"Bind complete! Port: "<<prt<<endl;
    

    listen(sockfd,5);

    cout<<"Waiting for connection~~~~~~"<<endl;

    length=sizeof(client);

    while( (connectfd = accept(sockfd, (struct sockaddr *)&client, &length)) )
    {
    	cout<<"Connected~~"<<endl;

    	pthread_t thread;
    	SSL * ssl;
    	ssl = SSL_new(ctx);  
    	SSL_set_fd(ssl, connectfd); 
    	//int * sock;
    	//sock = &connectfd;
    	//data.fd=sock;
    	
    	data.ssl=ssl;
    	//cout<<i;
    	if(pthread_create(&thread,NULL,&handle,&data)<0)
    	{
    		cout<<"Thread create fail!"<<endl;
    		return 1;


    	}
    	//pthread_join(thread,NULL);


    	//cout<<"hihi";
    }




}