/*
 *  mhf - mini http frame
 *
 *  Copyright (C) MHF
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Author:
 *      hehbhehb@sina.com
 */

#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>	
#include <time.h>		
#include <netinet/in.h>
#include <arpa/inet.h>	
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>

#include <pwd.h>
#include "mhf.h"

SERVER *server;

static void sig_handler(const int sig) {
    fprintf(stderr,"SIGINT handled.\n");
    exit(EXIT_SUCCESS);
}

static void set_maxcore()
{
    struct rlimit rlim;
    struct rlimit rlim_new;
    /*
     * First try raising to infinity; if that fails, try bringing
     * the soft limit to the hard.
     */
    if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
        rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &rlim_new)!= 0) {
            /* failed. try raising just to the old max */
            rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
            (void)setrlimit(RLIMIT_CORE, &rlim_new);
        }
    }
    /*
     * getrlimit again to see what we ended up with. Only fail if
     * the soft limit ends up 0, because then no core files will be
     * created at all.
     */

    if ((getrlimit(RLIMIT_CORE, &rlim) != 0) || rlim.rlim_cur == 0) {
        fprintf(stderr, "failed to ensure corefile creation\n");
        exit(1);
    }
}

static int daemonize(int nochdir, int verbose)
{
    int fd;

    switch (fork()) {
    case -1:
        return (-1);
    case 0:
        break;
    default:
        _exit(EXIT_SUCCESS);
    }

    if (setsid() == -1)
        return (-1);

    if (nochdir == 0) {
        if(chdir("/tmp") != 0) {
            perror("chdir");
            return (-1);
        }
    }

    if (verbose == 0 && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        if(dup2(fd, STDIN_FILENO) < 0) {
            perror("dup2 stdin");
            return (-1);
        }
        if(dup2(fd, STDOUT_FILENO) < 0) {
            perror("dup2 stdout");
            return (-1);
        }
        if(dup2(fd, STDERR_FILENO) < 0) {
            perror("dup2 stderr");
            return (-1);
        }

        if (fd > STDERR_FILENO) {
            if(close(fd) < 0) {
                perror("close");
                return (-1);
            }
        }
    }
    return (0);
}

int
evutil_snprintf(char *buf, size_t buflen, const char *format, ...)
{
	int r;
	va_list ap;
	va_start(ap, format);
	r = evutil_vsnprintf(buf, buflen, format, ap);
	va_end(ap);
	return r;
}

int
evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap)
{
#ifdef _MSC_VER
	int r = _vsnprintf(buf, buflen, format, ap);
	buf[buflen-1] = '\0';
	if (r >= 0)
		return r;
	else
		return _vscprintf(format, ap);
#else
	int r = vsnprintf(buf, buflen, format, ap);
	buf[buflen-1] = '\0';
	return r;
#endif
}

int mhf_listen(int port)
{
	int listenfd;
	int opt;
	struct sockaddr_in sin = { AF_INET };

	if ((listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("tcp_listen::socket error"); 
		return(-1);
	}

	opt = 1;
	setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,(void *)&opt,(int)sizeof(opt));

	memset(&sin,0,sizeof(sin));
	sin.sin_family=AF_INET;
	sin.sin_port=htons( port );
	if (bind(listenfd,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		close( listenfd );
		return (-1);
	}

	if ( listen(listenfd, 5) < 0) {
		perror("listen");
		close( listenfd );
		return (-1);
	}
	return ( listenfd );
}

int mhf_select( int fd , int sec )
{
	fd_set rset;
	struct timeval tv,*ptv;
	time_t begin_t;
	int retval;

	ptv = sec > 0 ? &tv : NULL;
	while(1) {
		FD_ZERO( &rset );
		FD_SET( fd , &rset );
	
		begin_t = time(NULL);
		tv.tv_sec  = sec;
		tv.tv_usec = 0;
		if( (retval=select(fd+1, &rset, NULL, NULL, ptv)) < 0 ) {
			if( errno == EINTR) {
				sec = sec - (begin_t - time(NULL));
				continue;
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}
	return retval;
}


/*
 * Returns a fresh connection queue conn.
 */
static CONN *mhf_conn_new(void) {
    CONN *conn = NULL;
    pthread_mutex_lock(&server->conn_freelist_lock);
    if (server->conn_freelist) {
        conn = server->conn_freelist;
        server->conn_freelist = conn->next;
    }
    pthread_mutex_unlock(&server->conn_freelist_lock);

    if (NULL == conn) {
        int i;

        /* Allocate a bunch of conns at once to reduce fragmentation */
        conn = malloc(sizeof(CONN) * ITEMS_PER_ALLOC);
        if (NULL == conn)
            return NULL;

        /*
         * Link together all the new conns except the first one
         * (which we'll return to the caller) for placement on
         * the freelist.
         */
        for (i = 2; i < ITEMS_PER_ALLOC; i++)
            conn[i - 1].next = &conn[i];

        pthread_mutex_lock(&server->conn_freelist_lock);
        conn[ITEMS_PER_ALLOC - 1].next = server->conn_freelist;
        server->conn_freelist = &conn[1];
        pthread_mutex_unlock(&server->conn_freelist_lock);
    }

    return conn;
}

static void mhf_conn_init(CONN *conn, int fd, char *address, int port) {

	conn->fd = fd;
	if ((conn->remote_host = strdup(address)) == NULL) {
		fprintf( stderr, "failed to strdup remote_host\n");
		exit(1);
	}
	conn->remote_port = port;
	
	conn->input_headers = calloc(1, sizeof(struct evkeyvalq));
	if (conn->input_headers == NULL) {
		fprintf(stderr,"%s: calloc", __func__);
		goto error;
	}
	TAILQ_INIT(conn->input_headers);

	conn->output_headers = calloc(1, sizeof(struct evkeyvalq));
	if (conn->output_headers == NULL) {
		fprintf(stderr,"%s: calloc", __func__);
		goto error;
	}
	TAILQ_INIT(conn->output_headers);

	if ((conn->input_buffer = evbuffer_new()) == NULL) {
		fprintf(stderr,"%s: evbuffer_new", __func__);
		goto error;
	}

	if ((conn->output_buffer = evbuffer_new()) == NULL) {
		fprintf(stderr,"%s: evbuffer_new", __func__);
		goto error;
	}

	if ((conn->output_buffer_final = evbuffer_new()) == NULL) {
		fprintf(stderr,"%s: evbuffer_new", __func__);
		goto error;
	}

	return;
 error:
	exit(1);	
}

/*
 * Frees a connection queue conn (free its member and then adds it to the freelist.)
 */
static void mhf_conn_free(CONN *conn) {

	if (conn->remote_host != NULL)
		free(conn->remote_host);
	if (conn->uri != NULL)
		free(conn->uri);
	if (conn->response_code_line != NULL)
		free(conn->response_code_line);

	mhf_clear_headers(conn->input_headers);
	free(conn->input_headers);

	mhf_clear_headers(conn->output_headers);
	free(conn->output_headers);

	if (conn->input_buffer != NULL)
		evbuffer_free(conn->input_buffer);

	if (conn->output_buffer != NULL)
		evbuffer_free(conn->output_buffer);

	if (conn->output_buffer_final != NULL)
		evbuffer_free(conn->output_buffer_final);

	if (conn->fd)
		close(conn->fd);

	pthread_mutex_lock(&server->conn_freelist_lock);
	conn->next = server->conn_freelist;
	server->conn_freelist = conn;
	pthread_mutex_unlock(&server->conn_freelist_lock);
}

static void mhf_cq_init(CONNQ *cq) {
    pthread_mutex_init(&cq->lock, NULL);
    pthread_cond_init(&cq->cond, NULL);
    cq->head = NULL;
    cq->tail = NULL;
}

/*
 * Looks for an conn on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the conn, or NULL if no conn is available
 */
static CONN *mhf_cq_pop(CONNQ *cq) {
    CONN *conn;

    pthread_mutex_lock(&cq->lock);
    pthread_cond_wait(&cq->cond, &cq->lock);    
    conn = cq->head;
    if (NULL != conn) {
        cq->head = conn->next;
        if (NULL == cq->head)
            cq->tail = NULL;
    }
    pthread_mutex_unlock(&cq->lock);

    return conn;
}

/*
 * Adds an conn to a connection queue.
 */
static void mhf_cq_push(CONNQ *cq, CONN *conn) {
    conn->next = NULL;

    pthread_mutex_lock(&cq->lock);
    if (NULL == cq->tail)
        cq->head = conn;
    else
        cq->tail->next = conn;
    cq->tail = conn;
    pthread_cond_signal(&cq->cond);
    pthread_mutex_unlock(&cq->lock);
}


/*
 * Reads data from a file descriptor into conn->input_buffer, parse and place the headers into conn->input_headers
 */
int mhf_read_buffer(CONN *conn)
{
	int n, len,ret;
	enum parse_result res;
	struct evbuffer *input_buffer = conn->input_buffer;
	int fd = conn->fd;
	conn->state = HTTP_STATE_READING_FIRSTLINE;
	while(1)
	{
		ret = mhf_select(fd, HTTP_TIMEOUT);	
		if (ret < 0) {
			fprintf(stderr,"%s %d %s select error \n",__func__,errno,strerror(errno));			
			return(-2);
		}
		else if (ret == 0) {
			fprintf(stderr,"%s timeout \n",__func__);	
			return(-1);
		}
		n = evbuffer_read(input_buffer, fd, -1);		
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			{
				fprintf(stderr,"%s %d(EINTR||EAGAIN|EWOULDBLOCK) %s\n",__func__,errno,strerror(errno));
				continue;
			}
			else {
				fprintf(stderr,"%s %d(other error) %s\n",__func__,errno,strerror(errno));
				return(-2);
			}
		} 
		else if (n == 0) {
#ifdef DEBUG		
			fprintf(stderr,"%s connection closed \n",__func__);								
#endif
			return(-3); 		
		}

		while(1) {
			switch (conn->state) {
			case HTTP_STATE_READING_FIRSTLINE:
				res = mhf_read_firstline(conn);
				break;
			case HTTP_STATE_READING_HEADERS:
				res = mhf_read_header(conn);
				break;
			case HTTP_STATE_READING_BODY:
				break;
			case HTTP_STATE_END:
				return (0);				
			case HTTP_STATE_END_WITH_ERR:
#ifdef DEBUG				
				fprintf(stderr,"%s %d HTTP protocol error \n",__func__,res);
#endif
				return(-1);
			default:
				fprintf(stderr,"unsupported http state\n",__func__,res);
				exit(1);
			}
			if (res == MORE_DATA_EXPECTED)
				break;
		}
	}	
}

int mhf_send_buffer(int fd, struct evbuffer *output_buffer)	
{	
	int n;
	while(1) {
#if 0	
		printf("send=%s\n",output_buffer->buffer);
#endif
		n = evbuffer_write(output_buffer, fd);
		if (n == -1) {
			return -1;
		}
		else if (n == 0) {
			return -2;
		}
		if (EVBUFFER_LENGTH(output_buffer) == 0) {
			break;
		}
	}
	return 0;	
}

int prepare_sample_page(CONN *conn, int code, const char *reason)
{
#define SAMPLE_FORMAT "<HTML><HEAD>\n" \
	    "<TITLE></TITLE>\n" \
	    "</HEAD><BODY>\n" \
	    "<H1>%d %s</H1>\n" \
	    "</BODY></HTML>\n"

	struct evbuffer *buf = evbuffer_new();
	evbuffer_add_printf(buf, SAMPLE_FORMAT, code, reason);	
	mhf_clear_headers(conn->output_headers);
	mhf_response_code(conn, code, reason);
	mhf_add_header(conn->output_headers, "Content-Type", "text/html");
 	evbuffer_add_buffer(conn->output_buffer, buf);	
	evbuffer_free(buf);
	return 0;
#undef SAMPLE_FORMAT
}

char *mhf_util_get_img_file_content(char *filename, unsigned int *len) 
{
	FILE *in;
	struct stat stat_buf;
	char *buffer;
	in = fopen(filename, "rb");
	if (!in) {
		fprintf(stderr,"can not open %s\n",filename);	
		return(NULL);
	}
	if (fstat(fileno(in), &stat_buf) != 0) {
		fprintf(stderr,"can not stat %s\n",filename);
		fclose(in);
		return(NULL);  	
	}
	buffer = malloc(stat_buf.st_size);
	if (!buffer) {
		fprintf(stderr,"can not malloc %d\n",stat_buf.st_size);
		fclose(in);
		exit(1);
	}
	if (fread(buffer, 1, stat_buf.st_size, in)!= stat_buf.st_size) 
	{
		fprintf(stderr,"can not fread %s,%d\n",filename,stat_buf.st_size);
		free(buffer);
		fclose(in);	
		return(NULL);  		  	
	}
	fclose(in);
	if (len)
		*len = stat_buf.st_size;
	return(buffer);	
}

void prepare_sample_file(CONN *conn, char *filename) 
{
	char *data;
	unsigned int len;
	
	mhf_clear_headers(conn->output_headers);	
	data = mhf_util_get_img_file_content(filename,&len);
	if (data == NULL) {
		mhf_response_code(conn, HTTP_NOTFOUND, "NOT FOUND");
		return;
	}
	if (strcasestr(filename, ".gif"))
		mhf_add_header(conn->output_headers, "Content-Type", "image/gif");	
	else if (strcasestr(filename, ".jpg"))
		mhf_add_header(conn->output_headers, "Content-Type", "image/jpeg");	
	else if (strcasestr(filename, ".png"))
		mhf_add_header(conn->output_headers, "Content-Type", "image/png");
	else
		mhf_add_header(conn->output_headers, "Content-Type", "text/html");	
	
	evbuffer_add(conn->output_buffer, data, len);
	free(data);
	mhf_response_code(conn, HTTP_OK, "OK");	
	return;
}

#ifdef HAVE_STAT
static void mhf_increase_running_threads_num(CONN *conn) {
    pthread_mutex_lock(&server->stat_lock);
    server->stat_running_threads_num++;
    pthread_mutex_unlock(&server->stat_lock);
}

static void mhf_decrease_running_threads_num(CONN *conn) {
    pthread_mutex_lock(&server->stat_lock);
    server->stat_running_threads_num--;
    pthread_mutex_unlock(&server->stat_lock);
}
#endif

static void *mhf_consume(void *arg) {
	int ret;
	CONN *conn;
#ifdef DEBUG	
	fprintf(stderr, "thread created,tid=%x\n", (unsigned long)pthread_self());
#endif
	while(1)
	{
#ifdef HAVE_STAT	
		mhf_decrease_running_threads_num(conn);	
#endif

		conn = mhf_cq_pop(server->cq);

#ifdef HAVE_STAT		
		mhf_increase_running_threads_num(conn);
#endif		
		if (NULL != conn) {
			ret = mhf_read_buffer(conn);
			if (ret < 0) {
				mhf_conn_free(conn);		
				continue;	
			}

			/*	Prepare conn->output_headers,conn->output_buffer,conn->response_code */
			mhf_prepare_data(conn);

			/* 	Move evcon->output_headers + evcon->output_buffer ==> evcon->output_buffer_final */				
			mhf_make_header(conn); 	

			/* fire */
			mhf_send_buffer(conn->fd, conn->output_buffer_final);
			
			mhf_conn_free(conn);
		}
	}    
	return NULL;
}

static CONN *mhf_produce() {
	CONN *conn;
	int fd,port;
	char *address;
       struct sockaddr_in cliaddr;	
	socklen_t len = sizeof(struct sockaddr_in);
	
	if((fd = accept(server->listenfd, (struct sockaddr*)&cliaddr, &len)) < 0)
	{
		fprintf(stderr,"accept error = %s\n",strerror(errno));
		return(NULL);
	}
	address = inet_ntoa(cliaddr.sin_addr);
#ifdef DEBUG
	fprintf( stderr, "\nAccepted,ip=%s,port=%d,fd=%d,tid=%x\n" ,address, cliaddr.sin_port, fd, (unsigned long)pthread_self());
#endif			
	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, (int)sizeof(opt) );
	
	if ((conn = mhf_conn_new()) == NULL) {
		fprintf( stderr, "failed to get new conn\n");
		exit(1);
	}
	memset(conn, 0, sizeof(CONN));
	mhf_conn_init(conn, fd, address, cliaddr.sin_port);

	return(conn);		
}

static SERVER *mhf_server_init(int port, int nthreads)
{
    SERVER *s;
	
    s = malloc(sizeof(SERVER));
    if (NULL == s) {
        perror("Failed to allocate memory for s");
        exit(EXIT_FAILURE);
    }
        
    s->cq = malloc(sizeof(CONNQ));
    if (NULL == s->cq) {
        perror("Failed to allocate memory for connection queue");
        exit(EXIT_FAILURE);
    }    
    mhf_cq_init(s->cq);
    
    pthread_mutex_init(&s->conn_freelist_lock, NULL);
    s->conn_freelist = NULL;

    if ((s->listenfd = mhf_listen(port)) < 0) {
        fprintf( stderr," failed to listen %d\n", port);
        exit (1);
    }
    int opt=1;
    setsockopt(s->listenfd,SOL_SOCKET,SO_REUSEADDR,(void *)&opt,(int)sizeof(opt));
	
    server = s;
    return(s);
}

int mhf_server_free(SERVER *s) {
    CONN *conn,*tmp;	
    free(s->cq);
    conn = s->conn_freelist;
    while (conn) {
           tmp = conn->next;
	    free(conn);
           conn = tmp;
    }
    close(s->listenfd);	
    free(s);	
}

void mhf_server_set_callback(void (*cb)(CONN*)) {
	server->cb = cb;	
}

int main (int argc, char **argv)
{
	int nthreads=2, port=80;
	int i,opt,verbose=0;
       int maxcore = 0;
	int c,ret;
	int do_daemonize = 0;
	char *username = NULL,*config_file=NULL;
	char *pid_file = NULL;
	struct passwd *pw;
	pthread_t tid;		
	CONN *conn;
	   
	signal( SIGQUIT , SIG_IGN );
	signal( SIGPIPE , SIG_IGN );
	signal(SIGINT, sig_handler);	
	setbuf(stderr, NULL);

	while (-1 != (c = getopt(argc, argv,
	      "p:"   /* port */				
	      "n:"   /* threads num */
	      "d"   /* daemon mode */		
             "r"   /* maximize core file limit */	      
	      "v"   /* verbose */          
	    ))) {
	    switch (c) {
	    case 'n':
	        nthreads = atoi(optarg);
	        break;
	    case 'p':
	        port = atoi(optarg);
	        break;
	    case 'd':
	        do_daemonize = 1;
	        break;
           case 'r':
              maxcore = 1;
              break;
	    case 'v':
	        verbose++;
	        break;
	    default:
	        fprintf(stderr, "Illegal argument \"%c\"\n", c);
	        return 1;
	    }
	}

	if (maxcore) 
		set_maxcore();		

	if (do_daemonize) {
	    if (daemonize(0, verbose) == -1) {
	        fprintf(stderr, "failed to daemon() in order to daemonize\n");
	        exit(EXIT_FAILURE);
	    }
	}
	
	mhf_server_init(port, nthreads);
	
	/* You SHOULD use your own callback func here */
	mhf_server_set_callback(user_func_sample);	
	
	for (i = 0; i < nthreads; i++)
	{
	    if ((ret = pthread_create(&tid, NULL, mhf_consume, NULL)) != 0) {
	        fprintf(stderr, "failed to pthread_create: %s\n", strerror(ret));
	        exit(1);
	    }
	}	
	sleep(2);	
	while( 1 )
	{
		if (conn = mhf_produce()) {
			mhf_cq_push(server->cq, conn);
		}
	}

	mhf_server_free(server);
	return EXIT_SUCCESS;
}

int mhf_prepare_data(CONN *conn)
{
#ifdef DEBUG
	fprintf(stderr,"%s: url = %s\n", __func__, conn->uri);
#endif	

#ifdef HAVE_STAT
	if (strcasestr(conn->uri+1, "stat")) {
		char str[32];
		sprintf(str,"running_threads_num:%d",server->stat_running_threads_num+1);
		prepare_sample_page(conn, HTTP_OK, str);
		return(0);
	}
#endif		
	if (server->cb)
		server->cb(conn);
	else 
		prepare_sample_page(conn, HTTP_OK, "warning: you should call mhf_server_set_callback()... ");
	
	return(0);
}

void user_func_sample(CONN *conn)
{
	prepare_sample_file(conn, conn->uri+1);
}

