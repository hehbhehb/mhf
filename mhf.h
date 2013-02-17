#ifndef _SS_SERVER_
#define _SS_SERVER_

#ifdef __cplusplus
extern "C" {
#endif

struct evkeyval {
	TAILQ_ENTRY(evkeyval) next;

	char *key;
	char *value;
};

TAILQ_HEAD (evkeyvalq, evkeyval);

enum mhf_cmd_type { EVHTTP_REQ_GET, EVHTTP_REQ_POST, EVHTTP_REQ_HEAD };

enum http_state {
	HTTP_STATE_READING_FIRSTLINE = 0,
	HTTP_STATE_READING_HEADERS,
	HTTP_STATE_READING_BODY,
	HTTP_STATE_END,
	HTTP_STATE_END_WITH_ERR	
};

enum parse_result {
	ALL_DATA_READ = 1,
	MORE_DATA_EXPECTED = 0,
	DATA_CORRUPTED = -1
};

typedef struct conn CONN;
struct conn {
	int fd;
	char *remote_host;
	u_short remote_port;
	enum mhf_cmd_type type;
	char *uri;
	char major;
	char minor;
	struct evkeyvalq *input_headers;
	struct evbuffer *input_buffer;

	int response_code;
	char *response_code_line;
	struct evkeyvalq *output_headers;    
	struct evbuffer *output_buffer;
	struct evbuffer *output_buffer_final;	

	enum http_state state;
	CONN *next;
};

typedef struct conn_queue CONNQ;
struct conn_queue {
    CONN *head;
    CONN *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
};

/* Response codes */
#define HTTP_OK			200
#define HTTP_NOCONTENT		204
#define HTTP_MOVEPERM		301
#define HTTP_MOVETEMP		302
#define HTTP_NOTMODIFIED	304
#define HTTP_BADREQUEST		400
#define HTTP_NOTFOUND		404
#define HTTP_SERVUNAVAIL	503

#define HTTP_TIMEOUT		5


#define ITEMS_PER_ALLOC 64

struct evbuffer {
	u_char *buffer;
	u_char *orig_buffer;

	size_t misalign;
	size_t totallen;
	size_t off;

	void (*cb)(struct evbuffer *, size_t, size_t, void *);
	void *cbarg;
};

#define EVBUFFER_LENGTH(x)	(x)->off
#define EVBUFFER_DATA(x)	(x)->buffer
#define EVBUFFER_INPUT(x)	(x)->input
#define EVBUFFER_OUTPUT(x)	(x)->output

typedef struct _SERVER
{
	int listenfd;
	CONN *conn_freelist;
	pthread_mutex_t conn_freelist_lock;
	CONNQ *cq;
	void (*cb)(CONN*);
	
#ifdef HAVE_STAT
	pthread_mutex_t stat_lock;
	int stat_running_threads_num;
#endif	

} SERVER;

extern SERVER *server;

int
evutil_snprintf(char *buf, size_t buflen, const char *format, ...);

int
evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap);

void user_func_sample(CONN *conn);

#ifdef __cplusplus
}
#endif

#endif

