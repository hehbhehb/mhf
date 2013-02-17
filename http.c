/*
 *  Copyright (C) MHF
 */

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
#include <assert.h>

#include "mhf.h"

void
mhf_response_code(CONN *conn, int code, const char *reason)
{
	conn->response_code = code;
	if (conn->response_code_line != NULL)
		free(conn->response_code_line);
	conn->response_code_line = strdup(reason);
}

static const char *
mhf_method(enum mhf_cmd_type type)
{
	const char *method;

	switch (type) {
	case EVHTTP_REQ_GET:
		method = "GET";
		break;
	case EVHTTP_REQ_POST:
		method = "POST";
		break;
	case EVHTTP_REQ_HEAD:
		method = "HEAD";
		break;
	default:
		method = NULL;
		break;
	}

	return (method);
}

const char *
mhf_find_header(const struct evkeyvalq *headers, const char *key)
{
	struct evkeyval *header;

	TAILQ_FOREACH(header, headers, next) {
		if (strcasecmp(header->key, key) == 0)
			return (header->value);
	}

	return (NULL);
}

void mhf_clear_headers(struct evkeyvalq *headers)
{
	struct evkeyval *header;

	for (header = TAILQ_FIRST(headers);
	    header != NULL;
	    header = TAILQ_FIRST(headers)) {
		TAILQ_REMOVE(headers, header, next);
		free(header->key);
		free(header->value);
		free(header);
	}
}

static int
mhf_header_is_valid_value(const char *value)
{
	const char *p = value;

	while ((p = strpbrk(p, "\r\n")) != NULL) {
		/* we really expect only one new line */
		p += strspn(p, "\r\n");
		/* we expect a space or tab for continuation */
		if (*p != ' ' && *p != '\t')
			return (0);
	}
	return (1);
}

static int
mhf_add_header_internal(struct evkeyvalq *headers,
    const char *key, const char *value)
{
	struct evkeyval *header = calloc(1, sizeof(struct evkeyval));
	if (header == NULL) {
		fprintf(stderr,"%s: calloc", __func__);
		return (-1);
	}
	if ((header->key = strdup(key)) == NULL) {
		free(header);
		fprintf(stderr,"%s: strdup", __func__);
		return (-1);
	}
	if ((header->value = strdup(value)) == NULL) {
		free(header->key);
		free(header);
		fprintf(stderr,"%s: strdup", __func__);
		return (-1);
	}

	TAILQ_INSERT_TAIL(headers, header, next);

	return (0);
}

int mhf_disp_header(const struct evkeyvalq *headers)
{
	struct evkeyval *header;
	TAILQ_FOREACH(header, headers, next) {
		fprintf(stderr,"%s: %s\n",header->key,header->value);
	}
	return 0;
}

static int
mhf_append_to_last_header(struct evkeyvalq *headers, const char *line)
{
	struct evkeyval *header = TAILQ_LAST(headers, evkeyvalq);
	char *newval;
	size_t old_len, line_len;

	if (header == NULL)
		return (-1);

	old_len = strlen(header->value);
	line_len = strlen(line);

	newval = realloc(header->value, old_len + line_len + 1);
	if (newval == NULL)
		return (-1);

	memcpy(newval + old_len, line, line_len + 1);
	header->value = newval;

	return (0);
}

static int
mhf_parse_request_line(CONN *conn, char *line)
{
	char *method;
	char *uri;
	char *version;

	/* Parse the request line */
	method = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	uri = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	version = strsep(&line, " ");
	if (line != NULL)
		return (-1);

	/* First line */
	if (strcmp(method, "GET") == 0) {
		conn->type = EVHTTP_REQ_GET;
	} else if (strcmp(method, "POST") == 0) {
		conn->type = EVHTTP_REQ_POST;
	} else if (strcmp(method, "HEAD") == 0) {
		conn->type = EVHTTP_REQ_HEAD;
	} else {
		fprintf(stderr,"%s: bad method %s on connect %p from %s",
			__func__, method, conn, conn->remote_host);
		return (-1);
	}

	if (strcmp(version, "HTTP/1.0") == 0) {
		conn->major = 1;
		conn->minor = 0;
	} else if (strcmp(version, "HTTP/1.1") == 0) {
		conn->major = 1;
		conn->minor = 1;
	} else {
		fprintf(stderr,"%s: bad version %s on connect %p from %s",
			__func__, version, conn, conn->remote_host);
		return (-1);
	}

	if ((conn->uri = strdup(uri)) == NULL) {
		fprintf(stderr,"%s: mhf_decode_uri", __func__);
		return (-1);
	}

	return (0);
}

enum parse_result
mhf_parse_firstline(CONN *conn, struct evbuffer *buffer)
{
	char *line;
	enum parse_result status = ALL_DATA_READ;

	line = evbuffer_readline(buffer);
	if (line == NULL)
		return (MORE_DATA_EXPECTED);

	if (mhf_parse_request_line(conn, line) == -1)
		status = DATA_CORRUPTED;

	free(line);
	return (status);
}

enum parse_result mhf_read_firstline(CONN *conn)
{
	enum parse_result res;
	res =mhf_parse_firstline(conn, conn->input_buffer);
	if (res == DATA_CORRUPTED) {
		conn->state = HTTP_STATE_END_WITH_ERR;
		return res;
	} else if (res == MORE_DATA_EXPECTED) {
		return res;
	}
	conn->state = HTTP_STATE_READING_HEADERS;
	return res;
}

enum parse_result mhf_read_header(CONN *conn)
{
	enum parse_result res;
	int fd = conn->fd;

	res = mhf_parse_headers(conn, conn->input_buffer);
	if (res == DATA_CORRUPTED) {
		conn->state = HTTP_STATE_END_WITH_ERR;
		return res;
	} else if (res == MORE_DATA_EXPECTED) {
 		return res;
	}
	conn->state = HTTP_STATE_END;
	return res;
}


enum parse_result
mhf_parse_headers(CONN *conn, struct evbuffer* buffer)
{
	char *line;
	enum parse_result status = MORE_DATA_EXPECTED;

	struct evkeyvalq* headers = conn->input_headers;
	while ((line = evbuffer_readline(buffer))
	       != NULL) {
		char *skey, *svalue;

		if (*line == '\0') { /* Last header - Done */
			status = ALL_DATA_READ;
			free(line);
			break;
		}

		/* Check if this is a continuation line */
		if (*line == ' ' || *line == '\t') {
			if (mhf_append_to_last_header(headers, line) == -1)
				goto error;
			free(line);
			continue;
		}

		/* Processing of header lines */
		svalue = line;
		skey = strsep(&svalue, ":");
		if (svalue == NULL)
			goto error;

		svalue += strspn(svalue, " ");

		if (mhf_add_header(headers, skey, svalue) == -1)
			goto error;

		free(line);
	}

	return (status);

 error:
	free(line);
	return (DATA_CORRUPTED);
}


int
mhf_add_header(struct evkeyvalq *headers,
    const char *key, const char *value)
{
#ifdef DEBUG
	fprintf(stderr, "%s: key: %s val: %s\n", __func__, key, value);
#endif
	if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL) {
		/* drop illegal headers */
		fprintf(stderr,"%s: dropping illegal header key\n", __func__);
		return (-1);
	}
	
	if (!mhf_header_is_valid_value(value)) {
		fprintf(stderr,"%s: dropping illegal header value\n", __func__);
		return (-1);
	}

	return (mhf_add_header_internal(headers, key, value));
}


/*
 * Create the headers needed for an HTTP reply
 */

static void
mhf_make_header_response(CONN *conn)
{
	evbuffer_add_printf(conn->output_buffer_final, "HTTP/%d.%d %d %s\r\n",
	    conn->major, conn->minor, conn->response_code,
	    conn->response_code_line);

	if (EVBUFFER_LENGTH(conn->output_buffer)) {
		if (mhf_find_header(conn->output_headers,
			"Content-Type") == NULL) {
			mhf_add_header(conn->output_headers,
			    "Content-Type", "text/html; charset=ISO-8859-1");
		}
	}

	mhf_add_header(conn->output_headers, "Connection", "close");
}


void
mhf_make_header(CONN *conn)
{
	struct evkeyval *header;

	mhf_make_header_response(conn);	

	TAILQ_FOREACH(header, conn->output_headers, next) {
		evbuffer_add_printf(conn->output_buffer_final, "%s: %s\r\n",
		    header->key, header->value);
	}
	evbuffer_add(conn->output_buffer_final, "\r\n", 2);

	if (EVBUFFER_LENGTH(conn->output_buffer) > 0) {
		/*
		 * For a request, we add the POST data, for a reply, this
		 * is the regular data.
		 */
		evbuffer_add_buffer(conn->output_buffer_final, conn->output_buffer);
	}
}


static void
mhf_maybe_add_date_header(struct evkeyvalq *headers)
{
	if (mhf_find_header(headers, "Date") == NULL) {
		char date[50];
#ifndef WIN32
		struct tm cur;
#endif
		struct tm *cur_p;
		time_t t = time(NULL);
#ifdef WIN32
		cur_p = gmtime(&t);
#else
		gmtime_r(&t, &cur);
		cur_p = &cur;
#endif
		if (strftime(date, sizeof(date),
			"%a, %d %b %Y %H:%M:%S GMT", cur_p) != 0) {
			mhf_add_header(headers, "Date", date);
		}
	}
}


