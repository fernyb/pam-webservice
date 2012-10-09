#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <pwd.h>

#include <curl/curl.h>
#include <json-c/json.h>

typedef struct {
  const char *host;
  const char *port;
  const char *path;
  const char *user_field;
  const char *passwd_field;
  int debug;
} Service;


struct string {
  char *ptr;
  size_t len;
};

void init_string(struct string *s) {
  s->len = 0;
  s->ptr = (char *)malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
  size_t new_len = s->len + size*nmemb;
  s->ptr = (char *)realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

int make_request(const char *username, const char *passwd, Service serv)
{
  CURL *curl;
  CURLcode res;
  json_object *new_obj;
 
  curl = curl_easy_init();
  if(curl) {
    struct string s;
    init_string(&s);

    char endpoint[1024];
    sprintf(endpoint, "http://%s:%s%s?%s=%s&%s=%s", serv.host, serv.port, serv.path, serv.user_field, username, serv.passwd_field, passwd);

    if(serv.debug == 1) {
      syslog(LOG_DEBUG, "%s", endpoint);
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    //printf("******** %s\n", s.ptr);
  
    new_obj = json_tokener_parse(s.ptr);
    //printf("new_obj.to_string()=%s\n", json_object_to_json_string(new_obj));
    
    json_object * obj;
    obj = json_object_object_get(new_obj, "found");
    const char *response = json_object_to_json_string(obj);
    if(serv.debug == 1) {
      syslog(LOG_DEBUG, "%s", response);
    }

    int found;
    if(strcmp(response, "\"ok\"") == 0) {
      found = 1;
      if(serv.debug == 1) {
        syslog(LOG_DEBUG, "%s", "Authentication response is ok");
      }
    } else {
      found = 0;
      if(serv.debug == 1) {
        syslog(LOG_DEBUG, "%s", "Authentication response failed");
      }
    }

    json_object_put(new_obj);

    /* Check for errors */ 
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
 
    /* always cleanup */
    free(s.ptr); 
    curl_easy_cleanup(curl);

    if(found == 1) {
      if(serv.debug == 1) {
        syslog(LOG_DEBUG, "%s", "Authentication did pass");
      }
      return 1;
    }
  }
  if(serv.debug == 1) {
    syslog(LOG_DEBUG, "%s", "Authentication failed");
  }
  return 0;
}


/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

Service parse_webservice_args(int argc, const char **argv) {
  int i;
  char *token = NULL;
  const char *sep = "=";

  Service serv;
  serv.debug = 0;

  const char *name;

  for(i=0; i<argc; i++) {
    name = argv[i];
    token = strtok((char *)name, sep);

    if(strcmp(token, "debug") == 0) {
      serv.debug = 1;
      continue;
    }

    if(strcmp(token, "host") == 0) {
      token = strtok(NULL, sep);
      serv.host = token;
      continue;
    }
    if(strcmp(token, "port") == 0) {
      token = strtok(NULL, sep);
      serv.port = token;
      continue;
    }
    if(strcmp(token, "path") == 0) {
      token = strtok(NULL, sep);
      serv.path = token;
      continue;
    }
    if(strcmp(token, "user_field") == 0) {
      token = strtok(NULL, sep);
      serv.user_field = token;
      continue;
    }
    if(strcmp(token, "passwd_field") == 0) {
      token = strtok(NULL, sep);
      serv.passwd_field = token;
      continue;
    }
  }
  return serv;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  Service serv = parse_webservice_args(argc, argv);

  if(serv.debug == 1) {
    syslog(LOG_DEBUG, "host: %s", serv.host);
    syslog(LOG_DEBUG, "port: %s", serv.port);
    syslog(LOG_DEBUG, "path: %s", serv.path);
    syslog(LOG_DEBUG, "user_field: %s", serv.user_field);
    syslog(LOG_DEBUG, "passwd_field: %s", serv.passwd_field);
    syslog(LOG_DEBUG, "PAM SM AUTHENTICATION");
  }

	int retval;
  const char *rhost;
  const char *user = NULL;
  const char *passwd = NULL;
  static const char password_prompt[] = "Password:";

  int pgu_ret;

  pgu_ret = pam_get_user(pamh, &user, NULL);
  if (pgu_ret != PAM_SUCCESS || user == NULL) {
    return PAM_AUTH_ERR;
  }
  if(serv.debug) {
    syslog(LOG_DEBUG, "USER: %s", user);
  }

  if (PAM_SUCCESS != (retval = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, password_prompt))) {
    if(serv.debug == 1) {
      syslog(LOG_DEBUG, "%s => %s", "PAM NOT SUCCESS", passwd);
    }
  }

  if(serv.debug == 1) {
    syslog(LOG_DEBUG, "PASSWORD: %s", passwd);
  }

  if (pam_get_item(pamh, PAM_RHOST, (const void**)&rhost) == PAM_SUCCESS) {
    if(serv.debug == 1) {
      syslog(LOG_DEBUG, "RHOST: %s", rhost);
    }
  } else {
    rhost = NULL;
  }


  int resp = make_request(user, passwd, serv);
  if(resp == 1) {
    return PAM_SUCCESS;
  }
  return PAM_AUTH_ERR;
}
