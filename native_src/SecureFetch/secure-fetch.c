/*
Keys4All Thunderbird-Addon
Designed and developed by
Fraunhofer Institute for Secure Information Technology SIT
<https://www.sit.fraunhofer.de>
(C) Copyright FhG SIT, 2018

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//Windows defines
// #define socklen_t int32_t
//shared
#include <stdio.h>	/* for printf */
#include <unbound.h>	/* unbound API - BSD-LICENSE*/
#include <stdbool.h> /* bool */
#include <ldns/ldns.h> /* BSD-LICENSE*/
#include <ldns/rdata.h>
#include <ldns/dane.h>
#include <math.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

//Windows includes
/*
#define socklen_t int32_t
#include <ws2tcpip.h>
#include <Winsock2.h>
*/


//Gnu/Linux includes

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>  // for inet_ntoa


#define CLOG_MAIN
#include "clog.h"

// Constants
/*
static char * SRV_PGP_SERVICE   = "_pgpkey-https.";
static char * SRV_SMIME_SERVICE =  "_ldaps.";
static char * SRV_PROTOCOL      = "_tcp.";
*/

static char * SRV_PGP_SERVICE   = "_hkps.";
static char * SRV_SMIME_SERVICE =  "_ldaps.";
static char * SRV_PROTOCOL      = "_tcp.";
const int LOGGER = 0; /* Unique identifier for logger */


//Forward Declarations
typedef struct keyserver_rr keyserver_rr;
typedef struct tlsa_rr tlsa_rr;
typedef struct http_response http_response;

char* getPGPKeyServer(char * cp_domain);
char* getSMIMEKeyServer(char * cp_domain);
keyserver_rr * sendSRVRequest(char * cp_domain, int * counter, bool for_pgp);
char * createSRVUri(char * cp_domain, bool for_pgp);
tlsa_rr * getTLSARecord(char * domain);
X509 * fetchCert(char * uri, char * port);
char * createTlsaName(const char * domain, const char * port, const char * protocol);
bool verifyCert(X509 * fetched_cert, tlsa_rr * tlsa_record);
void secureFetch(char * uri);
bool is_end_reached(char*buffer);
bool get_header_info(char * buffer, http_response * response);
char * parse_chunked_response(char * body);
bool getVerifiedCert(char * uri, char * port);
bool getVerifiedLDAPCert(char * uri, char * port);



//Main Function
int main(int argc, char *argv[]) {
  int r;

  /* Initialize the logger */
  r = clog_init_path(LOGGER, "log.txt");
  if (r != 0) {
      fprintf(stderr, "Logger initialization failed.\n");
      return 1;
  }
  /* Set minimum log level to info (default: debug) */
  clog_set_level(LOGGER, CLOG_DEBUG);
  /* Initialized */
  clog_info(CLOG(LOGGER), "%s", "Initialized Logger");

  if(argc == 3)
  {
    if(strcmp(argv[1], "-pgp") == 0)
    {
      char * s_ret = getPGPKeyServer(argv[2]);
      printf("%s", s_ret);
      clog_free(LOGGER);
      return 0;
    }
    else if(strcmp(argv[1], "-smime") == 0)
    {
      char * s_ret = getSMIMEKeyServer(argv[2]);
      printf("%s", s_ret);
      clog_free(LOGGER);
      return 0;
    }
    else if(strcmp(argv[1], "-dane") == 0)
    {
	  clog_info(CLOG(LOGGER), "SecureFetch -dane %s", argv[2]);
      secureFetch(argv[2]);
      clog_free(LOGGER);
      return 0;
    }
    else if(strcmp(argv[1], "-ldap-cert") == 0)
    {
	    clog_info(CLOG(LOGGER), "SecureFetch -ldap-cert %s", argv[2]);

      clog_free(LOGGER);
      if(getVerifiedLDAPCert(argv[2], "636"))
      {
        printf("%s", "true");
        return 0;
      }
      printf("%s", "false");
      return 0;
    }
  }
}



//Structs
struct keyserver_rr {
  char * uri;
  int port;
  char * type;
  int priority;
  int weight;
  int is_secure; //0:secure, 1:insecure, 2:bogus
};

struct tlsa_rr {
  int usage;
  int selector;
  int match_type;
  char * cert_association;
};


struct http_response {
  char *  status_code;
  int     content_length;
  bool    is_chunked_encoding;
  char *  body;
};


//Function Implementations
char* getPGPKeyServer(char * cp_domain)
{
  clog_info(CLOG(LOGGER), "getPGPKeyServer(%s)", cp_domain);
  int iCounter = 0;
  keyserver_rr * pgp_servers = sendSRVRequest(cp_domain, &iCounter, true);
  if(pgp_servers == NULL)
  {
    return "";
  }
  char * s_keyserver;
  //char s_port [20];
  //TODO: check if counter == 0 -> no srv entry
  //snprintf(s_port, 20, "%d", pgp_servers[0].port);
  s_keyserver = malloc(strlen(pgp_servers[0].uri));//TODO: + strlen(s_port));
  strcpy(s_keyserver, pgp_servers[0].uri);
  //strcat(s_keyserver, s_port);
  //s_keyserver[strlen(pgp_servers[0].uri)-1] = ':';
  clog_debug(CLOG(LOGGER), "PGP-Keyserver: %s", s_keyserver);
  return s_keyserver;
}



char* getSMIMEKeyServer(char * cp_domain)
{
  clog_debug(CLOG(LOGGER), "getSMIMEKeyServer(%s)", cp_domain);
  int iCounter = 0;
  keyserver_rr * pgp_servers = sendSRVRequest(cp_domain, &iCounter, false);
  if(pgp_servers == NULL)
  {
    return "";
  }
  char * s_keyserver;
  //char s_port [20];
  //TODO: check if counter == 0 -> no srv entry
  //snprintf(s_port, 20, "%d", pgp_servers[0].port);
  s_keyserver = malloc(strlen(pgp_servers[0].uri));// + strlen(s_port));
  strcpy(s_keyserver, pgp_servers[0].uri);
  //strcat(s_keyserver, s_port);
  //s_keyserver[strlen(pgp_servers[0].uri)-1] = ':';
  clog_debug(CLOG(LOGGER), "SMIME-Keyserver: %s", s_keyserver);
  return s_keyserver;
}


/**
 * takes a domain e.g. example.net and returns a keyserver_rr array containing the DNS entries.
 * @param cp_domain char * for domain
 * @param counter int * contains the number of entries in the returned array
 * @param for_pgp bool decides if DNS request for PGP *or* S/MIME keyserver address is requested
 * @return keyserver_rr * array containing the requested DNS entries
 */
keyserver_rr * sendSRVRequest(char * cp_domain, int * counter, bool for_pgp)
{
  clog_debug(CLOG(LOGGER), "sendSRVRequest(%s, int * counter, bool for_pgp)", cp_domain);
  struct ub_ctx* ctx;
  struct ub_result* result;
  int retval;
  *counter = 0;
  //TODO: as argument? check for buffer overflow
  int ks_array_size = 10;
  keyserver_rr * keyservers = malloc(ks_array_size * sizeof(keyserver_rr));

  /* create context */
  ctx = ub_ctx_create();
  if(!ctx) {
    //TODO:
    //printf("error: could not create unbound context\n");
    clog_warn(CLOG(LOGGER), "Could not create unbound context!%s", "");
    return NULL;
  }

  //TODO:  New: check if it works
  /* read public keys for DNSSEC verification */
  clog_debug(CLOG(LOGGER), "reading trust-anchor for DNSSEC%s", "");
	if( (retval=ub_ctx_add_ta_file(ctx, "trust-anchor.txt")) != 0) {
    clog_warn(CLOG(LOGGER), "error adding keys from trust-anchor: %s\n", ub_strerror(retval));
		return 1;
	}


  /* query for webserver */
  char * srv_uri = createSRVUri(cp_domain, for_pgp);
  retval = ub_resolve(ctx, srv_uri,
    33 /* TYPE A (IPv4 address) */,
    1 /* CLASS IN (internet) */, &result);
  if(retval != 0) {
    //TODO:
    //printf("resolve error: %s\n", ub_strerror(retval));
    return NULL;
  }

  /* check for data and parse srv rr */
  if(result->havedata)
  {
    char **data;
    int *len;
    for (data = result->data, len = result->len; *data; data++, len++) {
      if (*len < 7) {
        //TODO:
        /* Handle error */
        clog_warn(CLOG(LOGGER), "Can not parse received SRV-Entry%s", "");
        continue;
      }
      uint16_t priority = ((*data)[0] << 8) | (*data)[1];
      uint16_t weight   = ((*data)[2] << 8) | (*data)[3];
      uint16_t port     = ((*data)[4] << 8) | (*data)[5];
      ldns_rdf *target_rdf =
          ldns_dname_new_frm_data(*len - 6, *data + 6);
      char *target = ldns_rdf2str(target_rdf);

      //create keyserver_rr struct
      keyserver_rr keyserver;
      keyserver.uri = target;
      keyserver.priority = priority;
      keyserver.weight = weight;
      keyserver.port = port;

      if(for_pgp) {
        keyserver.type = SRV_PGP_SERVICE;
      } else {
        keyserver.type = SRV_SMIME_SERVICE;
      }

      /* show security status */
    	if(result->secure) {
        clog_debug(CLOG(LOGGER), "SRV-record is secured by DNSSEC %s", "");
        keyserver.is_secure = 1;
      }
    	else if(result->bogus) {
        clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check is bogus: %s", result->why_bogus);
        keyserver.is_secure = 2;
      }
    	else {
        clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check: INSECURE %s", "");
        keyserver.is_secure = 0;
      }

      keyservers[*counter] = keyserver;
      *counter = *counter + 1;
      ldns_rdf_free(target_rdf);
    }
  }
  else
  {
    clog_debug(CLOG(LOGGER), "Received no data for SRV-Record request %s", "");
    //TODO: check
    //ub_resolve_free(result);
    //ub_ctx_delete(ctx);
    //free(srv_uri);
    return NULL;
  }
  ub_resolve_free(result);
  ub_ctx_delete(ctx);
  free(srv_uri);

  return keyservers;
}


/**
 * creates the SRV-URI for the request.
 * @param cp_domain char * for domain
 * @param for_pgp bool decides if DNS request for PGP *or* S/MIME keyserver address is requested
 * @return char * SRV-URI
 */
char * createSRVUri(char * cp_domain, bool for_pgp)
{
  char* srv_uri;
  if(for_pgp)
  {
    srv_uri = malloc((strlen(cp_domain) + strlen(SRV_PROTOCOL) + strlen(SRV_PGP_SERVICE))*2);
    strcpy(srv_uri, SRV_PGP_SERVICE);
    strcat(srv_uri, SRV_PROTOCOL);
    strcat(srv_uri, cp_domain);

    return srv_uri;
  }
  srv_uri = malloc(strlen(cp_domain) + strlen(SRV_PROTOCOL) + strlen(SRV_SMIME_SERVICE));
  strcpy(srv_uri, SRV_SMIME_SERVICE);
  strcat(srv_uri, SRV_PROTOCOL);
  strcat(srv_uri, cp_domain);

  return srv_uri;
}


char * createTlsaName(const char * domain, const char * port, const char * protocol)
{
  unsigned int domain_length = strlen(domain);
  unsigned int port_length = strlen(port);
  unsigned int protocol_length = strlen(protocol);

  char * ret_value = malloc(domain_length + port_length + protocol_length + 5);
  strcpy(ret_value, "_");
  strcat(ret_value, port);
  strcat(ret_value, ".");
  strcat(ret_value, "_");
  strcat(ret_value, protocol);
  strcat(ret_value, ".");
  strcat(ret_value, domain);

  return ret_value;
}

tlsa_rr * getTLSARecord(char * domain)
{
  clog_info(CLOG(LOGGER), "Function: getTlsaRecord: %s", domain);
  struct ub_ctx* ctx;
  struct ub_result* result;
  ldns_pkt * ldns_packet = NULL;
  ldns_status packet_status = 0;
  ldns_rr_list *rr_list = NULL;
  char * port = (char *)malloc(sizeof(char));

  strcpy(port,"443");
  char * protocol = (char *)malloc(sizeof(char)*3);
  strcpy(protocol, "tcp");

  tlsa_rr * tlsa_record = malloc(sizeof(tlsa_rr));
  int retval;
  int * counter = 0;

  /* create context */
  ctx = ub_ctx_create();
  if(!ctx) {
    //TODO:
    //printf("error: could not create unbound context\n");
    return NULL;
  }

  /* read public keys for DNSSEC verification */
	if( (retval=ub_ctx_add_ta_file(ctx, "trust-anchor.txt")) != 0) {
		clog_warn(CLOG(LOGGER), "error adding keys from trust-anchor: %s\n", ub_strerror(retval));
		return 1;
	}

  /* query for tlsa */
  char * tlsa_uri = createTlsaName(domain, port, protocol);
  retval = ub_resolve(ctx, tlsa_uri, 52,
	    1, &result);
  //TODO:
  //free(tlsa_uri);

  if(retval != 0) {
    clog_warn(CLOG(LOGGER), "Could not resolve DNS-request: %s", ub_strerror(retval));
    return NULL;
  }

  if (result->rcode == LDNS_RCODE_SERVFAIL) {
    printf("resolve error: %s\n", "rcode servfail");
    clog_warn(CLOG(LOGGER), "Could not resolve DNS-request: %s", "LDNS_RCODE_SERVFAIL");
  }

  if(result->secure) {
      if(result->havedata) {
        packet_status = ldns_wire2pkt(&ldns_packet,
  			    (uint8_t *)(result->answer_packet),
  			    result->answer_len);
      }
      clog_debug(CLOG(LOGGER), "Received TLSA-Record is secure %s", "");


      if (packet_status != LDNS_STATUS_OK) {
        clog_warn(CLOG(LOGGER), "Failed to parse dns-packet %s", "");
      }

      rr_list = ldns_pkt_rr_list_by_type(ldns_packet,
    			    52, LDNS_SECTION_ANSWER);
    	if (rr_list == NULL) {
    		clog_warn(CLOG(LOGGER), "DNS-Packet has no ressource records %s", "");
    	}
    	ldns_pkt_free(ldns_packet); ldns_packet = NULL;


      for (int i = 0; i < ldns_rr_list_rr_count(rr_list); ++i) {
            //extract rdf
    				ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
    				assert(rr != NULL);
    				//parsed to multiple rdfs?
    				if (ldns_rr_rd_count(rr) < 4) {
              clog_warn(CLOG(LOGGER), "RR number %d has not enough fields", i);
    				}
    				ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
    				    *rdf_selector      = ldns_rr_rdf(rr, 1),
    				    *rdf_matching_type = ldns_rr_rdf(rr, 2),
    				    *rdf_association   = ldns_rr_rdf(rr, 3);

    				if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
    				    (ldns_rdf_size(rdf_selector) != 1) ||
    				    (ldns_rdf_size(rdf_matching_type) != 1)) {
              clog_warn(CLOG(LOGGER), "Improperly formatted TLSA RR %d", i);
    				}
            uint8_t cert_usage, selector, matching_type;
    				uint8_t *association;
    				size_t association_size;
    				cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
    				selector = ldns_rdf_data(rdf_selector)[0];
    				matching_type = ldns_rdf_data(rdf_matching_type)[0];
    				association = ldns_rdf_data(rdf_association);
    				association_size = ldns_rdf_size(rdf_association);
            char * result = malloc(sizeof(char)*2000);
            *result = '\0';
            uint8_to_hex(association, association_size, result);
            //LOG
            //printf("usage: %i, association: %s, selector: %i, matching-type: %i", cert_usage, result, selector, matching_type);
            tlsa_record->usage = cert_usage;
            tlsa_record->selector = selector;
            tlsa_record->match_type = matching_type;
            tlsa_record->cert_association = result;
            return tlsa_record;
      }
    }
  	else if(result->bogus) {
      clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check is bogus: %s", result->why_bogus);
      return NULL;
    }
  	else {
      clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check: INSECURE %s", "");
      return NULL;
    }

    //keyservers[*counter] = keyserver;
    //*counter = *counter + 1;
    //TODO: which variable should be freed here???
    //ldns_rdf_free(target_rdf);

    //TODO: fix
    ub_resolve_free(result);
    ub_ctx_delete(ctx);


}

tlsa_rr * getLDAPTLSARecord(char * domain)
{
  clog_info(CLOG(LOGGER), "Function: getTlsaRecord: %s", domain);
  struct ub_ctx* ctx;
  struct ub_result* result;
  ldns_pkt * ldns_packet = NULL;
  ldns_status packet_status = 0;
  ldns_rr_list *rr_list = NULL;
  char * port = (char *)malloc(sizeof(char));

  strcpy(port,"389");
  char * protocol = (char *)malloc(sizeof(char)*3);
  strcpy(protocol, "tcp");

  tlsa_rr * tlsa_record = malloc(sizeof(tlsa_rr));
  int retval;
  int * counter = 0;

  /* create context */
  ctx = ub_ctx_create();
  if(!ctx) {
    //TODO:
    //printf("error: could not create unbound context\n");
    return NULL;
  }

  /* read public keys for DNSSEC verification */
	if( (retval=ub_ctx_add_ta_file(ctx, "trust-anchor.txt")) != 0) {
		clog_warn(CLOG(LOGGER), "error adding keys from trust-anchor: %s\n", ub_strerror(retval));
		return 1;
	}

  /* query for tlsa */
  char * tlsa_uri = createTlsaName(domain, port, protocol);
  retval = ub_resolve(ctx, tlsa_uri, 52,
	    1, &result);
  //TODO:
  //free(tlsa_uri);

  if(retval != 0) {
    clog_warn(CLOG(LOGGER), "Could not resolve DNS-request: %s", ub_strerror(retval));
    return NULL;
  }

  if (result->rcode == LDNS_RCODE_SERVFAIL) {
    printf("resolve error: %s\n", "rcode servfail");
    clog_warn(CLOG(LOGGER), "Could not resolve DNS-request: %s", "LDNS_RCODE_SERVFAIL");
  }

  if(result->secure) {
      if(result->havedata) {
        packet_status = ldns_wire2pkt(&ldns_packet,
  			    (uint8_t *)(result->answer_packet),
  			    result->answer_len);
      }
      clog_debug(CLOG(LOGGER), "Received TLSA-Record is secure %s", "");


      if (packet_status != LDNS_STATUS_OK) {
        clog_warn(CLOG(LOGGER), "Failed to parse dns-packet %s", "");
      }

      rr_list = ldns_pkt_rr_list_by_type(ldns_packet,
    			    52, LDNS_SECTION_ANSWER);
    	if (rr_list == NULL) {
    		clog_warn(CLOG(LOGGER), "DNS-Packet has no ressource records %s", "");
    	}
    	ldns_pkt_free(ldns_packet); ldns_packet = NULL;


      for (int i = 0; i < ldns_rr_list_rr_count(rr_list); ++i) {
            //extract rdf
    				ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
    				assert(rr != NULL);
    				//parsed to multiple rdfs?
    				if (ldns_rr_rd_count(rr) < 4) {
              clog_warn(CLOG(LOGGER), "RR number %d has not enough fields", i);
    				}
    				ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
    				    *rdf_selector      = ldns_rr_rdf(rr, 1),
    				    *rdf_matching_type = ldns_rr_rdf(rr, 2),
    				    *rdf_association   = ldns_rr_rdf(rr, 3);

    				if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
    				    (ldns_rdf_size(rdf_selector) != 1) ||
    				    (ldns_rdf_size(rdf_matching_type) != 1)) {
              clog_warn(CLOG(LOGGER), "Improperly formatted TLSA RR %d", i);
    				}
            uint8_t cert_usage, selector, matching_type;
    				uint8_t *association;
    				size_t association_size;
    				cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
    				selector = ldns_rdf_data(rdf_selector)[0];
    				matching_type = ldns_rdf_data(rdf_matching_type)[0];
    				association = ldns_rdf_data(rdf_association);
    				association_size = ldns_rdf_size(rdf_association);
            char * result = malloc(sizeof(char)*2000);
            *result = '\0';
            uint8_to_hex(association, association_size, result);
            //LOG
            //printf("usage: %i, association: %s, selector: %i, matching-type: %i", cert_usage, result, selector, matching_type);
            tlsa_record->usage = cert_usage;
            tlsa_record->selector = selector;
            tlsa_record->match_type = matching_type;
            tlsa_record->cert_association = result;
            clog_debug(CLOG(LOGGER), "Returning secure TLSA-Record %s", "");
            return tlsa_record;
      }
    }
  	else if(result->bogus) {
      clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check is bogus: %s", result->why_bogus);
      return NULL;
    }
  	else {
      clog_warn(CLOG(LOGGER), "SRV-record's DNSSEC-check: INSECURE %s", "");
      return NULL;
    }

    //keyservers[*counter] = keyserver;
    //*counter = *counter + 1;
    //TODO: which variable should be freed here???
    //ldns_rdf_free(target_rdf);

    //TODO: fix
    ub_resolve_free(result);
    ub_ctx_delete(ctx);


}

void uint8_to_hex(uint8_t * bin, size_t size, char * result)
{
  char buffer [2];
  for(int i = 0; i < 32; i++) {
    sprintf(buffer,"%02x",bin[i]);
    strcat(result, buffer);
  }
}

X509 * fetchCert(char * uri, char * port)
{
  clog_debug(CLOG(LOGGER), "Entered fetchCert: %s", "");
  //Create SSL ctx
  SSL_METHOD *ssl_method;
  SSL_CTX *ssl_ctx;
  SSL * ssl;
  X509 *cert;

  SSL_library_init();
  OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
  SSL_load_error_strings();			/* Bring in and register error messages */
  ssl_method = SSLv23_client_method();		/* Create new client-method instance */
  ssl_ctx = SSL_CTX_new(ssl_method);			/* Create new context */
  if ( ssl_ctx == NULL )
  {
      ERR_print_errors_fp(stderr);
      //TODO: error
      return;
  }
  clog_debug(CLOG(LOGGER), "fetchCert: created openssl context %s", "");

  //Open connection to server
  int server_socket;
  struct hostent *host;
  struct sockaddr_in addr; //TODO: pointer or not?

  if ( (host = gethostbyname(uri)) == NULL )
  {
    clog_debug(CLOG(LOGGER), "fetchCert: gethostbyname == null %s", "");
    //TODO: error
      return;
  }
  clog_debug(CLOG(LOGGER), "fetchCert: got host by name %s", "");

  server_socket = socket(PF_INET, SOCK_STREAM, 0);
  clog_debug(CLOG(LOGGER), "fetchCert: created socket %s", "");
  memset(&addr, 0, sizeof(addr));
  clog_debug(CLOG(LOGGER), "fetchCert: set address %s", "");
  addr.sin_family = AF_INET;
  clog_debug(CLOG(LOGGER), "fetchCert: set socket family %s", "");
  addr.sin_port = htons(atoi(port));
  clog_debug(CLOG(LOGGER), "fetchCert: set port %s", "");
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  clog_debug(CLOG(LOGGER), "fetchCert: creating connection %s", "");

  if ( connect(server_socket, &addr, sizeof(addr)) != 0 )
  {
    clog_warn(CLOG(LOGGER), "Could not connect to server %s", uri);
    close(server_socket);
    return;
  }

  clog_debug(CLOG(LOGGER), "fetchCert: creating ssl request %s", "");
  //Create request
  ssl = SSL_new(ssl_ctx);
  SSL_set_fd(ssl, server_socket);				/* attach the socket descriptor */
  if ( SSL_connect(ssl) != 1 )			/* perform the connection */
  {
      clog_warn(CLOG(LOGGER), "Could not connect to server with SSL/TLS encryption: %s", uri);
      //TODO: delete
      //ERR_print_errors_fp(stderr);
      return;
  }
  else
  {
      clog_debug(CLOG(LOGGER), "Connected to server with SSL/TLS encryption: %s", SSL_get_cipher(ssl));
      //TODO: LOG
      //ShowCerts(ssl);								/* get any certs */

      //read certificate
      cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
      return cert;
      //TODO:
      SSL_free(ssl);								/* release connection state */
  }
  close(server_socket);									/* close socket */
  SSL_CTX_free(ssl_ctx);								/* release context */
}

X509 * fetchStartTLSCert(char * uri, char * port)
{
  clog_debug(CLOG(LOGGER), "Entered fetchCert: %s", "");
  //Create SSL ctx
  SSL_METHOD *ssl_method;
  SSL_CTX *ssl_ctx;
  SSL * ssl;
  X509 *cert;

  SSL_library_init();
  OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
  SSL_load_error_strings();			/* Bring in and register error messages */
  ssl_method = SSLv23_client_method();		/* Create new client-method instance */
  ssl_ctx = SSL_CTX_new(ssl_method);			/* Create new context */
  if ( ssl_ctx == NULL )
  {
      ERR_print_errors_fp(stderr);
      //TODO: error
      return;
  }
  clog_debug(CLOG(LOGGER), "fetchCert: created openssl context %s", "");

  //Open connection to server
  int server_socket;
  struct hostent *host;
  struct sockaddr_in addr; //TODO: pointer or not?

  if ( (host = gethostbyname(uri)) == NULL )
  {
    clog_debug(CLOG(LOGGER), "fetchCert: gethostbyname == null %s", "");
    //TODO: error
      return;
  }
  clog_debug(CLOG(LOGGER), "fetchCert: got host by name %s", "");

  server_socket = socket(PF_INET, SOCK_STREAM, 0);
  clog_debug(CLOG(LOGGER), "fetchCert: created socket %s", "");
  memset(&addr, 0, sizeof(addr));
  clog_debug(CLOG(LOGGER), "fetchCert: set address %s", "");
  addr.sin_family = AF_INET;
  clog_debug(CLOG(LOGGER), "fetchCert: set socket family %s", "");
  addr.sin_port = htons(atoi(port));
  clog_debug(CLOG(LOGGER), "fetchCert: set port %s", "");
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  clog_debug(CLOG(LOGGER), "fetchCert: creating connection %s", "");

  if ( connect(server_socket, &addr, sizeof(addr)) != 0 )
  {
    clog_warn(CLOG(LOGGER), "Could not connect to server %s", uri);
    close(server_socket);
    return;
  }
  clog_debug(CLOG(LOGGER), "fetchCert: sending StartTLS command %s", "");
  send(server_socket, "STARTTLS\r\n", sizeof("STARTTLS\r\n"), 0);

  clog_debug(CLOG(LOGGER), "fetchCert: sleep... %s", "");
  sleep(2);

  clog_debug(CLOG(LOGGER), "fetchCert: creating ssl request %s", "");
  //Create request
  ssl = SSL_new(ssl_ctx);
  SSL_set_fd(ssl, server_socket);				/* attach the socket descriptor */
  if ( SSL_connect(ssl) != 1 )			/* perform the connection */
  {
      clog_warn(CLOG(LOGGER), "Could not connect to server with SSL/TLS encryption: %s", uri);
      //TODO: delete
      //ERR_print_errors_fp(stderr);
      return;
  }
  else
  {
      clog_debug(CLOG(LOGGER), "Connected to server with SSL/TLS encryption: %s", SSL_get_cipher(ssl));
      //TODO: LOG
      //ShowCerts(ssl);								/* get any certs */

      //read certificate
      cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
      return cert;
      //TODO:
      SSL_free(ssl);								/* release connection state */
  }
  close(server_socket);									/* close socket */
  SSL_CTX_free(ssl_ctx);								/* release context */
}


bool verifyCert(X509 * fetched_cert, tlsa_rr * tlsa_record)
{
  ldns_rr * own_tlsa_rr = malloc(sizeof(ldns_rr)*6);
  ldns_status status;

  status = ldns_dane_create_tlsa_rr(/*ldns_rr** */  &own_tlsa_rr,
             /*ldns_tlsa_certificate_usage*/      tlsa_record->usage,
             /*ldns_tlsa_selector*/               tlsa_record->selector,
             /*ldns_tlsa_matching_type*/          tlsa_record->match_type,
             /*X509* */                           fetched_cert);
  if(status != LDNS_STATUS_OK)
  {
    clog_warn(CLOG(LOGGER), "Error parsing the certificate %s", "");
    return false;
  }


  ldns_rr *rr = own_tlsa_rr;
  //parsed to multiple rdfs?
  if (ldns_rr_rd_count(rr) < 4) {
    clog_warn(CLOG(LOGGER), "Error at creating new TLSA record for verifying the server certificate: RR has not enough fields %s", "");
    return false;
  }

  ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
      *rdf_selector      = ldns_rr_rdf(rr, 1),
      *rdf_matching_type = ldns_rr_rdf(rr, 2),
      *rdf_association   = ldns_rr_rdf(rr, 3);

  if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
      (ldns_rdf_size(rdf_selector) != 1) ||
      (ldns_rdf_size(rdf_matching_type) != 1)) {
    clog_warn(CLOG(LOGGER), "TLSA-RR is improperly formatted %s", "");
    return false;
  }
  uint8_t new_cert_usage, new_selector, new_matching_type;
  uint8_t *new_association;
  size_t new_association_size;
  new_cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
  new_selector = ldns_rdf_data(rdf_selector)[0];
  new_matching_type = ldns_rdf_data(rdf_matching_type)[0];
  new_association = ldns_rdf_data(rdf_association);
  new_association_size = ldns_rdf_size(rdf_association);
  char * new_result = malloc(sizeof(char)*2000);
  *new_result = '\0';
  uint8_to_hex(new_association, new_association_size, new_result);

  if(
     strcmp(tlsa_record->cert_association, new_result) == 0 &&
      tlsa_record->usage == new_cert_usage &&
      tlsa_record->selector == new_selector &&
      tlsa_record->match_type == new_matching_type
  )
  {
    clog_debug(CLOG(LOGGER), "Could Cert be verified with TLSA-record: %s", "True");
    return true;
  }
  clog_warn(CLOG(LOGGER), "Could Cert be verified with TLSA-record: %s", "False");
  return false;
}



bool getVerifiedLDAPCert(char * uri, char * port)
{
  clog_info(CLOG(LOGGER), "%s", "entered bool getVerifiedCert");

  //get TLSA-record
  tlsa_rr * tlsa;
  tlsa = getLDAPTLSARecord(uri);

  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: got TLSA-record");
  //get certificate
  X509 * cert;
  cert = fetchCert(uri, port);

  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: got ldap-cert");
  //verify certificate
  bool is_secure = verifyCert(cert, tlsa);
  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: verified cert");
  //return verification info
  if(is_secure == false)
  {
    return false;
  }

  //create file path to save certificate
  char * file_path = malloc((strlen(uri) + strlen("certs/")) * sizeof(char/* *file_path*/) );
  strcpy(file_path, "certs/");
  strcat(file_path, uri);
  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: created filepath");

  //write certificate to file
  FILE *fp = fopen(file_path, "w");
  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: opened file");
  int rc = PEM_write_X509(fp, cert);
  clog_info(CLOG(LOGGER), "%s", "getVerifiedCert: wrote file");
  if(rc)
  {
    return true;
  }
  return false;
}



void secureFetch(char * uri)
{
  clog_info(CLOG(LOGGER), "%s", "entered void secureFetch");
  //char address[] = "10.10.10.10/10";
  char delimiter[] = "/";
  char * hostname = malloc(strlen(uri)*sizeof(char)*2);//TODO: check if allocation size is right
  strcpy(hostname, uri);
  char * path = malloc(strlen(uri)*sizeof(char)*2);//TODO: check if allocation size is right
  clog_info(CLOG(LOGGER), "%s", "secureFetch: allocated memory for hostname & path");
  path = strchr(uri, '/');
  if (path != NULL)
  {
    hostname = strtok(hostname, delimiter);
  }
  else
  {
    path = "/";
  }

  clog_info(CLOG(LOGGER), "%s", "secureFetch: getTLSARecord");
  //LOG: hostname + path
  //TODO:
  //fetch and verify cert: DNSSEC + DANE
  tlsa_rr * tlsa_record = getTLSARecord(hostname);
  clog_info(CLOG(LOGGER), "%s", "secureFetch: fetchCert");
  X509 * cert = fetchCert(uri, "443");


  //use cert for request
  clog_info(CLOG(LOGGER), "%s", "secureFetch: Trying TLS request");
  //Create SSL ctx
  SSL_METHOD *ssl_method;
  SSL_CTX *ssl_ctx;
  SSL * ssl;

  SSL_library_init();
  OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
  SSL_load_error_strings();			/* Bring in and register error messages */
  ssl_method = SSLv23_client_method();		/* Create new client-method instance */
  ssl_ctx = SSL_CTX_new(ssl_method);			/* Create new context */
  if ( ssl_ctx == NULL )
  {
      clog_warn(CLOG(LOGGER), "Could not create OpenSSL context %s", "");
      //ERR_print_errors_fp(stderr);
      //TODO: error
      return;
  }

  //Open connection to server
  int server_socket;
  struct hostent *host;
  struct sockaddr_in addr;

  if ( (host = gethostbyname(hostname)) == NULL )
  {
    clog_warn(CLOG(LOGGER), "Unable to get host by name %s", "");
    return;
  }
  server_socket = socket(PF_INET, SOCK_STREAM, 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(atoi("443"));
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(server_socket, &addr, sizeof(addr)) != 0 )
  {
      close(server_socket);
      clog_warn(CLOG(LOGGER), "Unable to connect to host %s", hostname);
      return;
  }
  //Create request
  ssl = SSL_new(ssl_ctx);
  SSL_set_fd(ssl, server_socket);				/* attach the socket descriptor */
  if ( SSL_connect(ssl) != 1 )			/* perform the connection */
  {
      clog_warn(CLOG(LOGGER), "Could not create connection with SSL/TLS %s", "");
      return;
  }
  else
  {
      //read certificate
      cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */

      //verify cert
      if( ! verifyCert(cert, tlsa_record) )
      {
        clog_warn(CLOG(LOGGER), "Certificate could not be verified with DANE %s", "");
        return;
      }
      clog_debug(CLOG(LOGGER), "Certificate could be verified with DANE %s", "");

      //send data
      clog_debug(CLOG(LOGGER), "Allocate memory to send data %s", "");
      char * text = malloc(sizeof(char)*2000);
      clog_info(CLOG(LOGGER), "Allocated memory to send data %s", "");
      strcpy(text, "GET ");
      clog_info(CLOG(LOGGER), "Copied string 'GET ' %s", "");
      clog_info(CLOG(LOGGER), "Path string is: %s", path);
      strcat(text, path);
      clog_info(CLOG(LOGGER), "Appended string path %s", path);
      strcat(text, " HTTP/1.1");
      strcat(text, "\r\n");
      strcat(text, "Host: ");
      strcat(text, hostname);
      clog_info(CLOG(LOGGER), "Appended string Hostname %s", hostname);
      strcat(text, "\r\n\r\n");
      clog_debug(CLOG(LOGGER), "Starting SSL_write %s", "");
      SSL_write(ssl, text, strlen(text));


      //read data
      const int readSize = 4096;
      char *rc = '\0';
      int received, count = 0;
      char buffer[4096];
      bool isChunked = false;
      bool isHeaderReceived = false;
      http_response * response = malloc(sizeof(http_response));


      while (1)
      {
        if (!rc)
          rc = malloc (readSize * sizeof (char) + 1);
        else
          rc = realloc (rc, (count + 1) *
                        readSize * sizeof (char) + 1);

        received = SSL_read (ssl, buffer, readSize);
        buffer[received] = '\0';

        if (received > 0)
        {
          strcat (rc, buffer);
          clog_debug(CLOG(LOGGER), "Received chunk %s", "");
        }
        else
        {
          get_header_info(rc, response);
          //TODO: are more checks needed?
          clog_debug(CLOG(LOGGER), "Status-Code: %s", response->status_code);

          if(strcmp(response->status_code, "200") != 0 )
          {
            return;
          }

          if(response->is_chunked_encoding)
          {
            clog_debug(CLOG(LOGGER), "Response has chunked encoding %s", "");
            char * parsed_response;
            parsed_response = parse_chunked_response(response->body);
            printf("%s", parsed_response);
            clog_debug(CLOG(LOGGER), "Received DANE-secured response: \n%s", parsed_response);
          }
          else
          {
            //TODO:
            printf("%s", rc/*response->body*/);
          }


          break;
        }
        count++;
    }
    return ;

    //TODO:
    SSL_free(ssl);								/* release connection state */

    close(server_socket);									/* close socket */
    SSL_CTX_free(ssl_ctx);								/* release context */
  }
}



//returns false if no complete header is in the buffer
bool get_header_info(char * buffer, http_response * response)
{
  char * headerEnd;
  char * chunkedEncoding;
  char * contentLength;

  //check if complete header is in the buffer
  headerEnd = strstr(buffer, "\r\n\r\n");
  if(headerEnd == NULL)
  {
    return false;
  }
  response->body = (headerEnd+4);

  //check for chunked encoding
  chunkedEncoding = strstr(buffer, "\r\nTransfer-Encoding: chunked\r\n");
  if( chunkedEncoding != NULL)
  {
    response->is_chunked_encoding = true;
    response->content_length = 0;
  }
  else
  {
    response->is_chunked_encoding = false;
    //check for content-length header
    contentLength = strstr(buffer, "\r\nContent-Length: ");
  }

  //get status_code
  char * pstatus_code = strstr(buffer, "HTTP/1.1 ");
  pstatus_code = pstatus_code + 9;
  char * status_code = malloc(sizeof(char)*4);
  if(pstatus_code != NULL)
  {
    strncpy(status_code, pstatus_code, 3);
    status_code[3] = '\0';
    response->status_code = status_code;//pstatus_code;
  }
  return true;
}



bool is_end_reached(char*buffer)
{
  if(strstr(buffer, "\r\n\r\n") != NULL)
  {
    return true;
  }

  return false;
}


char * parse_chunked_response(char * body)
{
  bool isChunkLengthLine = true;
  bool is_r = true;
  bool is_first_token = true;
  char * temp_string = malloc(sizeof(char)*strlen(body));
  strcpy(temp_string, body);
  char * parsed_body = malloc(sizeof(char)*strlen(body));
  *parsed_body = '\0';
  char * ptr;
  int copied_chunks = 0;

  long int i_chunk_length = -1;
  char * s_chunk_length = malloc(sizeof(char)*40);
  *s_chunk_length = '\0';

  //loop: (realloc if necessary),read chunk size, read chunk, copy chunk to destination
  for(char * ptr = body; *ptr; ++ptr)
  {
    if(i_chunk_length == -1)
    {
      //copy if end is not reached
      if(*ptr != '\n' && *(ptr-1) != '\r')
      {
        if(is_first_token && *ptr != '\n' && *ptr != '\r')
        {
          strncpy(s_chunk_length, ptr, 1);
          s_chunk_length[1] = '\0';
          is_first_token = false;
        }
        else
        {
          if(*ptr != '\n' && *ptr != '\r')
          {
            strncat(s_chunk_length, ptr, 1);
          }
        }
      }
      else //if end is reached
      {
        i_chunk_length = strtol(s_chunk_length, NULL, 16);
      }
    }

    if(i_chunk_length != -1 && i_chunk_length != 0) //read & copy chunk
    {
      ptr = ptr +1;
      //LOG
      //printf("\n\n\nCopy chunk:\n Hex-Size: %s \n Int-Size: %i\n", s_chunk_length, i_chunk_length);
      strncat(parsed_body, ptr, i_chunk_length);
      ptr = ptr +1+ i_chunk_length;
      i_chunk_length = -1;
      s_chunk_length[0] = '\0';
      s_chunk_length[1] = '\0';
      s_chunk_length[2] = '\0';
      s_chunk_length[3] = '\0';
      s_chunk_length[4] = '\0';
      copied_chunks++;
    }
  }
  return parsed_body;
}
