/******************************************************************************

PROGRAM:  ssl-mp3server.c
SYNOPSIS:
**CHANGE dir_path VARIABLE inside handle_client function to relative folder of
  mp3 files for testing/use

**currently disconnects client after any command is recieved. Just needs a
  simple loop in the handle_client function
compile command (or run with included Makefile)
gcc ssl-mp3server.c -o ssl-mp3server -lssl -lcrypto -pthread

TODO:
.create loop for maintaining client connection until client sends "exit"
.ensure fault tolerance is accomplished accordingly
.more testing to ensure robust error handling
.potential opportunities for cleaning up/optimizing handle_client function
******************************************************************************/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <dirent.h>

#define BUFFER_SIZE       256
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define ERR_ARGLO	  1
#define ERR_COMD          2

//struct for client information
// client_addr and port are only necessary for server monitoring
typedef struct {
    int client_socket;
    SSL* ssl;
    struct sockaddr_in addr;
    char* client_addr;
    unsigned int port;
} ClientInfo;

int client_count;
/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of
the machine to that socket, then listens on the socket for incoming TCP
connections.

*******************************************************************************/
int create_socket(unsigned int port) {
  int    s;
  struct sockaddr_in addr;

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
  // any available network interface on the machine, so clients can connect
  // through any, e.g., external network interface, localhost, etc.

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address already
  // in use, or an invalid network address
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Server: Unable to bind to socket: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Listen for incoming TCP connections using the newly created and configured
  // socket. The second argument (1) indicates the number of pending connections
  // allowed, which in this case is one.  That means if the server is connected
  // to one client, a second client attempting to connect may receive an error,
  // e.g., connection refused.
  //
  // Failure could result from an invalid socket descriptor or from using a
  // socket descriptor that is already in use.
  if (listen(s, 1) < 0) {
    fprintf(stderr, "Server: Unable to listen: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("Server: Listening on TCP port %u\n", port);

  return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in
this program.  The function SSL_load_error_strings registers the error strings
for all of the libssl and libcrypto functions so that appropriate textual error
messages are displayed when error conditions arise. OpenSSL_add_ssl_algorithms
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl() {
  EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters
for the connection, and in this program, each context is configured using the
configure_context() function below. Each context object is created using the
function SSL_CTX_new(), and the result of that call is what is returned by this
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context() {
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid
                                // getting a compiler warning about the call to
                                // SSLv23_server_method()
  SSL_CTX*          ssl_ctx;

  // Use SSL/TLS method for server
  ssl_method = SSLv23_server_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx < 0) {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    strerror(errno);
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}

/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto().
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx) {
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  // Set the certificate to use, i.e., 'cert.pem'
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM)
      <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Set the private key contained in the key file, i.e., 'key.pem'
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

/******************************************************************************

This function is executed by each thread to handle a client connection.

Most of this initial function was just moved from ssl-server.c main() week4
******************************************************************************/
void* handle_client(void* arg) {
    ClientInfo* client_info = (ClientInfo*)arg;
    int client_socket = client_info->client_socket;
    SSL* ssl = client_info->ssl;
    struct sockaddr_in addr;
    int port = client_info->port;
    char buffer[BUFFER_SIZE];
    int nbytes_read;
    int nbytes_written;
    int rcount = 1;
    const char reply[] = "Hello World!";
    unsigned int len = sizeof(addr);
    char * client_addr = client_info->client_addr;
    char* dir_path = "audio";
    // Bind the SSL object to the network socket descriptor.
    SSL_set_fd(ssl, client_socket);

    // The last step in establishing a secure connection is calling SSL_accept(),
    // which executes the SSL/TLS handshake.
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Server: Could not establish secure connection:\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("Server: Established SSL/TLS connection with client (%s)\n", client_addr);
          //variables for marshalling
          while(true){
            bzero(buffer, BUFFER_SIZE);
            char cmd[256];
            char fname[256];
            char filler[256];
	          memset(cmd, 0, sizeof(cmd));
            memset(fname, 0, sizeof(fname));
            memset(filler, 0, sizeof(filler));

            printf("Waiting for message\n");
            nbytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);
	    //printf("Bytes Read: %d\n", nbytes_read);
     	    if (nbytes_read < 0) {
        	fprintf(stderr, "Client: Could not write message to socket: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
            }
	          printf("Server received message: ");
	          puts(buffer);
            int message = sscanf(buffer, "%s %s %s", cmd, fname, filler);
            printf("Message info: message = %d, cmd = %s, fname = %s, filler = %s\n", message, cmd, fname, filler);
            //maximum of two strings allowed in message
            //"exit"
            //"list"
            //"dl audio.mp3"
            if (message > 2) {
          		//too many args
          		memset(buffer, 0, sizeof(buffer));
              sprintf(buffer, "error fill %d", 7); //error back to client
              fprintf(stderr, "Server: Error: %s\n", strerror(7));
              if (SSL_write(ssl, buffer, strlen(buffer)) < 0)
                fprintf(stderr, "Server: Error sending message: %s\n", strerror(errno));
            } else if ((message < 1) || (strlen(buffer) < 1)) {
          		//too few args or empty
          		memset(buffer, 0, sizeof(buffer));
          		printf("Server: Error: Too few arguments.\n");
          		sprintf(buffer, "othererr fill %d", ERR_ARGLO);
              if (SSL_write(ssl, buffer, strlen(buffer)) < 0){
                fprintf(stderr, "Server: Error sending message: %s\n", strerror(errno));
              }
            } else {
              if(strcmp(cmd, "exit") == 0){
                //for no loop
                /*SSL_shutdown(ssl);
                SSL_free(ssl);

                // Close the socket descriptor
                close(client_socket);

                // Free the client_info memory
                free(client_info);
                printf("Server: Closed SSL/TLS connection with client (%s)\n", client_addr);
                client_count--;
                return NULL;
                */
                //for loop
                break;
              } //exits loop and shuts down connection

              if (strcmp(cmd, "list") == 0){
                //full path to file is built here. we need to reset dir_path to baseline in the case of looping
                dir_path = "audio";
                DIR* directory = opendir(dir_path);
                if(directory == NULL){
                  sprintf(buffer, "error fill %d", errno);
                  fprintf(stderr, "Server: Error: %s\n", strerror(errno));
                } else {
                  struct dirent* entry;
                  while((entry = readdir(directory)) != NULL){
                    memset(buffer, 0, sizeof(buffer));
                    if(entry->d_type == DT_REG){
                      const char* file_name = entry->d_name;
                      const char* extension = strrchr(file_name, '.');
                      if(extension != NULL && strcmp(extension, ".mp3") == 0){
                        printf("%s\n", file_name);
                        sprintf(buffer, "list %s", file_name);
                        if(SSL_write(ssl, buffer, strlen(buffer)) < 0){
                          fprintf(stderr,"Server: Error sending message: %s\n", strerror(errno));
                        }
                      }
                    }
                  }
                  memset(buffer, 0, sizeof(buffer));
                  sprintf(buffer, "end");
                  SSL_write(ssl, buffer, strlen(buffer));
                  closedir(directory);
                }
              } else if (strcmp(cmd, "dl") == 0) {
                //full path to file is built here. we need to reset dir_path to baseline in the case of looping
                dir_path = "audio";
                char fullpath[50];
                char *path_sep = "/";
                strcat(fullpath, dir_path); //fullpath = audio
                strcat(fullpath, path_sep); //fullpath = audio/
                strcat(fullpath, fname); //fullpath = audio/fname.mp3
                if (access(fullpath, F_OK) == 0) {
                    //file exists
                    printf("file '%s' exists, starting transfer\n", fname);
                    int sourcefd = open(fullpath, O_RDWR, 0);
                    if (sourcefd < 0) {
                      fprintf(stderr, "Server: Could not open file '%s': %s\n", fname, strerror(errno));
                      sprintf(buffer, "error fill %d", errno);
                      if (SSL_write(ssl, buffer, strlen(buffer)) < 0)
                        fprintf(stderr, "Server: Error sending message: %s\n", strerror(errno));
                    } else {
                      printf("trying to transfer\n");
                      //loop data transfer
                      printf("sending msg to prep client\n");
                      memset(buffer, 0, sizeof(buffer));
                      sprintf(buffer, "dl");
                      SSL_write(ssl, buffer, strlen(buffer));
                      memset(buffer, 0, sizeof(buffer));
                      int sentcount = 0;
                      while (rcount > 0) {
                        rcount = read(sourcefd, buffer, BUFFER_SIZE);
                        nbytes_written = SSL_write(ssl, buffer, rcount);
                        sentcount += nbytes_written;
                        printf("read: %d bytes, total transferred: %d bytes\n", rcount, sentcount);
                      }
                      memset(buffer, 0, sizeof(buffer));
                      close(sourcefd);
                    }
                } else {
                  //file doesn't exist
                  printf("file '%s' does not exist, sending error\n", fname);
                  sprintf(buffer, "error fill %d", 6);
                  if (SSL_write(ssl, buffer, strlen(buffer)) < 0)
                    fprintf(stderr, "Server: Error sending message: %s\n", strerror(errno));
                }
	      } else {
		memset(buffer, 0, sizeof(buffer));
	        printf("Server: Error: Invalid command.\n");
                sprintf(buffer, "othererr fill %d", ERR_COMD);
                if (SSL_write(ssl, buffer, strlen(buffer)) < 0){
                  fprintf(stderr, "Server: Error sending message: %s\n", strerror(errno));
                }
	      }
            }
            memset(buffer, 0, sizeof(buffer));
          }
        }

    // clean up the SSL connection and free the associated memory
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Close the socket descriptor
    close(client_socket);

    // Free the client_info memory
    free(client_info);
    printf("Server: Closed SSL/TLS connection with client (%s)\n", client_addr);
    client_count--;
    return NULL;
}

/******************************************************************************

The main function creates the server and starts accepting client connections.

******************************************************************************/
int main(int argc, char* argv[]) {
    unsigned int port = DEFAULT_PORT;
    int sockfd;
    int client;
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    SSL_CTX* ssl_ctx;
    pthread_t tid;
    char client_addr[INET_ADDRSTRLEN];
    // Check if a port number is specified as a command-line argument
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    // Initialize and create SSL data structures and algorithms
    init_openssl();
    ssl_ctx = create_new_context();
    configure_context(ssl_ctx);

    // Create a socket and listen for incoming connections
    sockfd = create_socket(port);

    while (true) {
        // Accept incoming connections
        client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            fprintf(stderr, "Server: Unable to accept connection\n");
            //exit(EXIT_FAILURE);
        } else {
          client_count++;
          printf("Number of Clients: %d\n", client_count);
          inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr, INET_ADDRSTRLEN);
          printf("Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);
          // Create a new SSL object for the client connection
          SSL* ssl = SSL_new(ssl_ctx);
          SSL_set_fd(ssl, client);

          // Perform SSL handshake
          if (SSL_accept(ssl) <= 0) {
              fprintf(stderr, "Server: Could not establish secure connection\n");
              ERR_print_errors_fp(stderr);
              SSL_free(ssl);
              close(client);
              continue;
          }

          // structure to hold client information
          ClientInfo* client_info = malloc(sizeof(ClientInfo));
          client_info->client_socket = client;
          client_info->ssl = ssl;
          client_info->addr = addr;
          client_info->client_addr = client_addr;
          client_info->port = port;

          // thread to handle the client connection
          if (pthread_create(&tid, NULL, handle_client, client_info) != 0) {
              fprintf(stderr, "Server: Failed to create thread\n");
              //exit(EXIT_FAILURE); //do not shut down serverr for failed connection
          }
      }
    }

    // Cleanup and free resources
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return 0;
}
