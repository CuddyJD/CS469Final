/******************************************************************************

PROGRAM:  ssl-server.c
AUTHOR:   Joshua Cuddy, William Sung
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a server that handles queries from a client over a ssl
          connection. Upon receipt of the query, the sqlite3 database will be 
          polled and results will be returned to the client. 

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
#include <errno.h>
#include <sqlite3.h>
#include <ctype.h>
#include <pthread.h>

#define BUFFER_SIZE 256
#define DEFAULT_PORT 4433
#define DEFAULT_BACKUPTIME 60
#define CERTIFICATE_FILE "cert.pem"
#define KEY_FILE "key.pem"
#define DB_PATH "./users.sqlite3"
#define DB_PATH_BACKUP "./users.sqlite3.bak"

//Mutex lock to prevent access to db while it's backing up
static pthread_mutex_t dbLock = PTHREAD_MUTEX_INITIALIZER;

//Time intervals between backups in seconds. Global to share between main and threads.
int backupTime = DEFAULT_BACKUPTIME;

//Results counter
int resultsCount = 0;

// thread addresses
pthread_t     threadIDs[10];
/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of
the machine to that socket, then listens on the socket for incoming TCP
connections.

*******************************************************************************/
int create_socket(unsigned int port)
{
  int s;
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
  if (s < 0)
  {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address already
  // in use, or an invalid network address
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
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
  if (listen(s, 1) < 0)
  {
    fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
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
void init_openssl()
{
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl()
{
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
SSL_CTX *create_new_context()
{
  const SSL_METHOD *ssl_method; // This should be declared 'const' to avoid
                                // getting a compiler warning about the call to
                                // SSLv23_server_method()
  SSL_CTX *ssl_ctx;

  // Use SSL/TLS method for server
  ssl_method = SSLv23_server_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx == NULL)
  {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    ERR_print_errors_fp(stderr);
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
void configure_context(SSL_CTX *ssl_ctx)
{
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  // Set the certificate to use, i.e., 'cert.pem'
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0)
  {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Set the private key contained in the key file, i.e., 'key.pem'
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
  {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

struct args {
  int tnum;
  int client;
  char* client_addr;
  SSL *ssl;
};

/**
 * Writes into results file specificied text
*/
void writeToResults(int fp, char *writeText) {
  int size = write(fp, writeText, strlen(writeText));
  if (size < 0) {
      fprintf(stderr, "Unable to write to: %s\n", strerror(errno));
  }
}


/*
* Callback function for sqlite3 exec, loops through results and displays them while adding into data file
*/
static int results(void *NotUsed, int argc, char **argv, char **azColName)
{
  int i;
  FILE *fp;

  resultsCount++;

  fp = fopen("data", "a");
  if (fp == NULL) {
    fprintf(stderr, "Error: Unable to open data file\n");
  }

  char writeText[BUFFER_SIZE];

  for (i = 0; i < argc; i++)
  {

    //printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    sprintf(writeText, "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    fputs(writeText, fp);
  }
  fclose(fp);
  printf("\n");

  return 0;
}

/**
 * concatenates two strings together into a new string
*/
char *concat(const char *s1, const char *s2)
{
  const size_t len1 = strlen(s1);
  const size_t len2 = strlen(s2);
  char *result = malloc(len1 + len2 + 1); 

  memcpy(result, s1, len1);
  memcpy(result + len1, s2, len2 + 1);
  return result;
}


/**
 * creates data file and writes header into file
*/
int makeDataFile()
{
  // create new data file or overwrite the old one
  FILE *fp;
  fp = fopen("data", "w+");
  if (fp == NULL)
  {
    return 1;
  }
  fprintf(fp, "DATABASE QUERY RESULTS\n");
  fclose(fp);
  return 0;
}

/**
 * creates results file
*/
int makeResultsFile()
{
  // operation results file
  mode_t mode = O_RDWR | O_CREAT | O_TRUNC | S_IRWXU; // modes for creating file (READ WRITE, CREATE IF NOT EXIST, TRUNCATE, WITH RWX FLAGS)
  int file = creat("results", mode);                  // create file with modes and target
  if (file < 0)                                       // check for errors
  {
    return 1;
  }
  return file;
}

//When called, function backs up the DB to a backup file every 'time' seconds
void* backup(void* param){
    long long byteCount;
	int readFile,
	    writeFile,
	    readResult,
	    writeResult;
	bool complete;
	char buffer[BUFFER_SIZE];

    printf("Backup Daemon: Starting up!\n");
    bzero(buffer, BUFFER_SIZE);

    //Continue backup loop forever!
    while(true){
        sleep(backupTime); //delay in backup cycles

        //Block until mutex lock is aquired
        pthread_mutex_lock(&dbLock);
        printf("Backup Daemon: Mutex lock aquired.\n");

        //Open source file and test for success
	    readFile = open(DB_PATH, O_RDONLY, 0);
	    if(readFile < 0){
		    printf("Backup Daemon: ERROR! Unable to open source file '%s' (%s)\n", DB_PATH, strerror(errno));
		    continue;
	    }

       	//Attempt to create destination for copy data
	    writeFile = creat(DB_PATH_BACKUP, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	    if(writeFile < 0){
		    printf("Backup Daemon: Unable to write to destination file '%s' (%s)\n", DB_PATH_BACKUP, strerror(errno));
		    continue;
	    }

        //Copy source file into destination
	    complete = false;
	    byteCount = 0;
	    while(!complete){
		    //Read next buffer
		    readResult = read(readFile, buffer, BUFFER_SIZE);
		    if(readResult == 0){             //End of file
			    complete = true;
			    printf("Backup Daemon: %lli total bytes backed up from '%s' to '%s'\n", byteCount, DB_PATH, DB_PATH_BACKUP);
			    close(readFile);
			    close(writeFile);

		    }else if(readResult < 0){        //Read error
			    printf("Backup Daemon: Unable to read from source file '%s' (%s)\n", DB_PATH, strerror(errno));
                pthread_mutex_unlock(&dbLock);
			    break;

		    }else if(!complete){             //Read success
			    writeResult = write(writeFile, buffer, readResult);

			    if(writeResult < 0){     //Write error
				    printf("Backup Daemon: Unable to write to destination file '%s' (%s)\n",
					    DB_PATH_BACKUP, strerror(errno));
                    pthread_mutex_unlock(&dbLock);
				    break;
			    }
			    byteCount += writeResult;    //tracking total data copied for final display
		    }
	    }

        //Release db mutex lock for client operations
        pthread_mutex_unlock(&dbLock);
        printf("Backup Daemon: Mutex lock released.\n");
    }
}

//When called, restores backup file into main db path. Modified non-looping version of backup method w reversed paths
bool restore(){
    long long byteCount;
	int readFile,
	    writeFile,
	    readResult,
	    writeResult;
	bool complete;
	char buffer[BUFFER_SIZE];

    printf("Backup Restore: Starting up!\n");
    bzero(buffer, BUFFER_SIZE);

    //Open source file and test for success
    readFile = open(DB_PATH_BACKUP, O_RDONLY, 0);
    if(readFile < 0){
        printf("Backup Restore: ERROR! Unable to open source file '%s' (%s)\n", DB_PATH_BACKUP, strerror(errno));
        return false;
    }

    //Attempt to create destination for copy data
    writeFile = creat(DB_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(writeFile < 0){
        printf("Backup Restore: Unable to write to destination file '%s' (%s)\n", DB_PATH, strerror(errno));
        return false;
    }

    //Copy source file into destination
    complete = false;
    byteCount = 0;
    while(!complete){
        //Read next buffer
        readResult = read(readFile, buffer, BUFFER_SIZE);
        if(readResult == 0){             //End of file
            complete = true;
            printf("Backup Restore: %lli total bytes restored up from '%s' to '%s'\n", byteCount, DB_PATH_BACKUP, DB_PATH);
            close(readFile);
            close(writeFile);
            return true;
        }else if(readResult < 0){        //Read error
            printf("Backup Restore: Unable to read from source file '%s' (%s)\n", DB_PATH_BACKUP, strerror(errno));
            return false;

        }else if(!complete){             //Read success
            writeResult = write(writeFile, buffer, readResult);

            if(writeResult < 0){     //Write error
                printf("Backup Restore: Unable to write to destination file '%s' (%s)\n", DB_PATH, strerror(errno));
                return false;
            }
            byteCount += writeResult;    //tracking total data copied for final display
        }
    }
}

/*
* Sends passed in file name over passed in ssl connection
*/
void sendFile(char* filename, SSL *ssl) {
  int file = open(filename, O_RDONLY);
        if (file < 0)
        {
          fprintf(stderr, "Error: %s\n", strerror(errno));
        }
        else
        {
          char buf[BUFFER_SIZE]; // buffer
          int size;              // size left in file

          // Loop: Server reads a chunk of the local file and sends it to the client via message
          do
          {
            size = read(file, buf, BUFFER_SIZE); // get remaining size and load buffer
            SSL_write(ssl, buf, size);           // send to client
          } while (size != 0);
        }
}

/**
 * Performs selected sqlite3 operation on term 
*/
int performOperation(char *operation, char *term) {
          //Aquire mutex lock to prevent access while backup in progress
        pthread_mutex_lock(&dbLock);
        printf("Server: Mutex lock aquired.\n");

        // start db code
        char dbName[50];
        strcpy(dbName, "users.sqlite3");

        sqlite3 *db;
        char *zErrMsg = 0;
        int rc;
        char *sql = "";
        sqlite3_stmt *res;
        const char *data = "Results function called";

        // add if db file does not exit look for backup first
        rc = sqlite3_open(dbName, &db);

        if (rc)
        {
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return rc;
        }
        else
        {
          fprintf(stderr, "Opened database successfully\n");
        }


        int file = makeResultsFile();

        // make user table
        // Create SQL statement
        sql = "CREATE TABLE if not exists USERS("
              "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
              "USERNAME TEXT NOT NULL);";

        // Execute SQL statement
        rc = sqlite3_exec(db, sql, results, 0, &zErrMsg);
        if (rc) {
          fprintf(stderr, "SQL error: %s\n", zErrMsg);
          sqlite3_free(zErrMsg);
          return rc;
        }

        if (strcmp(operation, "add") == 0)
        {

          char *first = "INSERT INTO USERS VALUES (NULL, '";
          char *second = "');";
          char *build = concat(first, term);
          sql = concat(build, second);
          rc = sqlite3_exec(db, sql, results, 0, &zErrMsg);
          
        }

        if (strcmp(operation, "delete") == 0)
        {
          char *first = "DELETE FROM USERS WHERE USERNAME='";
          char *second = "';";
          char *build = concat(first, term);
          sql = concat(build, second);

          rc = sqlite3_exec(db, sql, results, 0, &zErrMsg);

        }

        if (strcmp(operation, "display") == 0)
        {
          if (makeDataFile())
            fprintf(stderr, "Error: Unable to make data file \n");

          resultsCount = 0;
          if (strcmp(term, "all") == 0)
            sql = "SELECT * FROM USERS;";
          else {
            char *first = "SELECT * FROM USERS WHERE USERNAME='";
            char *second = "';";
            char *build = concat(first, term);
            sql = concat(build, second);
          }
          rc = sqlite3_exec(db, sql, results, (void *)data, &zErrMsg);
          printf("%d results found\n", resultsCount);
          FILE *fp;
          fp = fopen("data", "a");

          if (resultsCount == 0) {
            fprintf(fp, "No results found\n--End of File--");
          } else {
            fprintf(fp, "--End of File--\n");
          } 
          fclose(fp);
        }

        printf("Executing command: %s\n", sql);

        if (rc != SQLITE_OK)
        {
          fprintf(stderr, "SQL error: %s\n", zErrMsg);
          writeToResults(file, "Error: Unable to complete operation\n");
          sqlite3_free(zErrMsg);
        }
        else
        {
          fprintf(stdout, "Operation Complete\n");
          writeToResults(file, "Operation Complete\n");
        }

        // close db
        printf("Database closed\n");
        sqlite3_close(db);

        //Release mutex lock for backup daemon
        pthread_mutex_unlock(&dbLock);
        printf("Server: Mutex lock released.\n");

        close(file);

        return rc;
}

void* threadClient(void *clientArgs)
{
        struct args *data = (struct args *) clientArgs;
        SSL *ssl = data->ssl;
        int client = data->client;
        int tnum = data->tnum;
        char client_addr[INET_ADDRSTRLEN];

        strcpy(client_addr, data->client_addr);

        

        char buffer[BUFFER_SIZE],
            command[BUFFER_SIZE];
        do
        {
          printf("Server: Listening...\n");
          // This is where the server actually does the work receiving and sending messages
          bzero(buffer, BUFFER_SIZE);
          int nbytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);

          sscanf(buffer, "%s", command);
          if (strcmp(command, "exit") == 0)
          {
            break;
          }

          char operation[BUFFER_SIZE];
          char term[BUFFER_SIZE];

          sscanf(buffer, "%s %s", operation, term);

          if (nbytes_read < 0)
            fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
          else
            printf("Server: Command received from client: %s %s\n", operation, term);

          performOperation(operation, term);

          // start sending results file back
          char filename[25];
          if (strcmp(operation, "display") == 0)
            sendFile("data", ssl);
          else
            sendFile("results", ssl);

        } while (true);

        // Terminate the SSL session, close the TCP connection, and clean up
        printf("Server: Terminating SSL session and TCP connection with client (%s)\n",
               client_addr);
        SSL_free(ssl);
        close(client);
        pthread_join(threadIDs[tnum], NULL);
}

/******************************************************************************

The main program will perform as a server for sqlite3 database queries over an
ssl connection with clients. Backup daemon is configured upon startup to make a
.bak file for the sqlite3 db.

******************************************************************************/

int main(int argc, char **argv)
{
  SSL_CTX       *ssl_ctx;
  unsigned int  sockfd;
  unsigned int  port;
  int           thread = 0;
  char          buffer[BUFFER_SIZE],
                inputStr[BUFFER_SIZE];
  int           inputInt,
                inputLen;
  bool          inputLoop = true,
                validInt = true;
  pthread_t     threadID;

  //Prompt user for custom backup frequency, or continue with default (60 second)
  printf("Server: Initializing ... \n");
  while(inputLoop){

    //Get input as string
    printf("Server: Enter backup frequency in seconds (or 0 to use default setting): ");
    fgets(inputStr, sizeof(inputStr), stdin);
    inputLen = strlen(inputStr) - 1;

    //Parse string for all integer values
    for(int i = 0; i < inputLen; i++){
        if(!isdigit(inputStr[i])){
            validInt = false;
            break;
        }
    }

    //Store value if its an integer, else back to start of loop
    if(validInt){
        inputInt = atoi(inputStr);
    }else{
        printf("Server: ERROR! Unable to parse backup frequency.\n");
        printf("Server: Input must be an integer number.\n");
        validInt = true;
        continue;
    }

    //Check for negative numbers. Display error and return to start of loop
    if(inputInt < 0){
        printf("Server: ERROR! Unable to parse backup frequency.\n");
        printf("Server: Input must be a non-negative number.\n");
        continue;
    }

    //-- At this point the input is successful --
    if(inputInt == 0){    //Zero input = use default
        printf("Server: Success! Backup time configured to default setting (%d seconds).\n", backupTime);
    }else{   //Non zero input use the user's input
        backupTime = inputInt;
        printf("Server: Success! Backup time configured (%d seconds).\n", backupTime);
    }
    inputLoop = false;
  }

  //Create Backup Daemon thread using backup frequency
  pthread_create(&threadID, NULL, backup, &backupTime);

  // Initialize and create SSL data structures and algorithms
  init_openssl();
  ssl_ctx = create_new_context();
  configure_context(ssl_ctx);

  // Port can be specified on the command line. If it's not, use default port
  switch (argc)
  {
  case 1:
    port = DEFAULT_PORT;
    break;
  case 2:
    port = atoi(argv[1]);
    break;
  default:
    fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
    exit(EXIT_FAILURE);
  }


  // This will create a network socket and return a socket descriptor, which is
  // and works just like a file descriptor, but for network communcations. Note
  // we have to specify which TCP/UDP port on which we are communicating as an
  // argument to our user-defined create_socket() function.
  sockfd = create_socket(port);

  while (true)
  {
    // Wait for incoming connections and handle them as the arrive

    SSL *ssl;
    int client;
    int readfd;
    int rcount;
    const char reply[] = "Hello World!";
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    char client_addr[INET_ADDRSTRLEN];

    // Once an incoming connection arrives, accept it.  If this is successful,
    // we now have a connection between client and server and can communicate
    // using the socket descriptor

    client = accept(sockfd, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
        fprintf(stderr, "Server: Unable to accept connection: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Display the IPv4 network address of the connected client
    inet_ntop(AF_INET, (struct in_addr *)&addr.sin_addr, client_addr,
              INET_ADDRSTRLEN);
    printf("Server: Established TCP connection with client (%s) on port %u\n",
           client_addr, port);

    // Here we are creating a new SSL object to bind to the socket descriptor
    ssl = SSL_new(ssl_ctx);

    // Bind the SSL object to the network socket descriptor. The socket
    // descriptor will be used by OpenSSL to communicate with a client. This
    // function should only be called once the TCP connection is established.
    SSL_set_fd(ssl, client);

    // The last step in establishing a secure connection is calling SSL_accept(),
    // which executes the SSL/TLS handshake.  Because network sockets are
    // blocking by default, this function will block as well until the handshake
    // is complete.
    if (SSL_accept(ssl) <= 0)
    {
        fprintf(stderr, "Server: Could not establish secure connection:\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        struct args *clientArgs = (struct args*) malloc (sizeof(struct args));
        printf("Server: Established SSL/TLS connection with client (%s)\n",
               client_addr);
        
        clientArgs->client = client;
        clientArgs->client_addr = client_addr;
        clientArgs->ssl = ssl;
        if (thread == 10) {
          thread = 0;
        }
        clientArgs->tnum = thread;
        pthread_create(&threadIDs[thread], NULL, threadClient, clientArgs);
        thread++;

    }
  }

/*   while (true)
  {
  // Wait for incoming connections and handle them as the arrive

    SSL *ssl;
    int client;
    int readfd;
    int rcount;
    const char reply[] = "Hello World!";
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    char client_addr[INET_ADDRSTRLEN];

    // Once an incoming connection arrives, accept it.  If this is successful,
    // we now have a connection between client and server and can communicate
    // using the socket descriptor

    client = accept(sockfd, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
      fprintf(stderr, "Server: Unable to accept connection: %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    // Display the IPv4 network address of the connected client
    inet_ntop(AF_INET, (struct in_addr *)&addr.sin_addr, client_addr,
              INET_ADDRSTRLEN);
    printf("Server: Established TCP connection with client (%s) on port %u\n",
           client_addr, port);

    // Here we are creating a new SSL object to bind to the socket descriptor
    ssl = SSL_new(ssl_ctx);

    // Bind the SSL object to the network socket descriptor. The socket
    // descriptor will be used by OpenSSL to communicate with a client. This
    // function should only be called once the TCP connection is established.
    SSL_set_fd(ssl, client);

    // The last step in establishing a secure connection is calling SSL_accept(),
    // which executes the SSL/TLS handshake.  Because network sockets are
    // blocking by default, this function will block as well until the handshake
    // is complete.
    if (SSL_accept(ssl) <= 0)
    {
      fprintf(stderr, "Server: Could not establish secure connection:\n");
      ERR_print_errors_fp(stderr);
    }
    else
    {
      printf("Server: Established SSL/TLS connection with client (%s)\n",
             client_addr);

      int exit = -1;
      char command[BUFFER_SIZE];
      do
      {
        printf("Server: Listening...\n");
        // This is where the server actually does the work receiving and sending messages
        bzero(buffer, BUFFER_SIZE);
        int nbytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);

        sscanf(buffer, "%s", command);
        if (strcmp(command, "exit") == 0)
        {
            break;
        }

        char operation[BUFFER_SIZE];
        char term[BUFFER_SIZE];

        sscanf(buffer, "%s %s", operation, term);

        if (nbytes_read < 0)
          fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
        else
          printf("Server: Command received from client: %s %s\n", operation, term);

        performOperation(operation, term);
        
        // start sending results file back
        char filename[25];
        if (strcmp(operation, "display") == 0)
          sendFile("data", ssl);
        else
          sendFile("results", ssl);
        
      } while (true);


      // Terminate the SSL session, close the TCP connection, and clean up
      printf("Server: Terminating SSL session and TCP connection with client (%s)\n",
             client_addr);
      SSL_free(ssl);
      close(client);

    }

  } */
    printf("Server: Listening...\n");
    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);
    //Block and wait for Backup Daemon to complete and join
    pthread_join(threadID, NULL);
    return EXIT_SUCCESS;
}
