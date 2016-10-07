# MSQuery
UT2004 Master Server Query, in Python 2.7.  
Written by CVSoft, licensed under GPLv3.

## Prerequisites
MSQuery *REQUIRES* a valid UT2004 CD key. Place this in a text file containing just the CD key; the default location is `keys.txt`. You can specify the file location when creating a MSConnection object. Please do not hard-code UT2004 CD keys. 

## Using MSQuery
First, create a MSConnection object; this will prepare a connection to the UT2004 master server (it won't connect just yet). To get a list of servers, use the `query_servers(query type, keyword)` method.  
```with MSConnection() as ms:
    for server in ms.query_servers("gametype", "xDeathMatch"):
        print server.ip + ':' + str(server.port)
```
When using a MSConnection object directly (using the socket methods instead of query methods), remember that you must call `MSConnection.authenticate()` first; this method will both open a connection to the master server and handle authentication for you. After authenticating, you can send a single query to the master server -- after every query, the master server closes the connection. The query methods will reopen the connection if you use the same object, so you don't need to manually reopen the connection after every query. 

An error handling system is provided to gracefully handle issues that may arise. I don't feel it is complete within MSQuery itself, but if you implement MSQuery in your project, you can check the status of the MSQuery object with the `MSConnection.check_error()` method. Error constants are provided at the top of the source code, the're hard to miss.

### MSServer objects
MSServer objects are simple storage classes for all data returned by the master server for a single UT2004 game server. These are:
- `MSServer.ip`: string containing server's IP address
- `MSServer.port`: int containing game port
- `MSServer.query_port`: int containing query port (pretty much always port+1)
- `MSServer.cur_players`: int containing number of online players
- `MSServer.max_players`: int containing maximum number of players allowed on the server
- `MSServer.name`: string containing server's (partial) name -- it appears the master server does not transmit the entire name?
- `MSServer.map_name`: string containing server's (again, partial) map name
- `MSServer.flags`: dictionary containing server configuration flags
- `MSServer.filters`: dictionary containing server filter flags -- this is not quite documented, only one filter flag bit is known. 
- `MSServer.param_f`: int containing leftover data from first 4 bytes of data footer (data after map_name)
- `MSServer.param_g`: int containing leftover data from bytes 4 through 7 of data footer
- `MSServer.param_h`: int containing leftover data from bytes 8 through 11 of data footer
