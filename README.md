# Bare Chat

## Introduction
This is a simple command-line based peer-to-peer (P2P) chat service written in C in about 10 hours (this is reflected in the quality atm).

## Prerequisites
Before you can compile and run the P2P chat service, ensure you atleast have the following prerequisites installed on your system:

- C Compiler (e.g., gcc)
- Make

Note that you will also need to host the server on a machine that is accessible to all clients. This can be done by hosting the server on a public IP address or otherwise if you are technically inclined. This is because the p2p chat is based on all clients joining a server and finding eachother from there. (Kinda ass I know but it's not finished and privacy will be improved).

## Compilation

To compile the server, use the following command:

```bash
make server
```

To compile the client, use the following command:

```bash
make client
```

## Configuration
To use the server or client, there is a .env.example file. Here you can define how many threads you want to use etc. You will also need to configure the server port here and I'm thinking it might be a good idea to move the SERVER_KEY here in the future, I just need to be bothered...

# Usage

## Server
The server component is responsible for allowing discovery of eachothers ip-addresses and ports, to run the server simply write:

```bash
./server
```

When the server is running it should log all incoming messages and log info accordingly. 
## Client

The client component allows users to connect to the P2P chat network and communicate with other clients. To run a client, execute the following command:

```bash
./client
```

Once you have the client up and running, you will see a menu of commands. The thought is to do the following, although I have no checks so if you don't I don't really know what happens hehehe...

```
# Set username
setname <username>

# Connect to the server
join <ip:port>

# Get list of users on the server
info

# Connect to a user (you can send a message without connecting, but connect basically adds them to your address book)
connect <ip:port>

# Send a message to a user
send <ip:port> <message>

# Or if you have connected to a user, you can just do
send <username> <message>

# Disconnect from a user
disconnect <ip:port>

# Leave the server
leave

# Exit the client
quit
```

## Contributing
My code in this project is shit, but bare in mind at this date (29.10.2023), I have only used 2 days on this project and it's probably a project I'll never fully finish. If you dare look at the spaghetti barf excuse I have called "code", please make changes and I will review them.

## License
This project is licensed under the GPL-3 License - see the LICENSE file for details
