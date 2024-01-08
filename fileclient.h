#ifndef FILECLIENT_H
#define FILECLIENT_H

#include "c150nastyfile.h"
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <dirent.h>
#include <iomanip>
#include <sys/stat.h>    // for file stats
#include <openssl/sha.h> // for SHA-1 hashing
#include <cerrno>
#include <stdio.h>
#include <cmath>

using namespace C150NETWORK;  // for all the comp150 utilities


// Constants
const int MAX_RETRIES = 5;
const int TIMEOUT_SECONDS = 30;
const int FILE_DATA_CHUNK_SIZE = 256;

// Define the packet struct
struct packetCheckWriteInfo
{
    char filename[240];              // Filename
    int packet_index;                 // Packet index
    int total_packets;                // Total packets
    long file_size;
    char data[FILE_DATA_CHUNK_SIZE]; // Data
};

// forward declarations 
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkInputArguments(int argc, char *argv[]);
void readResponseFromTheServer(C150DgmSocket *sock, ssize_t readlen, string &incoming_message, char *argv[]);
void checkAndPrintMessage(C150DgmSocket *sock, DIR *SRC, string &ack_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed, int retry_attempt);
void computeFileSHA(unsigned char* sha_buf, int file_nastiness, string filepath);
void computeChunkSHA(unsigned char* sha_buf, packetCheckWriteInfo filechunk);
string extractFileNameFromMessage(const string &message);
string extractServerHashFromMessage(const string &message);
int extractPacketIndexFromMessage(const string &message);
void sendAckToServer(C150DgmSocket *sock, const string &filename, bool hash_matches, char *argv[]);
void sendFileChunkToServer(C150DgmSocket *sock, packetCheckWriteInfo packetData, char *argv[]);
packetCheckWriteInfo createPacketData(string file_path, const string &filename, int packetIndex, int totalPackets, int packetSize, int file_nastiness, long totalFileSize);
long getFileSize(const string &filePath, int file_nastiness);
vector<string> parseServerResponse(string &server_response);
string calculateFurtherResponse(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack);
string sendWholeFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed);
string sendpacketIndexToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed);
string readAckFromServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed);
void retrySendingAckAndFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed, bool hash_matches);
void retrySendingFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed);

#endif