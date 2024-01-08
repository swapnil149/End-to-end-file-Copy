#ifndef FILESERVER_H
#define FILESERVER_H

#include "c150nastyfile.h"       
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <dirent.h>
#include <iomanip>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <unordered_map> 

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

void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkInputArguments(int argc, char* argv[]);
void createTargetDirectory(const char* directory_name);
bool isFile(string fname, const char* target_directory_name);
void addTmpSuffix(const char* directory_name); // TODO: Remove this function for Pt. II
string removeTmpSuffix(string target_directory_name, string ack_filename);
string deleteFile(string target_directory_name, string ack_filename);
packetCheckWriteInfo parseClientMessage(string incoming_message, char* read_message);
void initFileAsTmp(packetCheckWriteInfo filechunk, int file_nastiness, const char* directory_name, unordered_map<string, int> *file_writes);
void writeToFile(NASTYFILE &curr_file, packetCheckWriteInfo filechunk, int file_nastiness, const char* target_dir_name, unordered_map<string, int> *file_writes);
void handleFileChunk(C150DgmSocket *sock, packetCheckWriteInfo filechunk, int file_nastiness, const char* target_dir_name, unordered_map<string, int> *file_writes, unordered_map<string, NASTYFILE*> *opened_files);
void handleFileMessage(C150DgmSocket *sock, string incoming, int file_nastiness, const char* target_directory_name, unordered_map<string, NASTYFILE*> * opened_files);
void computeFileSHA(unsigned char* sha_buf, string curr_filename, int file_nastiness, const char* target_dir, unordered_map<string, NASTYFILE*> * opened_files, long filesize);
void computeChunkSHA(unsigned char* sha_buf, packetCheckWriteInfo filechunk);
void sendSHAAndReceiveACK(unsigned char* sha_buf, size_t sha_buf_size, C150DgmSocket *sock, string filename, 
                            packetCheckWriteInfo filechunk, bool end_of_file, char* client_return, 
                            size_t client_return_size, int file_nastiness, const char* target_dir_name, 
                            unordered_map<string, NASTYFILE*> * opened_files);
int fileIsValid(string &ack_message, string &ack, string &filename);

void computeSHA(unsigned char *sha_buf, string filename_with_path, int packet_index, int chunk_size, int file_nastiness);



#endif
