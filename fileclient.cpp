// ------------------------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Authors: Swapnil Gupta and Mallory Grider
//
//
//        Sends all files within source directory to user-inputted server
//
//
//        COMMAND LINE
//
//              fileclient <server> <networknastiness> <filenastiness> <srcdir>
//
//
//        OPERATION
//
//         Perform the following steps for each file:
//          1. Send the file name to the server.
//          2. Calculate the SHA-1 hash for the file.
//          3. Wait for the server to respond with its computed SHA-1 hash.
//          4. Retry sending if a timeout occurs.

#include "fileclient.h"

using namespace std;         // for C++ std library
using namespace C150NETWORK; // for all the comp150 utilities

int main(int argc, char *argv[])
{
    // Initial variable declarations
    int network_nastiness = atoi(argv[2]); // Convert command line strings to integers
    int file_nastiness = atoi(argv[3]);
    DIR *SRC; // Unix descriptor for open directory
    SRC = opendir(argv[4]);        // amount of data read from socket
    string incoming_message = ""; // received message data for filecopy
    int retry_for_packets = 0;
    int retry_for_ack = 0;

    // GRADEME(argc, argv);                                  // Necessary for grade logging
    setUpDebugLogging("fileclientdebug.txt", argc, argv); // Set up debug message logging
    checkInputArguments(argc, argv);                      // Verify that input is in the correct format

    try
    {
        // Create the socket
        c150debug->printf(C150APPLICATION, "Creating C150DgmSocket");
        C150DgmSocket *sock = new C150NastyDgmSocket(network_nastiness);
        // Tell the DGMSocket which server to talk to
        sock->setServerName(argv[1]);
        // Set a timeout for the socket operations.
        sock->turnOnTimeouts(TIMEOUT_SECONDS);
        struct dirent *source_file; // Declare a variable for directory entries

        // Loop through all files in the source directory
        while ((source_file = readdir(SRC)) != NULL)
        {
            // Skip the universal . and .. in every directory
            if ((strcmp(source_file->d_name, ".") == 0) || (strcmp(source_file->d_name, "..") == 0))
            {
                continue;
            }
            string filename = source_file->d_name;
            string file_path = argv[4] + filename;
            long total_file_size = getFileSize(file_path, file_nastiness);             /* Size of the file in bytes */
            int total_packets = (total_file_size + FILE_DATA_CHUNK_SIZE - 1) / FILE_DATA_CHUNK_SIZE; // Track total packets sent for each file
            vector<string>parsed;
            parsed.push_back("");
            parsed.push_back("0");
            parsed.push_back(to_string(total_packets));
            parsed.push_back(filename);
            // define parse like push things inside it
            sendWholeFileToServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
        }
        closedir(SRC);
        // Close the socket after processing all files
        delete sock;
    }
    catch (C150NetworkException &e)
    {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG, "Caught C150NetworkException: %s\n", e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////
////                                                                 ////
////                        Helper functions                         ////
////                                                                 ////
/////////////////////////////////////////////////////////////////////////

// Send message to server confirming that SHA sums for the file on either disk
// are identical (or deny if the SHA sums differ)
void sendAckToServer(C150DgmSocket *sock, const string &filename, bool hash_matches, char *argv[])
{
    if (hash_matches)
    {
        cout << "File " << filename << " end-to-end check SUCCEEDS -- informing server" << endl;
    }
    else
    {
        cout << "File " << filename << " end-to-end check FAILS -- retrying" << endl;
    }
    string ackMessage = hash_matches ? "CONFIRM%" + filename : "DENY%" + filename;
    c150debug->printf(C150APPLICATION, "%s: Sending ACK message: \"%s\"", argv[0], ackMessage.c_str());
    sock->write(ackMessage.c_str(), ackMessage.length());
}

// Get the filename sent back from the server with SHA sum
string extractFileNameFromMessage(const string &message)
{
    // Look for delimiter
    size_t delimiterPos = message.find('*');
    if (delimiterPos != string::npos)
    {
        return message.substr(delimiterPos + 1);
    }
    return "";
}

// Get the SHA sum computed by the server
string extractServerHashFromMessage(const string &message)
{
    size_t delimiterPos = message.find('%');
    if (delimiterPos != string::npos)
    {
        return message.substr(0, delimiterPos);
    }
    return ""; 
}

// Get the SHA sum computed by the server
int extractPacketIndexFromMessage(const string &str)
{
    size_t percent_pos = str.find('%');
    size_t colon_pos = str.find(':');
    // Ensure both delimiters are found and '%' comes before ':'
    if (percent_pos != string::npos && colon_pos != string::npos && percent_pos < colon_pos) {
        string res = str.substr(percent_pos + 1, colon_pos - percent_pos - 1); 
        int ans = res.length() ? stoi(res) : 0;  
        return ans;  
    }
    return 0;
}

// Read checksum from server-side
void readResponseFromTheServer(C150DgmSocket *sock, ssize_t readlen, string &incoming_message, char *argv[])
{
    c150debug->printf(C150APPLICATION, "%s: Returned from write, doing read()", argv[0]);
    char buffer[512]; // Maximum expected message size

    // Read the response from the server into the buffer
    readlen = sock->read(buffer, sizeof(buffer));

    if (readlen <= 0)
    {
        incoming_message.clear(); // Handle errors or end of stream
    }
    else
    {
        incoming_message.assign(buffer, readlen); // Copy the data from the buffer into the string
    }

    c150debug->printf(C150APPLICATION, "%s: Received message from server: \"%s\"", argv[0], incoming_message.c_str());
}

// Initialize debugging logs
void setUpDebugLogging(const char *logname, int argc, char *argv[])
{
    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    //  Put the program name and a timestamp on each line of the debug log.
    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp();

    // Ask to receive all classes of debug message
    c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC | C150NETWORKDELIVERY);

    // We set a debug output indent in the server only, not the client.
    // That way, if we run both programs and merge the logs this way:
    c150debug->setIndent("    ");
}

// Receive and log result of final exchange with the server
void checkAndPrintMessage(C150DgmSocket *sock, DIR *SRC, string &ack_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed, int retry_attempt)
{
    // Except in case of timeouts, we're not expecting a zero length read
    if (!ack_message.length())
    {
        throw C150NetworkException("Unexpected zero length read in client");
    }

    size_t delimiter = ack_message.find("%");
    if (delimiter != std::string::npos)
    {
        string ack = ack_message.substr(0, delimiter);
        string filename = ack_message.substr(delimiter + 1);
        // Echo the response on the console
        if (ack == "RENAMED")
        {
            c150debug->printf(C150APPLICATION, "PRINTING RESPONSE: Renamed  \"%s\"\n", filename.c_str());
            *GRADING << "File: " << filename << " end-to-end check succeeded, attempt " << retry_attempt << endl;
        }
        else if ("DELETED")
        {
            c150debug->printf(C150APPLICATION, "PRINTING RESPONSE: Deleted  \"%s\"\n", filename.c_str());
            *GRADING << "File: " << filename << " end-to-end check failed, attempt " << retry_attempt << endl;
            retrySendingFileToServer(sock, SRC, ack_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
        }
        else
        {
            c150debug->printf(C150APPLICATION, "PRINTING RESPONSE: Error  \"%s\"\n", filename.c_str());
            *GRADING << "File: " << filename << " end-to-end check error, attempt " << retry_attempt << endl;
        }
    }
}

// Sanitize and parse user input from the command line
void checkInputArguments(int argc, char *argv[])
{
    // Check command line and parse arguments
    if (argc != 5)
    {
        fprintf(stderr, "Correct syntxt is: %s <serverName> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
        exit(4);
    }
    // Verify that both network nastiness and file nastiness are legitimate numeric values
    if (strspn(argv[2], "0123456789") != strlen(argv[2]))
    {
        fprintf(stderr, "Network nastiness %s is not numeric\n", argv[2]);
        fprintf(stderr, "Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(4);
    }
    if (strspn(argv[3], "0123456789") != strlen(argv[3]))
    {
        fprintf(stderr, "File nastiness %s is not numeric\n", argv[3]);
        fprintf(stderr, "Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(4);
    }
}

// Retrieve the size of a file given its path
long getFileSize(const string &file_path, int file_nastiness)
{
    NASTYFILE curr_file(file_nastiness);
    // Attempt to open the file in read-only binary mode
    void * fopenretval = curr_file.fopen(file_path.c_str(), "rb");

    // Check if the file was successfully opened
    if (fopenretval == NULL) {
        cerr << "Error opening file in source directory: " << file_path
            << " errono= " << strerror(errno) << endl;
        exit(16);

    }

    // Set file ptr to end of the file to retrieve size
    curr_file.fseek(0, SEEK_END);
    long file_size = curr_file.ftell();

    if (curr_file.fclose() != 0) {
        cerr << "Error closing file " << file_path << " errono= " 
            << strerror(errno) << endl;
        exit(16);
    }
    // Return the size of the file in bytes
    return file_size;
}
// Create packet data for a specific packet
packetCheckWriteInfo createPacketData(string file_path, const string &filename, 
                                        int packet_index, int total_packets, int packet_size, 
                                        int file_nastiness, long total_file_size)
{
    packetCheckWriteInfo packet;
    strncpy(packet.filename, filename.c_str(), sizeof(packet.filename));
    packet.packet_index = packet_index;
    packet.total_packets = total_packets;
    packet.file_size = total_file_size;
    NASTYFILE file(file_nastiness);
    
    // Open and read the file to obtain packet data
    void *fopenretval = file.fopen(file_path.c_str(), "rb");
    if (fopenretval == NULL) { 
        cerr << "Error opening file in source directory: " << filename
            << " errono= " << strerror(errno) << endl;
        exit(16);
    }


    if (packet_index == total_packets-1) {
        int remaining_bytes = total_file_size - (packet_index * FILE_DATA_CHUNK_SIZE);
        size_t offset = total_file_size - remaining_bytes; 
        file.fseek(offset, SEEK_SET);
        int len = file.fread(packet.data, 1, packet_size);
        if (len != packet_size) {
            cerr << "Error reading file " << filename << " while creating packet no. " << packet_index << endl;
            exit(16);
        }

        // Close the file
        file.fclose();

        return packet;
    }


    // Seek to the appropriate position in the file based on packet_index
    file.fseek(packet_index * packet_size, SEEK_SET); 

    // Read the packet data from the file
    int len = file.fread(packet.data, 1, packet_size);
    if (len != packet_size) {
        cerr << "Error reading file " << filename << " while creating packet no. " << packet_index << endl;
        exit(16);
    }

    // Close the file and return packet
    file.fclose();
    return packet;
}

// Send a packet of file data to the server
void sendFileChunkToServer(C150DgmSocket *sock, packetCheckWriteInfo packet_data, char *argv[])
{
    // Create a buffer to hold the entire packet
    char packet_buffer[sizeof(packet_data)];

    // Copy the data from the packet_data struct into the buffer
    memcpy(packet_buffer, &packet_data, sizeof(packet_data));

    // Send the entire packet to the server
    c150debug->printf(C150APPLICATION, "%s: Writing packet data for file: \"%s\", packet index: %d, packet count: %d, file size: %lu, packet data: %s", 
                      argv[0], packet_data.filename, packet_data.packet_index, packet_data.total_packets, packet_data.file_size, packet_data.data);
    sock->write(packet_buffer, sizeof(packet_buffer));
}

// Calculate the size of a data packet based on its index, the total number of packets, and the total file size
int getPacketSize(int packet_index, int total_packets, long total_file_size)
{
    int packet_size = FILE_DATA_CHUNK_SIZE; // Use the default packet size

      // Check if the packet is the last one
    if (packet_index == total_packets-1) 
    {
        // Calculate the remaining bytes in the file
        int remaining_bytes = total_file_size - (packet_index * FILE_DATA_CHUNK_SIZE);
        // If there are remaining bytes, set the packet size to the remaining bytes
        if (remaining_bytes > 0)
        {
            packet_size = remaining_bytes;
        }
    }
    return packet_size;
}

// Read acknowledgment messages from the server and handle them.
string readAckFromServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed) {
    // Check and print acknowledgment message, handle retries (0 is the initial retry attempt).
    checkAndPrintMessage(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed, 0);

    // Return "break" to indicate the completion of acknowledgment processing.
    return "break";
}

//Send a data packet or file hash verification to the server.
string sendpacketIndexToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed) {
    // Extract server hash or calculate it based on the incoming message
    string server_hash = parsed[0].length() ? parsed[0] : extractServerHashFromMessage(incoming_message);
    
    // Extract the packet index from the incoming message
    int packet_index_from_server = extractPacketIndexFromMessage(incoming_message);
    
    // Construct the file path
    string file_path = argv[4] + parsed[3];
    
    // Initialize a buffer to store the SHA-1 hash
    unsigned char sha_buf[20];
    
    // Initialize a flag to track whether the hash is for the entire file
    bool is_file_hash = false;
    
    // Get the total size of the file
    long total_file_size = getFileSize(file_path, file_nastiness);
    
    // Calculate the total number of packets for the file
    int total_packets = (total_file_size + FILE_DATA_CHUNK_SIZE - 1) / FILE_DATA_CHUNK_SIZE;
    
    // Calculate the packet size
    int packet_size = getPacketSize(packet_index_from_server, total_packets, total_file_size);
   
    // Check if the packet index indicates a file hash
    if (packet_index_from_server == -1) {
        computeFileSHA(sha_buf, file_nastiness, file_path);
        is_file_hash = true; 
    } else {
        packetCheckWriteInfo filechunk = createPacketData(file_path, parsed[3], packet_index_from_server, total_packets, packet_size, file_nastiness, total_file_size);
        computeChunkSHA(sha_buf, filechunk); 
    }    

    // Convert the computed SHA from client disk to a string
    ostringstream oss;
    for (int i = 0; i < 20; i++) {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(sha_buf[i]);
    }

    // Compare the client's hash with the server's hash
    bool hash_matches = oss.str() == server_hash;
    
    if (!hash_matches && !is_file_hash) {
        return "continue"; // Resend the particular packet that failed SHA check
    }

    if (is_file_hash) {
        retrySendingAckAndFileToServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed, hash_matches);
    }
    
    return "break"; // Packet SHA on either side matches, send the next packet
}

//Send an entire file to the server in 256-byte chunks and perform error handling.
string sendWholeFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed) {
    // Extract filename from parsed data
    string filename = parsed[3];
    
    // Construct the full file path
    string file_path = argv[4] + filename;
    
    // Get the total size of the file
    long total_file_size = getFileSize(file_path, file_nastiness);
    
    // Calculate the total number of packets for the file
    int total_packets = (total_file_size + FILE_DATA_CHUNK_SIZE - 1) / FILE_DATA_CHUNK_SIZE;
    
    if (total_packets > 0) {
        // Loop through all packets of the file
        for (int packet_index = 0; packet_index < total_packets; packet_index++) {
            int packet_size = getPacketSize(packet_index, total_packets, total_file_size);
            
            // Create a packet of file data
            packetCheckWriteInfo packet_data = createPacketData(file_path, filename, packet_index, total_packets, packet_size, file_nastiness, total_file_size);
            
            // Send the packet to the server with retry attempts
            for (retry_for_packets = 0; retry_for_packets < MAX_RETRIES; retry_for_packets++) {
                // Log and send the packet
                c150debug->printf(C150APPLICATION, "%s: Sending filename %s, retry attempt %d",
                                  argv[0], filename.c_str(), retry_for_packets);
                *GRADING << "File: " << filename << ", beginning transmission, attempt " << retry_for_packets << endl;
                sendFileChunkToServer(sock, packet_data, argv);
                *GRADING << "File: " << filename
                         << " transmission complete, waiting for end-to-end check, attempt " << retry_for_packets << endl;
                
                ssize_t readlen = 0;
                incoming_message = "";

                // Wait for the server to respond with its computed SHA-1 hash
                readResponseFromTheServer(sock, readlen, incoming_message, argv);

                // Check if the read operation timed out while waiting for the server to respond
                if (!sock->timedout()) {
                    // Calculate further response and continue or break based on the result
                    string res = calculateFurtherResponse(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack);
                    if (res == "continue") {
                        continue;
                    } else if (res == "break") {
                        break;
                    }
                }
            }
            
            if (retry_for_packets == MAX_RETRIES) {
                // Maximum retries reached, log an error message, and exit
                *GRADING << "File: " << filename
                        << " transmission failed. Network issues, maximum retries reached" << endl;
                fprintf(stderr, "Network issues: Maximum retries reached.\n");
                closedir(SRC);
                // Close the socket after processing all files
                delete sock;
                exit(4);
            }
        }
        
        int retry_for_fileSHA = 0;
        
        // Retry to receive the server's computed SHA-1 hash
        for (retry_for_fileSHA = 0; retry_for_fileSHA < MAX_RETRIES; retry_for_fileSHA++) {
            ssize_t readlen = 0;
            incoming_message = "";

            // Wait for the server to respond with its computed SHA-1 hash
            readResponseFromTheServer(sock, readlen, incoming_message, argv);

            // Check if the read operation timed out while waiting for the server to respond
            if (!sock->timedout()) {
                // Calculate further response and continue or break based on the result
                string res = calculateFurtherResponse(sock, SRC, incoming_message, argv, file_nastiness, retry_for_fileSHA, retry_for_ack);
                if (res == "continue") {
                    continue;
                } else if (res == "break") {
                    break;
                }
            }
        }
        
        if (retry_for_fileSHA == MAX_RETRIES) {
            // Maximum retries reached for file SHA retrieval, log an error message, and exit
            *GRADING << "File: " << filename
                    << " transmission failed. Network issues, maximum retries reached" << endl;
            fprintf(stderr, "Network issues: Maximum retries reached.\n");
            closedir(SRC);
            // Close the socket after processing all files
            delete sock;
            exit(4);
        }
    }
    
    return "";
}

//Calculate the further response based on the incoming message from the server and take appropriate actions
string calculateFurtherResponse(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack) {
    vector<string> parsed = parseServerResponse(incoming_message);

    // Check if the message is about the total end-to-end file check, not just for one packet
    string res = "";
    if ((parsed[1] == "-1") && (parsed[2] == "-1")) {
        if (parsed[0] == "RENAMED" || parsed[0] == "DELETED" || parsed[0] == "ERROR") {
            // Received final confirmation that the file was renamed, deleted, or an error occurred on the server-side
            res = readAckFromServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
            return res;
        }
        res = sendpacketIndexToServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
        return res;
    }

    // The message from the server concerns a particular packet. The index (parsed[1]) and total packet count (parsed[2]) should be real values
    res = sendpacketIndexToServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
    return res;
}

// Describing the structure of the `parsed` vector:
// parsed_values[0] is SHA or final confirmation ("RENAMED", "DELETED", or "ERROR").
// parsed_values[1] is packet_index, where this is -1 if the message is meant for a whole file.
// parsed_values[2] is the total packet count (again, -1 for a message meant about the totality of a file).
// parsed_values[3] is the filename.


//Parse a server response message to extract relevant information.
vector<string> parseServerResponse(string &server_response) {
    vector<string> parsed_values;
    size_t percent_pos = server_response.find('%');
    size_t colon_pos = server_response.find(':');
    size_t asterisk_pos = server_response.find('*');

    // Checking if the delimiters are found in the string and are in the correct order
    if (percent_pos != string::npos && colon_pos != string::npos &&
        asterisk_pos != string::npos && percent_pos < colon_pos && colon_pos < asterisk_pos) {
        
        parsed_values.push_back(server_response.substr(0, percent_pos));                               // SHA or final confirmation
        parsed_values.push_back(server_response.substr(percent_pos + 1, colon_pos - percent_pos - 1)); // packet index
        parsed_values.push_back(server_response.substr(colon_pos + 1, asterisk_pos - colon_pos - 1));  // total packet count
        parsed_values.push_back(server_response.substr(asterisk_pos + 1));                             // filename
    }
    return parsed_values;
}


//Compute the SHA-1 hash sum for the entire contents of a file.
void computeFileSHA(unsigned char* sha_buf, int file_nastiness, string filepath) {
    void* fopenretval;
    size_t len;
    size_t filesize;
    struct stat statbuf;
    char *buffer;  
    c150debug->printf(C150APPLICATION, "Computing SHA sum for the whole file\n");
    NASTYFILE input_file(file_nastiness);
    
    // do an fopen on the input file
    fopenretval = input_file.fopen(filepath.c_str(), "rb");  
    if (fopenretval == NULL) {
        cerr << "Error opening input file " << filepath << " errno=" << strerror(errno) << endl;
        exit(16);
    }

    // Read the whole input file 
    if (lstat(filepath.c_str(), &statbuf) != 0) {
        fprintf(stderr, "computeFileSHA: Error stating supplied source file %s\n", filepath.c_str());
        exit(20);
    }
  
    // Make an input buffer large enough for the whole file
    filesize = statbuf.st_size;
    buffer = (char *)malloc(filesize);

    // Read the whole file
    len = input_file.fread(buffer, 1, filesize);
    if (len != filesize) {
      cerr << "Error reading file " << filepath << " errno=" << strerror(errno) << endl;
      exit(16);
    }
  
    if (input_file.fclose() != 0) {
      cerr << "Error closing input file " << filepath << " errno=" << strerror(errno) << endl;
      exit(16);
    }

    // Compute SHA sum
    SHA1((const unsigned char *)buffer, filesize, sha_buf);
    free(buffer);
}

//Compute the SHA-1 hash sum for a chunk of file data
void computeChunkSHA(unsigned char* sha_buf, packetCheckWriteInfo filechunk) {
    int filechunk_data_size = FILE_DATA_CHUNK_SIZE;
    if (filechunk.packet_index == (filechunk.total_packets - 1)) {
        filechunk_data_size = filechunk.file_size - (filechunk.packet_index * FILE_DATA_CHUNK_SIZE);
    }

    char *buffer; 
    buffer = (char *)malloc(filechunk_data_size);
    memcpy(buffer, filechunk.data, filechunk_data_size);

    // Compute SHA sum
    SHA1((const unsigned char *)buffer, filechunk_data_size, sha_buf);
    free(buffer);
}

//Retries the process of sending an acknowledgment and file data to the server and handles retries
void retrySendingAckAndFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed, bool hash_matches) {
    // Send an ACK to the server based on whether the hash matches
    for (retry_for_ack = 0; retry_for_ack < MAX_RETRIES; retry_for_ack++)
    {
        sendAckToServer(sock, parsed[3], hash_matches, argv);
        // Wait for the server to respond back that it has successfully modified its .TMP file
        ssize_t readlen = 0;
        incoming_message = "";
        readResponseFromTheServer(sock, readlen, incoming_message, argv);
        if (!sock->timedout())
        {
            string res = calculateFurtherResponse(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack);
            if(res == "continue"){
                continue;
            } else if(res == "break"){
                break;
            }
        }
    }
    if (retry_for_ack == MAX_RETRIES)
    {
        *GRADING << "File: " << parsed[3]
                 << " transmission failed. Network sucks, maximum retries reached" << endl;
        fprintf(stderr, "Network sucks: Maximum retries reached.\n");
        closedir(SRC);
        // Close the socket after processing all files
        delete sock;
        exit(4);
    }
}

//Retries the process of sending the entire file to the server and handles retries
void retrySendingFileToServer(C150DgmSocket *sock, DIR *SRC, string &incoming_message, char *argv[], int file_nastiness, int retry_for_packets, int retry_for_ack, vector<string>& parsed) 
{
    int retry_for_file = 0;
    for (retry_for_file = 0; retry_for_file < MAX_RETRIES; retry_for_file++)
    {
        sendWholeFileToServer(sock, SRC, incoming_message, argv, file_nastiness, retry_for_packets, retry_for_ack, parsed);
    }
    if (retry_for_file == MAX_RETRIES)
    {
        *GRADING << "File: " << parsed[3]
                 << " transmission failed. Network sucks, maximum retries reached" << endl;
        fprintf(stderr, "Network sucks: Maximum retries reached.\n");
        closedir(SRC);
        // Close the socket after processing all files
        delete sock;
        exit(4);
    }
}

