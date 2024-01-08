// ----------------------------------------------------------------------------------
//
//                        fileserver.cpp
//
//        Authors: Swapnil Gupta and Mallory Grider
//
//
//        Receives copied files from client and stores them in
//          the user-inputted target directory
//
//
//        COMMAND LINE
//
//              fileserver <networknastiness> <filenastiness> <targetdir>
//
//
//        OPERATION
//
//             1. Wait for files from client
//             2. For every file, determine if received packet is related to filechunk
//                  or final end-to-end check
//                  2a. If filechunk, compute its SHA and send it to client, 
//                        then write filechunk to file in /TARGET
//                  2b. If end-to-end check, send final SHA and 
//                        complete end-to-end acknoledgements
//
//
//       LIMITATIONS - NEEDSWORK
//
//              - Much of the control flow should be reworked. handleFileChunk(), 
//                  for instance, is a bit convoluted for what it is trying to 
//                  accomplish 
//
// ----------------------------------------------------------------------------------

#include "fileserver.h"

using namespace std;         // for C++ std library
using namespace C150NETWORK; // for all the comp150 utilities

int main(int argc, char *argv[])
{

    // Initial variable declarations
    int file_nastiness;
    int network_nastiness;
    ssize_t readlen;            // Amount of data read from socket
    char incoming_message[512]; // Received message data from client
    const char *target_directory_name = argv[3];
    string ack, ack_filename; // Variables used in final file renaming or deletion

    // Final message sent to client after renaming or deletion
    string final_confirmation = "ERROR";

    // TODO: Delete after done using this map so we avoid memory leaks
    unordered_map<string, int> *file_writes;
    unordered_map<string, NASTYFILE *> *opened_files;

    // Keep track of how many times we have written to a file
    file_writes = new unordered_map<string, int>();

    // Keep track of what files are already open
    opened_files = new unordered_map<string, NASTYFILE *>();

    GRADEME(argc, argv); //  Necessary for grade logs

    setUpDebugLogging("fileserverdebug.txt", argc, argv);
    checkInputArguments(argc, argv);                // Verify that input is in the correct format
    createTargetDirectory((target_directory_name)); // If target directory does not exist on server, create it

    network_nastiness = atoi(argv[1]); // Convert command line strings to integers
    file_nastiness = atoi(argv[2]);

    try
    {
        // Create the socket
        c150debug->printf(C150APPLICATION, "Creating C150NastyDgmSocket(nastiness=%d)",
                          network_nastiness);
        C150DgmSocket *sock = new C150NastyDgmSocket(network_nastiness); 
        c150debug->printf(C150APPLICATION, "Ready to accept messages");

        while (1)
        {
            // Initial read of any messages from the client
            readlen = sock->read(incoming_message, sizeof(incoming_message));
            string readIncomingMessage(incoming_message);
            if (readlen == 0)
            {
                c150debug->printf(C150APPLICATION, "Read zero length message, trying again");
                continue;
            }
            string incoming(incoming_message); // Convert to C++ string
            *GRADING << "File: " << incoming << " starting to receive file" << endl;
            c150debug->printf(C150APPLICATION, "Successfully read %d bytes. Message=\"%s\"",
                              readlen, incoming.c_str());

            // If packet int values in the struct are -1 then we know we have a message
            //      for the final end-to-end check
            packetCheckWriteInfo filechunk = parseClientMessage(incoming, incoming_message);
            bool is_filechunk(filechunk.packet_index != -1);

            if (is_filechunk)
            {
                handleFileChunk(sock, filechunk, file_nastiness, target_directory_name, file_writes, opened_files);
            }
            else
            {
                handleFileMessage(sock, incoming, file_nastiness, target_directory_name, opened_files);
            }
        }
    }

    catch (C150NetworkException &e)
    {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG, "Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }

    return 0;
}

void handleFileChunk(C150DgmSocket *sock, packetCheckWriteInfo filechunk, int file_nastiness, const char *target_dir_name, unordered_map<string, int> *file_writes, unordered_map<string, NASTYFILE *> *opened_files)
{
    while (1)
    {
        unsigned char sha_buf[20]; // Stores file chunk SHA sum
        int filechunk_data_size = FILE_DATA_CHUNK_SIZE;
        if (filechunk.packet_index == (filechunk.total_packets - 1))
        {
            filechunk_data_size = filechunk.file_size - (filechunk.packet_index * filechunk_data_size);
        }

        string curr_filename = string(target_dir_name) + string(filechunk.filename) + ".TMP";
        NASTYFILE *curr_file;

        // Check if the file is already opened, otherwise
        //  open the file and store NASTYFILE ptr in opened_files hash map
        if (opened_files->find(curr_filename) == opened_files->end())
        {
            curr_file = new NASTYFILE(file_nastiness);
            void *fopenretval = curr_file->fopen(curr_filename.c_str(), "wb+");
            if (fopenretval == NULL)
            {
                cerr << "Error opening file " << curr_filename
                     << " errono= " << strerror(errno) << endl;
            }
            (*opened_files)[curr_filename] = curr_file;
        }
        else
        {
            curr_file = (*opened_files)[curr_filename];
        }

        writeToFile(*curr_file, filechunk, file_nastiness, target_dir_name, file_writes);

        // We are at the end of the file to copy if the number of times we have written
        //  to the file is equivalent to the total number of file chunks expected for that file
        bool end_of_file((*file_writes)[string(filechunk.filename)] == filechunk.total_packets);

        // Compute SHA of just the data
        computeChunkSHA(sha_buf, filechunk);

        // Send SHA message back to the client
        size_t buf_size = sizeof(sha_buf) / sizeof(sha_buf[0]);
        char incoming_message[512];
        size_t incoming_size = sizeof(incoming_message);
        sendSHAAndReceiveACK(sha_buf, buf_size, sock, filechunk.filename, filechunk, end_of_file,
                             incoming_message, incoming_size, file_nastiness, target_dir_name, opened_files);
        string incoming(incoming_message);

        // Parse received message from client – dictates whether we are handling a packet
        //  related to further file copying or the final file end-to-end check
        packetCheckWriteInfo new_filechunk = parseClientMessage(incoming, incoming_message);
        bool is_filechunk(new_filechunk.packet_index != -1);

        if (is_filechunk)
        {
            filechunk = new_filechunk;
            continue; // Avoids recursive call to handleFileChunk
        }
        else
        {
            handleFileMessage(sock, incoming, file_nastiness, target_dir_name, opened_files);
        }

        return;
    }
}

// Write packet data to file in target directory
void writeToFile(NASTYFILE &curr_file, packetCheckWriteInfo filechunk, int file_nastiness, const char *target_dir_name, unordered_map<string, int> *file_writes)
{
    int filechunk_data_size = FILE_DATA_CHUNK_SIZE;

    // Calculate offset if the last packet's data does not fit perfectly
    //  into 256 bytes
    if (filechunk.packet_index == (filechunk.total_packets - 1))
    {
        filechunk_data_size = filechunk.file_size - (filechunk.packet_index * 256);
    }

    if (filechunk.packet_index == filechunk.total_packets - 1)
    {
        int remainingBytes = filechunk.file_size - (filechunk.packet_index * 256);
        size_t offset = filechunk.file_size - remainingBytes;
        curr_file.fseek(offset, SEEK_SET);
        int len = curr_file.fwrite(filechunk.data, 1, filechunk_data_size);

        if (len != filechunk_data_size)
        {
            cerr << "Error reading file " << filechunk.filename << " while creating packet no. " << filechunk.packet_index << endl;
        }

        // Increase count of how many times we have written to this file
        (*file_writes)[string(filechunk.filename)]++;

        return;
    }

    curr_file.fseek(filechunk.packet_index * filechunk_data_size, SEEK_SET);
    int len = curr_file.fwrite(filechunk.data, 1, filechunk_data_size);

    if (len != sizeof(filechunk.data))
    {
        cerr << "Error writing file " << filechunk.filename << " errono= " << strerror(errno) << endl;
    }

    // Increase count of how many times we have written to this file
    (*file_writes)[string(filechunk.filename)]++;

    return;
}

// If we receive a packet from client related to the final end-to-end check for a specific packet,
//  either we need to delete the file (if it fails the end-to-end check), or we need to remove
//  its .TMP suffix so we know it was correctly copied
void handleFileMessage(C150DgmSocket *sock, string incoming, int file_nastiness, const char *target_directory_name, unordered_map<string, NASTYFILE *> *opened_files)
{

    string final_confirmation;
    string ack, ack_filename;
    string file_wo_tmp;

    // Check whether the file should be renamed or deleted. If it's valid, rename without .TMP suffix.
    int accept_file = fileIsValid(incoming, ack, ack_filename);
    if (accept_file == 1)
    {
        final_confirmation = removeTmpSuffix(target_directory_name, ack_filename);
    }
    else if (accept_file == 0)
    {
        final_confirmation = deleteFile(target_directory_name, ack_filename);
    }

    // Close file, remove file from hash map
    NASTYFILE *curr_file;
    file_wo_tmp = ack_filename;

    ack_filename = ack_filename + ".TMP";

    // Check if the file is already opened, otherwise
    //  open the file and store NASTYFILE ptr in opened_files hash map
    if (opened_files->find(ack_filename) == opened_files->end())
    {
        cerr << "File not already opened after final rename/delete directive" << endl;
    }
    else
    {
        curr_file = (*opened_files)[ack_filename];
        curr_file->fclose();                         // Close file
        (*opened_files).erase(string(ack_filename)); // Remove file from hash map
    }

    string packet_index = "-1";
    string packet_count = "-1";
    final_confirmation = final_confirmation + "%" + packet_index + ":" + packet_count + "*" + file_wo_tmp;
    c150debug->printf(C150APPLICATION, "Writing final confirmation message=\"%s\"", final_confirmation.c_str());
    sock->write(final_confirmation.c_str(), final_confirmation.length() + 1);

    return;
}

/////////////////////////////////////////////////////////////////////////
////                                                                 ////
////               End-to-End Check helper functions                 ////
////                                                                 ////
/////////////////////////////////////////////////////////////////////////

void computeChunkSHA(unsigned char *sha_buf, packetCheckWriteInfo filechunk)
{

    int filechunk_data_size = 256; // TODO: make this a global constant
    if (filechunk.packet_index == (filechunk.total_packets - 1))
    {
        filechunk_data_size = filechunk.file_size - (filechunk.packet_index * 256);
    }

    char *buffer;
    buffer = (char *)malloc(filechunk_data_size);
    memcpy(buffer, filechunk.data, filechunk_data_size);

    // Compute SHA sum
    SHA1((const unsigned char *)buffer, filechunk_data_size, sha_buf);
    free(buffer);
}

void computeFileSHA(unsigned char *sha_buf, string curr_filename, int file_nastiness,
                    const char *target_dir, unordered_map<string, NASTYFILE *> *opened_files,
                    long filesize)
{
    size_t len;
    size_t len_extra;
    char *buffer;
    char overflow_byte;

    c150debug->printf(C150APPLICATION, "Computing SHA sum for the whole file\n");
    curr_filename = target_dir + curr_filename + ".TMP"; // Need to include the correct path from the server-side

    NASTYFILE *curr_file;

    // Check if the file is already opened, otherwise
    //  open the file and store NASTYFILE ptr in opened_files hash map
    if (opened_files->find(curr_filename) == opened_files->end())
    {
        curr_file = new NASTYFILE(file_nastiness);
        void *fopenretval = curr_file->fopen(curr_filename.c_str(), "rb+");
        if (fopenretval == NULL)
        {
            cerr << "Error opening file " << curr_filename
                 << " errono= " << strerror(errno) << endl;
        }
        (*opened_files)[curr_filename] = curr_file;
    }
    else
    {
        curr_file = (*opened_files)[curr_filename];
        if (curr_file->fclose() == 0)
        {
            cerr << "File " << curr_filename << " didn't close correctly" << endl;
        };
        curr_file = new NASTYFILE(file_nastiness);
        void *fopenretval = curr_file->fopen(curr_filename.c_str(), "rb+");
        if (fopenretval == NULL)
        {
            cerr << "Error opening file second time " << curr_filename
                 << " errono= " << strerror(errno) << endl;
        }
        (*opened_files)[curr_filename] = curr_file;
    }

    // Make an input buffer large enough for the whole file
    buffer = (char *)malloc(filesize);

    curr_file->fseek(0, SEEK_SET);

    // Read the whole file
    len = curr_file->fread(buffer, 1, filesize);

    //NEEDSWORK: Should more intelligently handle this error
    if (len != (size_t)filesize)
    {
        cerr << "len not same as filesize" << endl; 
    }

    // Check if there is extra data past 'good' data in filesize amount
    len_extra = curr_file->fread(&overflow_byte, 1, 1);
    if (len_extra != 0)
    {
        memset(sha_buf, 0, filesize); // Send bogus SHA sum
    }

    // Compute SHA sum
    SHA1((const unsigned char *)buffer, filesize, sha_buf);
    free(buffer);
}

// Send file SHA sum and wait for acknowledgment from client; if no
//  acknowledgment is received, retry sending SHA sum
void sendSHAAndReceiveACK(unsigned char *sha_buf, size_t sha_buf_size, C150DgmSocket *sock, string filename,
                          packetCheckWriteInfo filechunk, bool end_of_file, char *client_return,
                          size_t client_return_size, int file_nastiness, const char *target_dir_name,
                          unordered_map<string, NASTYFILE *> *opened_files)
{

    ostringstream message_to_send;
    ssize_t readlen; // Amount of data read from client ACK return
    string packet_index;
    string packet_count;

    ostringstream fileSHA_message_to_send;
    string file_packet_index;
    string file_packet_count;

    unsigned char *file_sha_buf;
    file_sha_buf = (unsigned char *)malloc(20);

    // Convert SHA sum to string
    for (int i = 0; i < 20; i++)
    {
        message_to_send << hex << setw(2) << setfill('0') << static_cast<int>(sha_buf[i]);
    }

    
    packet_index = to_string(filechunk.packet_index);
    packet_count = to_string(filechunk.total_packets);

    message_to_send << "%" << packet_index << ":" << packet_count << "*" << filename;

    if (end_of_file)
    {
        computeFileSHA(file_sha_buf, filename, file_nastiness, target_dir_name, opened_files, filechunk.file_size);
        file_packet_index = "-1";
        file_packet_count = "-1";
        for (int i = 0; i < 20; i++)
        {
            fileSHA_message_to_send << hex << setw(2) << setfill('0') << static_cast<int>(file_sha_buf[i]);
        }

        fileSHA_message_to_send << "%" << file_packet_index << ":" << file_packet_count << "*" << filename;
    }

    // Send the message with SHA sum and filename back to the client
    try
    {
        sock->turnOnTimeouts(TIMEOUT_SECONDS);
        int retry = 0;
        while (retry != 5)
        {
            c150debug->printf(C150APPLICATION, "Writing message: \"%s\"", message_to_send.str().c_str());
            sock->write(message_to_send.str().c_str(), message_to_send.str().length() + 1);
            if (end_of_file)
            {
                sock->write(fileSHA_message_to_send.str().c_str(), fileSHA_message_to_send.str().length() + 1);
            }
            readlen = sock->read(client_return, client_return_size);
            if (readlen == 0)
            {
                c150debug->printf(C150APPLICATION, "Read zero length message, trying again");
                continue;
            }
            if (sock->timedout())
            { // Retry sending message
                retry++;
                c150debug->printf(C150APPLICATION, "Timed out, retrying write with message: \"%s\", attempt %d", message_to_send.str(), retry);
                continue;
            }
            else
            {
                // client_return[readlen] = '\0';  // Make sure null terminated
                string client_string(client_return); // Convert to C++ string
                c150debug->printf(C150APPLICATION, "Successfully read %d bytes. Message=\"%s\"", readlen, client_string.c_str());
                return; // Write suceeded, terminate loop
            }
        }
    }

    catch (C150NetworkException &e)
    {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG, "Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << "Caught C150NetworkException: " << e.formattedExplanation() << endl;
    }

    return;
}

// Parse response from the client on whether the sum computed by the server
//  matches the sum computed by the client (return true if there is
//  agreement, false otherwise)
int fileIsValid(string &ack_message, string &ack, string &filename)
{

    size_t delimiter = ack_message.find("%");
    if (delimiter != std::string::npos)
    {
        ack = ack_message.substr(0, delimiter);
        filename = ack_message.substr(delimiter + 1);
        if (ack == "CONFIRM")
        {
            *GRADING << "File: " << filename << " end-to-end check succeeded" << endl;
            return 1;
        }
        else
        {
            *GRADING << "File: " << filename << " end-to-end check failed" << endl;
            return 0;
        }
    }

    return -1;
}

// Tells whether the received message is packet data or related to the
//  final file SHA handshake
//
// Returns -1 for packet indices information if we are handling an ack message concerning a whole file,
//  otherwise returns 1 if we have populated instance of packetCheckWriteInfo
packetCheckWriteInfo parseClientMessage(string incoming, char *read_message)
{
    packetCheckWriteInfo parsed_message;
    parsed_message.packet_index = -1;
    parsed_message.total_packets = -1;

    // Messages concerning the complete file SHA check will be
    //      formatted as: CONFIRM%[filename] or DENY%[filename]
    if (incoming.substr(0, 7) == "CONFIRM" || incoming.substr(0, 4) == "DENY")
    {
        return parsed_message;
    }
    else
    {
        // We know that this packet is specific to a file chunk
        memcpy(&parsed_message, read_message, sizeof(packetCheckWriteInfo));
        
        return parsed_message;
    }
    return parsed_message; // NEEDSWORK: should we default to saying it's not for a file?
}

/////////////////////////////////////////////////////////////////////////
////                                                                 ////
////                     Misc. helper functions                      ////
////                                                                 ////
/////////////////////////////////////////////////////////////////////////

// Remove the file from the target directory
//
// Note: A file is deleted when the file on the server-side does
//       not match the original file on the client
string deleteFile(string target_directory, string ack_filename)
{
    string file_to_delete = target_directory + ack_filename + ".TMP";
    // Try to delete the file
    if (remove(file_to_delete.c_str()) == 0)
    {
        *GRADING << "File: " << ack_filename << " end-to-end check failed" << endl;
        return "DELETED";
    }
    else
    {
        c150debug->printf(C150ALWAYSLOG, "Error deleting file %s\n", ack_filename.c_str());
        return "ERROR";
    }
}

// Remove ".TMP" from the end of a filename
//
// Note: This operation is only done when we know that the file in the target
//       directory matches the file sent from the client
string removeTmpSuffix(string target_directory, string ack_filename)
{
    // Rename file without .TMP
    string old_filepath = target_directory + ack_filename + ".TMP";
    string new_filepath = target_directory + ack_filename;
    if (rename(old_filepath.c_str(), new_filepath.c_str()) == 0)
    {
        *GRADING << "File: " << ack_filename << " end-to-end check succeeded" << endl;
        return "RENAMED";
    }
    c150debug->printf(C150ALWAYSLOG, "Error removing .TMP from file %s\n", ack_filename);
    *GRADING << "Error removing .TMP suffix from file: " << ack_filename << endl;
    return "ERROR";
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

// Sanitize and parse user input from the command line
void checkInputArguments(int argc, char *argv[])
{
    // Check command line and parse arguments
    if (argc != 4)
    {
        fprintf(stderr, "Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(1);
    }
    // Verify that both network nastiness and file nastiness are legitimate numeric values
    if (strspn(argv[1], "0123456789") != strlen(argv[1]))
    {
        fprintf(stderr, "Network nastiness %s is not numeric\n", argv[1]);
        fprintf(stderr, "Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(4);
    }
    if (strspn(argv[1], "0123456789") != strlen(argv[1]))
    {
        fprintf(stderr, "File nastiness %s is not numeric\n", argv[1]);
        fprintf(stderr, "Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(4);
    }
}

// Create the target directory if it does not already exist
void createTargetDirectory(const char *directory_name)
{
    struct stat stat_check;
    if (stat(directory_name, &stat_check) == 0)
    {
        c150debug->printf(C150APPLICATION, "Target directory %s exists on server\n", directory_name);
        return;
    }
    else
    {
        if (mkdir(directory_name, 0777) == -1)
        { // Make the directory since it does not exist
            c150debug->printf(C150ALWAYSLOG, "Error creating directory name %s\n", directory_name);
            *GRADING << "Error creating directory " << directory_name << " – Exiting" << endl;
            exit(4);
        }
        else
        {
            c150debug->printf(C150APPLICATION, "Successfully created new target directory %s\n", directory_name);
        }
    }
    return;
}

// Return true if inputted file is a valid file, false otherwise
bool isFile(string fname, const char *target_directory_name)
{
    string full_path = target_directory_name + fname + ".TMP";
    const char *filename = full_path.c_str();
    struct stat statbuf;
    if (lstat(filename, &statbuf) != 0)
    {
        fprintf(stderr, "isFile: Error stating supplied source file %s\n", filename);
        *GRADING << "Error stating supplied source file " << filename << endl;
        return false;
    }

    if (!S_ISREG(statbuf.st_mode))
    {
        fprintf(stderr, "isFile: %s exists but is not a regular file\n", filename);
        return false;
    }
    return true;
}

// Add a .TMP suffix to every file in the target directory
// NOTE: This function is only useful in Pt.1
void addTmpSuffix(const char *directory_name)
{
    DIR *dir = opendir(directory_name);
    if (dir == nullptr)
    {
        std::cerr << "Failed to open directory: " << directory_name << std::endl;
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr)
    { // Skip if current file has .TMP suffix – if not, add it
        string curr_file = entry->d_name;

        if (curr_file == "." || curr_file == "..")
        {
            continue;
        }

        if (curr_file.size() >= 4 && curr_file.substr(curr_file.size() - 4) == ".TMP")
        {
            continue;
        }

        string old_path = string(directory_name) + "/" + curr_file;
        string new_path = old_path + ".TMP";

        if (rename(old_path.c_str(), new_path.c_str()) != 0)
        {
            cerr << "Error renaming file: " << old_path << " to " << new_path << endl;
        }
    }
    closedir(dir);
}

void initFileAsTmp(packetCheckWriteInfo filechunk, int file_nastiness, const char *directory_name, unordered_map<string, int> *file_writes)
{

    // Create file with .TMP suffix and write first packet of data
    NASTYFILE new_file(file_nastiness);
    string tmp_filename = string(directory_name) + string(filechunk.filename) + ".TMP";
    void *fopenretval = new_file.fopen(tmp_filename.c_str(), "rb");

    if (fopenretval == NULL)
    {
        cerr << "Error opening file " << tmp_filename << " errono= " << strerror(errno) << endl;
    }

    int len = new_file.fwrite(filechunk.data, 1, sizeof(filechunk.data));
    if (len != sizeof(filechunk.data))
    {
        cerr << "Error writing file " << tmp_filename << " errono= " << strerror(errno) << endl;
    }

    if (new_file.fclose() == 0)
    {
        c150debug->printf(C150ALWAYSLOG, "Successfully wrote TMP file %s", tmp_filename);
    }
    else
    {
        cerr << "Error closing file " << tmp_filename << " errono= " << strerror(errno) << endl;
    }

    (*file_writes)[string(filechunk.filename)] = 1;

    return;
}

