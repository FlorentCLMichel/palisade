// @file pre-utils.h - utilities to be used with
//    pre-client
//    pre-server
// @authors: David Cousins, Ian Quah
// TPOC: contact@palisade-crypto.org

// @copyright Copyright (c) 2020, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//remove explicit directory

#ifndef PRE_UTILS_H
#define PRE_UTILS_H

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "utils/serialize-binary.h"
#include <iostream>
#include <fstream>

/////////////////////////////////////////////////////////////////
// simple file based IPC for our pre-server client example.
// to keep this simple we implement all ipc calls as stand alone functions defined
// in this file.
// first we define the configuration context, then simple lock files then specific
// server and client functions customised for the IPC example
// thus this file could be easily replaced with socket based IPC and the server and client
// codes would not change.
// also note this code is hardcoded for the specific interation of this demo, it is not generic

using namespace lbcrypto;

// shortcuts for PALISADE types to make the code more readable
using CC = CryptoContext<DCRTPoly>; //crypto context
using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;             // plaintext
using KeyPair = LPKeyPair<DCRTPoly>; //secret/public key par. 
using EvalKey = LPEvalKey<DCRTPoly>;  //evaluation key
using vecInt = vector<int64_t>;  // vector of ints

/**
 * Config container.
*/
struct Configs {
  /////////////////////////////////////////////////////////////////
  // NOTE:
  // If running locally, you may want to replace the "hardcoded" DATAFOLDER with
  // the DATAFOLDER location below which gets the current working directory
  /////////////////////////////////////////////////////////////////
  //  char buff[1024];
  //  std::string DATAFOLDER = std::string(getcwd(buff, 1024)) + "/demoData";

  const std::string DATAFOLDER = "demoData";
  const std::string ccLocation = "/cryptocontext.txt";

  // Save-Load locations for keys
  const std::string publicKeyLocation = "/key_pub.txt";  // Pub key
  const std::string secretKeyLocation = "/key_sec.txt";  // Sec key
  const std::string reencryptionKeyLocation =
      "/reenc_key_mult.txt";  // reencryption key
  // Save-load locations for ciphertexts
  const std::string aliceCTLocation = "/alice_ciphertext.txt";
  // Save-load locations for plaintexts
  const std::string bobPTLocation = "/bob_plaintext.txt";
};


const std::string CLIENT_A_LOCK = "demoData/c_a_lock.txt";
const std::string CLIENT_B_LOCK = "demoData/c_b_lock.txt";
const std::string SERVER_LOCK = "demoData/s_lock.txt";

Configs GConf;  // global configuration structure that contains all locations for IPC

/////////////////////////////////////////////////////////////////
// Synchronization primitives
// we use files as locks to synchronize processes.
// we move data between processes using files.
// the locks prevent the file from being read before writing is complete
/////////////////////////////////////////////////////////////////

/** fExists: check if the file already exists
 * @param filename
 * @return
 *  bool: if true then file exists, false otherwise
 *        
 */
bool fExists(const std::string &filename) {
  if (FILE *file = fopen(filename.c_str(), "r")) {
    fclose(file);
    return true;
  } else {
    return false;
  }
}

/** fRemove: Remove the file if it already exists
 * @param filename
 * @return
 *  bool: if true then the file already exists and we delete it 
 *        false otherwise
 */
bool fRemove(const std::string &filename) {
  if (FILE *file = fopen(filename.c_str(), "r")) {
    fclose(file);
    std::remove(filename.c_str());
    return true;
  } else {
    return false;
  }
}

/** fCleanup: Remove all files used for synchronisation
 * @param config data
 * @return 
 *  void
 */
void fCleanup() {
  fRemove(CLIENT_A_LOCK);
  fRemove(CLIENT_B_LOCK);
  fRemove(SERVER_LOCK);
  fRemove(GConf.DATAFOLDER + GConf.ccLocation);
  fRemove(GConf.DATAFOLDER + GConf.publicKeyLocation);
  fRemove(GConf.DATAFOLDER + GConf.secretKeyLocation);
  fRemove(GConf.DATAFOLDER + GConf.reencryptionKeyLocation);
  fRemove(GConf.DATAFOLDER + GConf.aliceCTLocation);
  fRemove(GConf.DATAFOLDER + GConf.bobPTLocation);
}

/**
 * acquireLock
 *  - "get" the lock. Do this by creating the lock file
 * @param lockName - name of file for lock
 */
void acquireLock(const std::string &lockName) {
  DEBUG_FLAG(false);
  DEBUG("Acquiring lock " << lockName);
  try {
    std::ofstream myfile(lockName, std::ofstream::out);
    // myfile.open(lockName.c_str());
    DEBUG("opened");
    myfile << "lock" << std::endl;
    myfile.close();
    DEBUG("closed");
  } catch (const std::ios_base::failure &err) {
    std::cerr << "exception aquiring lock " << lockName << ": " << err.what()
              << std::endl;
	exit(EXIT_FAILURE);
  } catch (...) {
    std::cerr << "exception aquiring lock " << lockName << "of unknown type "
              << std::endl;
	exit(EXIT_FAILURE);
  }
}

/**
 * checkLock
 *  - return true if the lock file exists.
 * @param lockName - name of file for lock
 */
bool checkLock(const std::string &lockName) { return fExists(lockName); }

/**
 * releaseLock
 *  - "release" the lock by deleting the file
 * @param lockName - name of file for lock
 */
void releaseLock(const std::string &lockName) {
  try {
    std::remove(lockName.c_str());
  } catch (const std::ios_base::failure &err) {
    std::cerr << "exception releasing lock " << lockName << ": " << err.what()
              << std::endl;
	exit(EXIT_FAILURE);
  } catch (...) {
    std::cerr << "exception releasing lock " << lockName << "of unknown type "
              << std::endl;
	exit(EXIT_FAILURE);
  }
}

/**
 * Take a powernap of (DEFAULT) 0.5 seconds
 * @param ms - number of milisec to nap
 */
void nap(const int &ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}

/**
 * waitForAquiredLock
 *  - spin wait for a lock to be acquired 
 * @param lockName - name of file for lock
 * @param message - messag to print while waiting
 * @param ms - nap time to wait between checks. 
 */

void waitForAquiredLock(const std::string &lockName, const std::string &message,
                        const int &ms) {
  DEBUG_FLAG(false);
  DEBUG("waiting for acquired lock " << lockName);
  while (!checkLock(lockName)) {
    std::cout << message << std::flush;
    nap(ms);
  }
  std::cout << std::endl;
}

/**
 * waitForReleasedLock
 *  - spin wait for a lock to be released
 * @param lockName - name of file for lock
 * @param message - messag to print while waiting
 * @param ms - nap time to wait between checks. 
 */

void waitForReleasedLock(const std::string &lockName,
                         const std::string &message, const int &ms) {
  DEBUG_FLAG(false);
  DEBUG("waiting for released lock " << lockName);
  while (checkLock(lockName)) {
    std::cout << message << std::flush;
    nap(ms);
  }
  std::cout << std::endl;
}

/**
 * waitForMessage
 *  - spin wait for a message (file) to be written and associated
 * lock to be released
 * @param location - name of file for message
 * @param lockName - name of file for lock
 * @param message - messag to print while waiting
 * @param ms - nap time to wait between checks. 
 */
void waitForMessage(const std::string &location, const std::string &lockName,
                    const std::string &message, const int &ms) {
  DEBUG_FLAG(false);
  DEBUG("waiting for message " << location << "  " << lockName);
  while (!fExists(location)) {  // wait for file to exist
    std::cout << message << std::flush;
    nap(ms);
  }
  while (checkLock(lockName)) {  // wait for alice to finish writing
    std::cout << message << std::endl;
    nap(ms);
  }
  std::cout << std::endl;
}

/**
 * ipcDirPath
 *  - report the requred directory path that holds IPC files
 * @return directory path 
 */
std::string ipcDirPath(void){
  return GConf.DATAFOLDER;
}


/////////////////////////////////////////////////////////////////
// Server IPC calls using file I/O
/////////////////////////////////////////////////////////////////


/**
 * Makes a server which supports some basic pke operations
 * IPC is handled by file I.O
 * The server builds the crypto context, sends it to clients alice and bob.
 * alice sends her private key to the server who then can 
 * handles recryption key request from bob.
 * clients exchange data directly.
 *
 * note this is NOT meant to be a secure example, as alice's secret key is transferred 
 * using the unsecure mocked up IPC over files. A
 */

// server function calls

/**
 * serverSendCCToClient - writes the crypto context to  to a location
 * (in this case from a file)
 * @param cc - the crypto context to send
 
 */
void serverSendCCToClient(CC &cc) {
  DEBUG_FLAG(false);
  acquireLock(SERVER_LOCK);
  if (!Serial::SerializeToFile(GConf.DATAFOLDER + GConf.ccLocation, cc,
                               SerType::BINARY)) {
    std::cerr << "Error writing serialization of the crypto context to "
	  "cryptocontext.txt"
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
  releaseLock(SERVER_LOCK);
  DEBUG("SERVER: Cryptocontext sent");
}

/**
 * serverReceiveKeyRequest - receive a request from a client and "send" data over by
 * writing to a location
 * @param clientName "alice" or "bob"
 * @return keyPair containing the appropriate key
 */
KeyPair serverRecvKeyFromClient(string clientName) {
  KeyPair kp;
  string message = clientName + " lock still exists. Napping";

  if (clientName == "alice") {
    string location = GConf.DATAFOLDER + GConf.secretKeyLocation;
    waitForMessage(location, CLIENT_A_LOCK, message, 2000);
    if (!Serial::DeserializeFromFile(location, kp.secretKey,
                                     SerType::BINARY)) {
      std::cerr << "SERVER: cannot read serialized data from: " << location
                << std::endl;
      std::exit(EXIT_FAILURE);
    }
    kp.publicKey = NULL;
  } else if (clientName == "bob") {
    string location = GConf.DATAFOLDER + GConf.publicKeyLocation;
    waitForMessage(location, CLIENT_A_LOCK, message, 2000);
    if (!Serial::DeserializeFromFile(location, kp.publicKey,
                                     SerType::BINARY)) {
      std::cerr << "SERVER: cannot read serialized data from: " << location
                << std::endl;
      std::exit(EXIT_FAILURE);
      kp.secretKey = NULL;
    }
  } else {
    std::cout << "bad client name " << clientName << " Server Exiting"
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
  return kp;
}

/**
 * serverSendReencryptionkey - send a reencryption key to clientName
 * @param clientName - name of client requesting
 * @param reencKey - key to write
 */

void serverSendReencryptionKeyToClient(string clientName,
									   EvalKey &reencKey) {
  DEBUG_FLAG(false);
  if (clientName == "bob") {
    acquireLock(SERVER_LOCK);
    string location = GConf.DATAFOLDER + GConf.reencryptionKeyLocation;
    if (!Serial::SerializeToFile(location, reencKey, SerType::BINARY)) {
      std::cerr << "Exception writing reencryption key to " << location
                << std::endl;
      std::exit(EXIT_FAILURE);
    }
    DEBUG("SERVER: reencryption key serialized");
    releaseLock(SERVER_LOCK);
  } else {
    std::cerr << "bad client name " << clientName
              << " for reencryption key. Server Exiting" << std::endl;
    std::exit(EXIT_FAILURE);
  }
}


/////////////////////////////////////////////////////////////////
// Client IPC functions 
/////////////////////////////////////////////////////////////////


/**
 * clientRecvCCFromServer
 * @param name - name of client
 * @return - returns a cryptocontext
 */

CC clientRecvCCFromServer(string &name) {

  /////////////////////////////////////////////////////////////////
  // NOTE: ReleaseAllContexts is imperative; it ensures that the environment
  // is cleared before loading anything. The function call ensures we are not
  // keeping any contexts in the process. Use it before creating a new CC
  /////////////////////////////////////////////////////////////////
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CC clientCC;

  string location = GConf.DATAFOLDER + GConf.ccLocation;

  string message = name + " wait for Server. Napping ";
  waitForMessage(location, SERVER_LOCK, message, 1000);

  if (!Serial::DeserializeFromFile(location, clientCC, SerType::BINARY)) {
    std::cerr << name << " cannot read serialized data from: "
              << location << std::endl;
    std::exit(EXIT_FAILURE);
  }

  /////////////////////////////////////////////////////////////////
  // NOTE: the following 2 lines are essential
  // It is possible that the keys are carried over in the cryptocontext
  // serialization so clearing the keys is important
  /////////////////////////////////////////////////////////////////

  clientCC->ClearEvalMultKeys();
  clientCC->ClearEvalAutomorphismKeys();

  return clientCC;
}


/**
 * clientSendKeyToServer -- sends either alices secret key or bobs public key
 * @param name - name of client
 */

void clientSendKeyToServer(const string &name, KeyPair &kp) {
  bool aliceFlag = name == "alice";

  if (aliceFlag) {
    acquireLock(CLIENT_A_LOCK);
    auto location = GConf.DATAFOLDER + GConf.secretKeyLocation;
    if (!Serial::SerializeToFile(location, kp.secretKey,
                                 SerType::BINARY)) {
      std::cerr << name << " Exception writing secret key to " << location
                << std::endl;
      std::exit(EXIT_FAILURE);
    }
    releaseLock(CLIENT_A_LOCK);
  } else {
    acquireLock(CLIENT_B_LOCK);
    auto location = GConf.DATAFOLDER + GConf.publicKeyLocation;
    if (!Serial::SerializeToFile(location, kp.publicKey,
                                 SerType::BINARY)) {
      std::cerr << name << " Exception writing public key to " << location
                << std::endl;
      std::exit(EXIT_FAILURE);
    }
    releaseLock(CLIENT_B_LOCK);
  }
}

/**
 * clientRecvReencryptionKeyFromServer -- bob uses to get reencryption key
 * @param name - name of client
 * @param reencKey - resulting reencryption key
 */


EvalKey clientRecvReencryptionKeyFromServer(string clientName) {
  DEBUG_FLAG(false);
  EvalKey reencKey;
  if (clientName == "bob") {
    string location = GConf.DATAFOLDER + GConf.reencryptionKeyLocation;
    string message = clientName + " server lock still exists. Napping ";

    waitForMessage(location, SERVER_LOCK, message, 1000);

    if (!Serial::DeserializeFromFile(location, reencKey, SerType::BINARY)) {
      std::cerr << clientName << " Exception reading reencryption key from "
                << location << std::endl;
      std::exit(EXIT_FAILURE);
    }
    DEBUG(clientName << " reencryption key received");
	return reencKey;
	
  } else {
    std::cerr << "bad client name " << clientName
              << " for clientRecvReencryptionKeyFromServer. " << clientName
              << " Exiting" << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

/**
 * clientSendCTToClient -- alice sends CT to bob
 * @param name - name of client
 * @param ct - ciphertext to send
 */

void clientSendCTToClient(const string &name, CT &ct) {
  bool aliceFlag = name == "alice";
  auto location = GConf.DATAFOLDER + GConf.aliceCTLocation;
  if (aliceFlag) {
    acquireLock(CLIENT_A_LOCK);
    if (!Serial::SerializeToFile(location, ct, SerType::BINARY)) {
      std::cerr << name << " Error sending ciphertext" << std::endl;
      std::exit(EXIT_FAILURE);
    }
    releaseLock(CLIENT_A_LOCK);
  } else {
    std::cerr << name << " Erroneously asked to send CT " << location
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

/**
 * clientRecvCTFromClient -- bob uses to get ciphertext from alice
 * @param name - name of client
 * @param ct - resulting ciphertext
 */

CT clientRecvCTFromClient(const string &name) {
  CT ct;
  bool bobFlag = name == "bob";
  auto location = GConf.DATAFOLDER + GConf.aliceCTLocation;
  string message = name + " alice lock still exists. Napping ";
  if (bobFlag) {
    waitForMessage(location, CLIENT_A_LOCK, message, 1000);
    if (!Serial::DeserializeFromFile(location, ct, SerType::BINARY)) {
      std::cerr << name << " Error receiving ciphertext" << std::endl;
      std::exit(EXIT_FAILURE);
    }
	return ct;
  } else {
    std::cerr << name << " Erroneously asked to receieve CT " << location
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

/**
 * clientSendVecIntToClient -- bob sends vector of ints to alice 
 * @param name - name of client
 * @param vi - vector of ints to send
 */

void clientSendVecIntToClient(const string &name, vecInt &vi) {
  bool bobFlag = (name == "bob");
  auto location = GConf.DATAFOLDER + GConf.bobPTLocation;
  if (bobFlag) {
    acquireLock(CLIENT_B_LOCK);
    if (!Serial::SerializeToFile(location, vi, SerType::BINARY)) {
      std::cerr << name << " Error writing vecInt" << std::endl;
      std::exit(EXIT_FAILURE);
    }
    releaseLock(CLIENT_B_LOCK);
  } else {
    std::cerr << name << " Erroneously asked to write vecInt " << location
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

/**
 * clientRecvVecIntFromClient -- alice uses to get vector of ints from bob
 * @param name - name of client
 * @returns  resulting vector of ints
 */

vecInt clientRecvVecIntFromClient(const string &name) {
  vecInt vi;
  bool aliceFlag = name == "alice";
  auto location = GConf.DATAFOLDER + GConf.bobPTLocation;
  if (aliceFlag) {
    string message = name + " bob lock still exists. Napping ";
    waitForMessage(location, CLIENT_B_LOCK, message, 1000);
	
    if (!Serial::DeserializeFromFile(location, vi, SerType::BINARY)) {
      std::cerr << name << " Error reading vecInt" << std::endl;
      std::exit(EXIT_FAILURE);
    }
	return vi;
  } else {
    std::cerr << name << " Erroneously asked to write PT " << location
              << std::endl;
    std::exit(EXIT_FAILURE);
  }
}


#endif  // PRE_UTILS_H
