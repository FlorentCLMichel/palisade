// @file pre.cpp - Example of Proxy Re-Encryption client
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
//
// @section DESCRIPTION
// Example software for multiparty proxy-reencryption of an integer buffer using
// BFV rns scheme.

#define PROFILE

#include <getopt.h>
#include <chrono>

#include "palisade.h"
#include "pre-utils.h"

using namespace lbcrypto;

/**
 * run_client_alice - The alice client, 
 * @returns true if successful
 */

bool runClientAlice(void) {

  std::cout << "This program requres the subdirectory `"
            << ipcDirPath() << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;

  bool good = true;
  string name = "alice";

  
  // both alice and bob have to wait for the server to startup.
  // we use the client locks to show the sever that the clients have started
  // the server then frees it's showing it is working.

  PROFILELOG(name << " startup, aquiring lock then sleeping");
  acquireLock(CLIENT_A_LOCK);
  PROFILELOG(name << " startup, got lock napping ");

  // wait till server lock is free
  waitForReleasedLock(SERVER_LOCK, "Sz", 1000);

  releaseLock(CLIENT_A_LOCK);

  // time benchmarking variables
  TimeVar t;

  PROFILELOG(name << " reading crypto context from server");
  auto clientCC = clientRecvCCFromServer(name);

  // make clients keys
  PROFILELOG(name << " Generating key");
  TIC(t);
  auto keyPair = clientCC->KeyGen();
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
	
  if (!keyPair.good()) {
    std::cerr << name << " Key generation failed!" << std::endl;
    return (false);
  }

  PROFILELOG(name << " Serializing key");
  clientSendKeyToServer(name, keyPair);
  PROFILELOG(name << " Releaseing lock");

  auto ringsize = clientCC->GetRingDimension();
  auto plaintextModulus =
      clientCC->GetCryptoParameters()->GetPlaintextModulus();

  PROFILELOG(name << " plaintext modulus is :" << plaintextModulus);
  PROFILELOG(name << " can encrypt " << ringsize * 2 << " bytes of data");

  PT pt;
  CT ct;
  EvalKey reencryptionKey;

  PROFILELOG(name << " encrypting data");
  TIC(t);
  // we selected a plaintext modulus for the common cryptocontext so that we
  // could encode source data as a packed vector of shorts ringsize elements long
  unsigned int nshort = ringsize;
  vecInt vShorts; // our vector of shorts (must be stored as int64_t)

  if (plaintextModulus < 65536) {
    std::cerr
        << "error, code is designed for plaintextModulus>65536, modulus is "
        << plaintextModulus << std::endl;
	std::exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < nshort; i++){ // generate a random array of shorts
	vShorts.push_back(std::rand() % 65536);
  }
  //pack them into a packed plaintext (vector encryption)
  pt = clientCC->MakePackedPlaintext(vShorts);

  // Encryption
  ct = clientCC->Encrypt(keyPair.publicKey, pt);
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
  
  // at this point the two clients are ready to talk to each other.
  // alice will send her encrypted data packet to bob
  // then wait for bob to return his decrypted version

  // bob will receive alices encrypted packet, decrypt it with the reencryption key
  // he got from the server and his own decryption key 
  // then send the plaintext back to alice for comparison.

  PROFILELOG(name << " sending data to bob");
  clientSendCTToClient("alice", ct);

  // alice's final verification.
  PROFILELOG(name << " decrypting my data as a check");
  // self Decryption of alice's Ciphertext for testing
  TIC(t);
  PT ptDec;
  clientCC->Decrypt(keyPair.secretKey, ct, &ptDec);

  ptDec->SetLength(pt->GetLength()); //need to reset the length
  //unpack the plaintext data into vecInts
  vecInt unpackedOriginalAlice = pt->GetPackedValue();
  vecInt unpackedEncryptedAlice = ptDec->GetPackedValue();

  // note that PALISADE assumes that plaintext is in the range of -p/2..p/2
  // to recover 0...q simply add q if the unpacked value is negative
  for (unsigned int j = 0; j < pt->GetLength(); j++) {
    if (unpackedEncryptedAlice[j] < 0)
      unpackedEncryptedAlice[j] += plaintextModulus;
  }
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
  // receive bob's decrypted and upacked data
  PROFILELOG(name << " gettng bob vecInt");
  vecInt unpackedBob = clientRecvVecIntFromClient("alice");

  // verify result
  PROFILELOG(name << " verifying ");
  // compare all the results for correctness and return good=true if correct
  for (unsigned int j = 0; j < pt->GetLength(); j++) {
    if ((unpackedOriginalAlice[j] != unpackedEncryptedAlice[j]) ||
        (unpackedOriginalAlice[j] != unpackedBob[j])) {
      std::cout << j << ", " << unpackedOriginalAlice[j] << ", "
				<< unpackedEncryptedAlice[j] << ", " << unpackedBob[j] << std::endl;
      good = false;
    }
  }

  if (good) {
    std::cout << "PRE passes" << std::endl;
  } else {
    std::cout << "PRE fails" << std::endl;
  }

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  PROFILELOG(name << "Execution Completed.");

  return good;
}

/**
 * runClientBob - The bob client, 
 * @returns true if successful
 */

bool runClientBob(void) {

  std::cout << "This program requires the subdirectory "
            << ipcDirPath() << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;
  // wait for server to Generate parameters.

  string name = "bob";

  // both alice and bob have to wait for the server to startup.
  // we use the client locks to show the sever that the clients have started
  // the server then frees it's showing it is working.

  PROFILELOG(name << " startup, aquiring lock then sleeping");
  acquireLock(CLIENT_B_LOCK);
  PROFILELOG(name << " startup, got lock napping ");

  // wait till server lock is free
  waitForReleasedLock(SERVER_LOCK, "Sz", 1000);
  releaseLock(CLIENT_B_LOCK);
  
  // time benchmarking variables
  TimeVar t;
  
  PROFILELOG(name << " reading crypto context");
  auto clientCC = clientRecvCCFromServer(name);

  // make clients keys
  PROFILELOG(name << " Generating keys");
  TIC(t);
  auto keyPair = clientCC->KeyGen();
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
  
  if (!keyPair.good()) {
    std::cout << name << " Key generation failed!" << std::endl;
    return (false);
  }

  PROFILELOG(name << " Serializing public key");
  clientSendKeyToServer(name, keyPair);

  auto ringsize = clientCC->GetRingDimension();
  auto plaintextModulus =
      clientCC->GetCryptoParameters()->GetPlaintextModulus();
  PROFILELOG(name << " plaintext modulus is :" << plaintextModulus);

  if (plaintextModulus < 65536) {
    std::cerr
        << "error, code is designed for plaintextModulus>65536, modulus is "
        << plaintextModulus << std::endl;
	std::exit(EXIT_FAILURE);
  }

  PROFILELOG(name << " can encrypt " << ringsize * 2 << " bytes of data");

  PT pt;
  CT ct;

  // get reencryption key from server
  PROFILELOG(name << " Getting proxy re-encryption key...");
  EvalKey reencryptionKey = 
	clientRecvReencryptionKeyFromServer(name);

  // at this point the two clients are ready to talk to each other.

  // alice will send her encrypted data packet to bob

  // bob will wait for alice's packet, decrypt it with the reencryption key
  // then send the plaintext back to alice for comparison.

  // receive alice's encrypted data
  PROFILELOG(name << " Getting alices encrypted data");
  CT aliceCT = clientRecvCTFromClient("bob");

  PROFILELOG(name << " reecrypt the data with reencryption key");
  TIC(t);
  auto reencCT = clientCC->ReEncrypt(reencryptionKey, aliceCT);
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
  
  PROFILELOG(name << " decrypt the result with my key");
  PT bobPT;
  TIC(t);
  clientCC->Decrypt(keyPair.secretKey, reencCT, &bobPT);
  bobPT->SetLength(ringsize);  // note this could be something alice
  // sets and sents to bob
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");
  
  vecInt unpackedBob = bobPT->GetPackedValue();  
  PROFILELOG(name << " unpacking to length " << bobPT->GetLength());

  // note that PALISADE assumes that plaintext is in the range of -p/2..p/2
  // to recover 0...q simply add q if the unpacked value is negative
  for (unsigned int j = 0; j < bobPT->GetLength(); j++) {
    if (unpackedBob[j] < 0)
	  unpackedBob[j] += plaintextModulus;
  }
  PROFILELOG(name << " sending unpacked plaintext data to alice");
  clientSendVecIntToClient("bob",  unpackedBob);

  // bob is done
  PROFILELOG(name << " Execution Completed.");

  return true;
}


/**
 * main program
 * requires input of  -n alice|bob
 */

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  string name("");  // name of client to run

  while ((opt = getopt(argc, argv, "n:h")) != -1) {
    switch (opt) {
      case 'n':
        name = optarg;
        std::cout << "starting client named " << name << std::endl;
        break;
      case 'h':
      default: /* '?' */
        std::cerr << "Usage: " << std::endl
                  << "arguments:" << std::endl
                  << "  -n alice|bob name of the client" << std::endl
                  << "  -h prints this message" << std::endl;
		std::exit(EXIT_FAILURE);
    }
  }

  bool passed = false;

  if (name == "alice") {
    passed = runClientAlice();
  } else if (name == "bob") {
    passed = runClientBob();
  } else {
    std::cerr << "Bad client name: " << name << " must be alice or bob"
              << std::endl;
	std::exit(EXIT_FAILURE);
  }
  if (!passed) {  // there could be an error
	std::exit(EXIT_FAILURE);
  }
  std::exit(EXIT_SUCCESS);  // successful return
}
