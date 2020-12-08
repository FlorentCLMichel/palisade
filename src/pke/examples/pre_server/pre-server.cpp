// @file pke-server - code to simulate a pke server
// @author: Ian Quah, David Cousins
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

#define PROFILE

#include "palisade.h"
#include "pre-utils.h"

using namespace lbcrypto;


int main() {

  std::cout << "PRE client server demo:" << std::endl
			<< "Run pre-server first, then in separate windows run"<<std::endl
			<< " pre-client -n alice"<< std::endl
			<< "and pre-client -n bob"<< std::endl;
	

  std::cout << "This program requres the subdirectory `"
            << ipcDirPath() << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;

  PROFILELOG("SERVER:  Cleaning up from prior runs");
  fCleanup();

  // need an initial synchronization to make sure alice and bob are up.
  // we acquire ourlock
  // (bob and alice wait on this after aquiring their own locks)
  acquireLock(SERVER_LOCK);

  // then we wait for alice an bob o acquire their locks
  PROFILELOG("SERVER:  waiting for initial Alice wakeup");
  waitForAquiredLock(CLIENT_A_LOCK, "Az", 1000);

  PROFILELOG("SERVER:  waiting for initial Bob wakeup");
  waitForAquiredLock(CLIENT_B_LOCK, "Bz", 1000);

  // and we release our lock with releases alice and bob
  releaseLock(SERVER_LOCK);


  // time benchmarking variables
  TimeVar t;

  PROFILELOG("SERVER: Generating crypto context");
  TIC(t);
  int plaintextModulus = 65537;  // can encode shorts
  uint32_t multDepth = 1;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;

  auto serverCC = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
      plaintextModulus, securityLevel, sigma, 0, multDepth, 0, OPTIMIZED);
  serverCC->Enable(ENCRYPTION);
  serverCC->Enable(SHE);
  serverCC->Enable(PRE);
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");

  PROFILELOG("SERVER: writing CC");
  TIC(t);
  serverSendCCToClient(serverCC);
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");

  PROFILELOG("SERVER: get alice secret key");
  auto aliceKeyPairStore = serverRecvKeyFromClient("alice");
  auto aliceSecretKey = aliceKeyPairStore.secretKey;

  PROFILELOG("SERVER: get bob public key");
  auto bobKeyPairStore = serverRecvKeyFromClient("bob");  

  auto bobPublicKey = bobKeyPairStore.publicKey;

  PROFILELOG("SERVER : making Reencryption Key");
  TIC(t);
  EvalKey reencryptionKey = serverCC->ReKeyGen(bobPublicKey, aliceSecretKey);
  PROFILELOG("elapsed time " << TOC_MS(t) << "msec.");;
  
  PROFILELOG("SERVER : Sending Reencryption Key to Bob");
  serverSendReencryptionKeyToClient("bob", reencryptionKey);
  std::cout << "SERVER: Exiting" << std::endl;
  exit(EXIT_SUCCESS);
}
