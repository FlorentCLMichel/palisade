// @file real-numbers-serialization-client - code to simulate a client to show
// efficacy in a server-client relationship. The client releases all contexts
// and keys (just to be extra safe), then loads in contexts and keys from the
// server. The client then does operations on the data before re-serialization
// and sending the data back to the server to verify
// @author: Ian Quah
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
#include "utils.h"

#include "palisade.h"

using namespace lbcrypto;

std::tuple<CryptoContext<DCRTPoly>, LPPublicKey<DCRTPoly>>
clientDeserializeDataFromServer(Configs &userConfigs) {
  /////////////////////////////////////////////////////////////////
  // NOTE: ReleaseAllContexts is imperative; it ensures that the environment
  // is cleared before loading anything. The function call ensures we are not
  // keeping any contexts in the process. Use it before creating a new CC
  /////////////////////////////////////////////////////////////////
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContext<DCRTPoly> clientCC;
  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.ccLocation, clientCC,
          SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << userConfigs.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }

  /////////////////////////////////////////////////////////////////
  // NOTE: the following 2 lines are essential
  // It is possible that the keys are carried over in the cryptocontext
  // serialization so clearing the keys is important
  /////////////////////////////////////////////////////////////////

  clientCC->ClearEvalMultKeys();
  clientCC->ClearEvalAutomorphismKeys();

  LPPublicKey<DCRTPoly> clientPublicKey;
  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.pubKeyLocation, clientPublicKey,
          SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << userConfigs.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }
  std::cout << "CLIENT: KP from server deserialized" << std::endl;

  std::ifstream multKeyIStream(
      userConfigs.DATAFOLDER + userConfigs.multKeyLocation,
      std::ios::in | std::ios::binary);
  if (!multKeyIStream.is_open()) {
    std::cerr << "CLIENT: cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.multKeyLocation
              << std::endl;
    std::exit(1);
  }
  if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval mult key file"
              << std::endl;
    std::exit(1);
  }

  std::cout << "CLIENT: Relinearization keys from server deserialized."
            << std::endl;
  std::ifstream rotKeyIStream(
      userConfigs.DATAFOLDER + userConfigs.rotKeyLocation,
      std::ios::in | std::ios::binary);
  if (!rotKeyIStream.is_open()) {
    std::cerr << "CLIENT: Cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.multKeyLocation
              << std::endl;
    std::exit(1);
  }
  if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream,
                                                SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval rot key file" << std::endl;
    std::exit(1);
  }
  return std::make_tuple(clientCC, clientPublicKey);
}

void clientSerializeDataForServer(CryptoContext<DCRTPoly> &clientCC,
                                  Ciphertext<DCRTPoly> &clientC1,
                                  Ciphertext<DCRTPoly> &clientC2,
                                  LPPublicKey<DCRTPoly> &clientPublicKey,
                                  const Configs &userConfigs) {
  std::cout << "CLIENT: Applying operations on data" << std::endl;
  auto clientCiphertextMult = clientCC->EvalMult(clientC1, clientC2);
  auto clientCiphertextAdd = clientCC->EvalAdd(clientC1, clientC2);
  auto clientCiphertextRot = clientCC->EvalAtIndex(clientC1, 1);
  auto clientCiphertextRotNeg = clientCC->EvalAtIndex(clientC1, -1);

  // Now, we want to simulate a client who is encrypting data for the server to
  // decrypt. E.g weights of a machine learning algorithm

  std::cout << "CLIENT: encrypting a vector" << std::endl;
  realVector clientVector1 = {1.0, 2.0, 3.0, 4.0};
  if (clientVector1.size() != VECTORSIZE) {
    std::cerr << "clientVector1 size was modified. Must be of length 4"
              << "\n";
    exit(1);
  }
  auto clientPlaintext1 = clientCC->MakeCKKSPackedPlaintext(clientVector1);
  auto clientInitiatedEncryption =
      clientCC->Encrypt(clientPublicKey, clientPlaintext1);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherMultLocation,
      clientCiphertextMult, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherAddLocation,
      clientCiphertextAdd, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherRotLocation,
      clientCiphertextRot, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherRotNegLocation,
      clientCiphertextRotNeg, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.clientVectorLocation,
      clientInitiatedEncryption, SerType::BINARY);
}
int main() {
  Configs userConfigs = Configs();
  std::cout << "This program requires the subdirectory "
            << userConfigs.DATAFOLDER << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;
  /////////////////////////////////////////////////////////////////
  // Actual client work
  /////////////////////////////////////////////////////////////////

  // basically we need the server to go first to write out all the serialization
  // So, we wait to see if the first file exists yet, which is an indication
  // that the server has started its job.
  // File exists:
  //    -> server is in the process. So, we sleep until the lock has been
  //    released
  // File NOT exists:
  //    -> We sleep until the first file exists then we wait for the lock to be
  //    released
  std::cout << "CLIENT: Step 1: Wait for server" << std::endl;
  if (fExists(userConfigs.DATAFOLDER + userConfigs.ccLocation)) {
    std::cout << "CLIENT Step 1: Found indication that server is working. "
                 "Waiting for lock to be released"
              << std::endl;
    // if the file we use as our flag exists, we nap until the lock has been
    // released then we take it. At this point, we know serialization is
    // finished
    while (fExists(SERVER_LOCK)) {
      std::cout << "CLIENT Step 1: Waiting for lock release. Taking a power nap"
                << std::endl;
      nap(2000);
    }
  } else {
    while (!fExists(userConfigs.DATAFOLDER + userConfigs.ccLocation)) {
      std::cout << "CLIENT Step 1: Waiting for server to start working and "
                   "then for lock to be released"
                << std::endl;
      nap(2000);
    }
    while (fExists(SERVER_LOCK)) {
      std::cout << "CLIENT Step 1: Waiting for lock release. Taking a power nap"
                << std::endl;
      nap(2000);
    }
  }

  std::cout << "CLIENT 2: Acquired lock. Getting serialized data";
  acquireLock(CLIENT_LOCK);

  auto ccAndPubKeyAsTuple = clientDeserializeDataFromServer(userConfigs);
  auto clientCC = std::get<CRYPTOCONTEXT_INDEX>(ccAndPubKeyAsTuple);
  auto clientPublicKey = std::get<PUBLICKEY_INDEX>(ccAndPubKeyAsTuple);

  Ciphertext<DCRTPoly> clientC1;
  Ciphertext<DCRTPoly> clientC2;
  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.cipherOneLocation, clientC1,
          SerType::BINARY)) {
    std::cerr << "CLIENT: Cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.cipherOneLocation
              << std::endl;
    std::exit(1);
  }

  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.cipherTwoLocation, clientC2,
          SerType::BINARY)) {
    std::cerr << "CLIENT: Cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.cipherTwoLocation
              << std::endl;
    std::exit(1);
  }

  std::cout << "CLIENT Step 3: Serializing data" << '\n';
  clientSerializeDataForServer(clientCC, clientC1, clientC2, clientPublicKey,
                               userConfigs);

  std::ofstream file{userConfigs.DATAFOLDER + "/client_write.txt"};
  std::cout << "CLIENT Step 4: Serialized all data to be sent to server. "
               "Releasing lock"
            << std::endl;
  releaseLock(CLIENT_LOCK);
}
