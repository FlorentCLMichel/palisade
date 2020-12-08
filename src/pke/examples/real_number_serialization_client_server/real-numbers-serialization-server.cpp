// @file real-numbers-serialization-server - code to simulate a server to show
// efficacy in a server-client relationship. The server serializes contexts and
// keys for the client to then load. Afterwards, the server verifies that
// everything is correct
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

/**
 * Mocks a server which supports some basic operations
 */
class Server {
 public:
  /**
   * Instantiation of our "Server"
   * @param multDepth - integer describing the multiplicative depth for our CKKS
   * scheme
   * @param scaleFactorBits - scaleFactor
   * @param batchSize - size of the batch
   */
  Server(int multDepth, int scaleFactorBits, int batchSize);
  /**
   * provideData - read from some internal location, encrypt then send it off
   * for some client to process
   *    - in this case we write the data directly to a file (specified in the
   * config)
   * @param conf - a config specifying certain parameters (in a real-life
   * scenario this could be number of rows, serialization format, etc.)
   */
  void provideData(const Configs &conf);

  /**
   * receiveData - load data from some location (in this case from a file) and
   * process it however the server was set up.
   *
   * @param conf - a config specifying certain parameters (in a real-life
   * scenario this could be number of rows, serialization format, etc.)
   */
  void receiveData(const Configs &conf);

 private:
  /**
   * readData - reads data from our enclave
   * @param conf - config specifying parameters e.g number of rows to return,
   * some filter on returned rows, etc
   * @return real number matrix of values of interest
   */
  realMatrix readData(const Configs &conf);
  /**
   * packAndEncrypt - pack messages (into plaintexts) and encrypt them (into
   * ciphertexts)
   * @param matrixOfData - matrix of raw data, unpacked data. Likely directly
   * from a data lake
   * @return - a vector of ciphertexts (which are themselves like vectors)
   */
  ciphertextMatrix packAndEncrypt(const realMatrix &matrixOfData);

  /**
   * Write data
   * @param conf
   * @param matrix
   */
  void writeData(const Configs &conf, const ciphertextMatrix &matrix);
  LPKeyPair<DCRTPoly> m_kp;
  CryptoContext<DCRTPoly> m_cc;
  int m_vectorSize = 0;
};

/////////////////////////////////////////////////////////////////
// Public Interface
/////////////////////////////////////////////////////////////////

Server::Server(int multDepth, int scaleFactorBits, int batchSize) {
  m_cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
      multDepth, scaleFactorBits, batchSize);

  m_cc->Enable(ENCRYPTION);
  m_cc->Enable(SHE);
  m_cc->Enable(LEVELEDSHE);

  m_kp = m_cc->KeyGen();
  m_cc->EvalMultKeyGen(m_kp.secretKey);
  m_cc->EvalAtIndexKeyGen(m_kp.secretKey, {1, 2, -1, -2});
}

/**
 * provideData - receive a request from a client and "send" data over by writing
 * to a location
 * @param conf
 */
void Server::provideData(const Configs &conf) {
  auto rawData = readData(conf);
  auto ciphertexts = packAndEncrypt(rawData);
  writeData(conf, ciphertexts);
}

/**
 * receiveData - "receive" a payload from the client and verify the results
 */
void Server::receiveData(const Configs &conf) {
  /////////////////////////////////////////////////////////////////
  // Receive the data and decrpyt all of it
  /////////////////////////////////////////////////////////////////
  if (m_vectorSize == 0) {
    std::cerr << "SERVER: Must have sent data to client first ";
    std::cerr
        << "which initiates a vector size tracker (dimensionality of data)";
    std::cerr << "for use in decryption."
              << "\n";
    exit(1);
  }
  Ciphertext<DCRTPoly> serverCiphertextFromClient_Mult;
  Ciphertext<DCRTPoly> serverCiphertextFromClient_Add;
  Ciphertext<DCRTPoly> serverCiphertextFromClient_Rot;
  Ciphertext<DCRTPoly> serverCiphertextFromClient_RogNeg;
  Ciphertext<DCRTPoly> serverCiphertextFromClient_Vec;

  Serial::DeserializeFromFile(conf.DATAFOLDER + conf.cipherMultLocation,
                              serverCiphertextFromClient_Mult, SerType::BINARY);
  Serial::DeserializeFromFile(conf.DATAFOLDER + conf.cipherAddLocation,
                              serverCiphertextFromClient_Add, SerType::BINARY);
  Serial::DeserializeFromFile(conf.DATAFOLDER + conf.cipherRotLocation,
                              serverCiphertextFromClient_Rot, SerType::BINARY);
  Serial::DeserializeFromFile(conf.DATAFOLDER + conf.cipherRotNegLocation,
                              serverCiphertextFromClient_RogNeg,
                              SerType::BINARY);
  Serial::DeserializeFromFile(conf.DATAFOLDER + conf.clientVectorLocation,
                              serverCiphertextFromClient_Vec, SerType::BINARY);
  std::cout << "SERVER: Deserialized all data from client on server" << '\n'
            << std::endl;

  Plaintext serverPlaintextFromClient_Mult;
  Plaintext serverPlaintextFromClient_Add;
  Plaintext serverPlaintextFromClient_Rot;
  Plaintext serverPlaintextFromClient_RotNeg;
  Plaintext serverPlaintextFromClient_Vec;

  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Mult,
                &serverPlaintextFromClient_Mult);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Add,
                &serverPlaintextFromClient_Add);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Rot,
                &serverPlaintextFromClient_Rot);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_RogNeg,
                &serverPlaintextFromClient_RotNeg);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Vec,
                &serverPlaintextFromClient_Vec);

  /////////////////////////////////////////////////////////////////
  // Retrive the values from the CKKS packed Values
  /////////////////////////////////////////////////////////////////

  serverPlaintextFromClient_Mult->SetLength(m_vectorSize);
  serverPlaintextFromClient_Add->SetLength(m_vectorSize);
  serverPlaintextFromClient_Vec->SetLength(m_vectorSize);
  serverPlaintextFromClient_Rot->SetLength(m_vectorSize + 1);
  serverPlaintextFromClient_RotNeg->SetLength(m_vectorSize + 1);

  realVector multExpected = {12.5, 27, 43.5, 62};
  realVector addExpected = {13.5, 15.5, 17.5, 19.5};
  realVector vecExpected = {1, 2, 3, 4};
  realVector rotExpected = {2, 3, 4, 0.0000, 0.00000};
  realVector negRotExpected = {0.00000, 1, 2, 3, 4};

  auto multFlag = validateData(
      serverPlaintextFromClient_Mult->GetRealPackedValue(), multExpected);
  std::cout << "Mult correct: " << (multFlag ? "Yes" : "No ") << "\n";
  auto addFlag = validateData(
      serverPlaintextFromClient_Add->GetRealPackedValue(), addExpected);
  std::cout << "Add correct: " << (addFlag ? "Yes" : "No ") << "\n";
  auto vecFlag = validateData(
      serverPlaintextFromClient_Vec->GetRealPackedValue(), vecExpected);
  std::cout << "Vec encryption correct: " << (vecFlag ? "Yes" : "No ") << "\n";
  auto rotFlag = validateData(
      serverPlaintextFromClient_Rot->GetRealPackedValue(), rotExpected);
  std::cout << "Rotation correct: " << (rotFlag ? "Yes" : "No ") << "\n";
  auto negRotFlag = validateData(
      serverPlaintextFromClient_RotNeg->GetRealPackedValue(), negRotExpected);
  std::cout << "Negative rotation correct: " << (negRotFlag ? "Yes" : "No ")
            << "\n";
}

/////////////////////////////////////////////////////////////////
// Private Interface
/////////////////////////////////////////////////////////////////

/**
 * readData - mock reading data from the enclave. We just use hardcoded vectors
 * @return
 *  vector of hard-coded vectors (basically a matrix)
 */
std::vector<std::vector<double>> Server::readData(const Configs &conf) {
  std::cout << "SERVER: Writing data to: " << conf.DATAFOLDER << "\n";

  realVector vec1 = {1.0, 2.0, 3.0, 4.0};
  realVector vec2 = {12.5, 13.5, 14.5, 15.5};

  m_vectorSize = vec1.size();

  return {
      vec1,
      vec2,
  };
}

/**
 * packAndEncrypt - pack the data into a vector and then encrypt it
 * @param matrixOfData
 * @return
 */
ciphertextMatrix Server::packAndEncrypt(const realMatrix &matrixOfData) {
  auto container =
      ciphertextMatrix(matrixOfData.size(), Ciphertext<DCRTPoly>());

  unsigned int ind = 0;
  for (auto &v : matrixOfData) {
    container[ind] =
        m_cc->Encrypt(m_kp.publicKey, m_cc->MakeCKKSPackedPlaintext(v));
    ind += 1;
  }
  return container;
}

/**
 * writeData - write the read-pack-encrypt data to the specified locations.
 * @param conf
 * @param matrix
 */
void Server::writeData(const Configs &conf, const ciphertextMatrix &matrix) {
  if (!Serial::SerializeToFile(conf.DATAFOLDER + conf.ccLocation, m_cc,
                               SerType::BINARY)) {
    std::cerr << "Error writing serialization of the crypto context to "
                 "cryptocontext.txt"
              << std::endl;
    std::exit(1);
  }

  demarcate("SERVER-SIDE: sending data");

  std::cout << "SERVER: Cryptocontext serialized" << std::endl;

  if (!Serial::SerializeToFile(conf.DATAFOLDER + conf.pubKeyLocation,
                               m_kp.publicKey, SerType::BINARY)) {
    std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
    std::exit(1);
  }
  std::cout << "SERVER: Public key serialized" << std::endl;

  std::ofstream multKeyFile(conf.DATAFOLDER + conf.multKeyLocation,
                            std::ios::out | std::ios::binary);
  if (multKeyFile.is_open()) {
    if (!m_cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
      std::cerr << "SERVER: Error writing eval mult keys" << std::endl;
      std::exit(1);
    }
    std::cout << "SERVER: EvalMult/ relinearization keys have been serialized"
              << std::endl;
    multKeyFile.close();
  } else {
    std::cerr << "SERVER: Error serializing EvalMult keys" << std::endl;
    std::exit(1);
  }

  std::cout << "SERVER: Relinearization/ mult key serialized" << std::endl;
  std::ofstream rotationKeyFile(conf.DATAFOLDER + conf.rotKeyLocation,
                                std::ios::out | std::ios::binary);
  if (rotationKeyFile.is_open()) {
    if (!m_cc->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY)) {
      std::cerr << "SERVER: Error writing rotation keys" << std::endl;
      std::exit(1);
    }
    std::cout << "SERVER: Rotation keys have been serialized" << std::endl;
  } else {
    std::cerr << "SERVER: Error serializing Rotation keys" << std::endl;
    std::exit(1);
  }

  std::cout << "SERVER: Rotation/ automorphism key serialized" << std::endl;
  if (!Serial::SerializeToFile(conf.DATAFOLDER + conf.cipherOneLocation,
                               matrix[0], SerType::BINARY)) {
    std::cerr << "SERVER: Error writing ciphertext 1" << std::endl;
    std::exit(1);
  }

  std::cout << "SERVER: ciphertext1 serialized" << std::endl;
  if (!Serial::SerializeToFile(conf.DATAFOLDER + conf.cipherTwoLocation,
                               matrix[1], SerType::BINARY)) {
    std::cerr << "SERVER: Error writing ciphertext 2" << std::endl;
    std::exit(1);
  }
  std::cout << "SERVER: ciphertext2 serialized" << std::endl;
}

int main() {
  Configs userConfigs = Configs();
  std::cout << "This program requres the subdirectory `"
            << userConfigs.DATAFOLDER << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;

  std::cout << "SERVER 1: Acquiring lock"
            << "\n";

  acquireLock(SERVER_LOCK);
  const int multDepth = 5;
  const int scaleFactorBits = 40;
  const usint batchSize = 32;
  Server server = Server(multDepth, scaleFactorBits, batchSize);

  server.provideData(userConfigs);
  std::cout << "SERVER 2: Releasing lock"
            << "\n";
  releaseLock(SERVER_LOCK);
  while (fExists(CLIENT_LOCK)) {
    nap();
  }

  if (fExists(userConfigs.DATAFOLDER + "/client_write.txt")) {
    std::cout << "SERVER 3: Found to-serialize-to" << std::endl;
    // if the file we use as our flag exists, we nap until the lock has been
    // released then we take it. At this point, we know serialization is
    // finished
    while (fExists(userConfigs.DATAFOLDER + CLIENT_LOCK)) {
      std::cout << "SERVER 3: clients lock still exists. Napping" << std::endl;
      nap(2000);
    }
  } else {
    while (!fExists(userConfigs.DATAFOLDER + "/client_write.txt")) {
      std::cout << "SERVER 3: did not find serialize-to" << std::endl;
      nap(2000);
    }
    while (fExists(userConfigs.DATAFOLDER + CLIENT_LOCK)) {
      std::cout
          << "SERVER 3: found serialize-to now waiting for write to finish";
      nap(2000);
    }
  }
  std::cout << "SERVER 4: Acquiring lock" << std::endl;
  acquireLock(SERVER_LOCK);
  server.receiveData(userConfigs);

  std::cout << "SERVER 5: Releasing lock" << std::endl;
  releaseLock(SERVER_LOCK);
  std::cout << "SERVER 6: Cleaning up" << std::endl;
  fRemove(userConfigs.DATAFOLDER + "/client_write.txt");
  fRemove(userConfigs.DATAFOLDER + userConfigs.ccLocation);
  releaseLock(
      CLIENT_LOCK);  // in case the lock exists from a prior session clear it.
}
