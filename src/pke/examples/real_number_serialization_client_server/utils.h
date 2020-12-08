// @file utils.h - utilities to be used with
//    -real-numbers-serialization-client
//    -real-numbers-serialization-server
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
#ifndef PALISADE_SRC_PKE_EXAMPLES_REAL_NUMBER_SERIALIZATION_CLIENT_SERVER_UTILS_H_
#define PALISADE_SRC_PKE_EXAMPLES_REAL_NUMBER_SERIALIZATION_CLIENT_SERVER_UTILS_H_
#include <palisade.h>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include "utils/serialize-binary.h"
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <fstream>
#include <thread>
#include <cstring>
using namespace lbcrypto;

using realVector = std::vector<double>;
using realMatrix = std::vector<realVector>;
using ciphertextMatrix = std::vector<Ciphertext<DCRTPoly>>;

const int VECTORSIZE = 4;
const int CRYPTOCONTEXT_INDEX = 0;
const int PUBLICKEY_INDEX = 1;
const std::string CLIENT_LOCK = "/c_lock.txt";
const std::string SERVER_LOCK = "/s_lock.txt";

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

  // Save-Load locations for keys
  const std::string DATAFOLDER = "demoData";
  std::string ccLocation = "/cryptocontext.txt";
  std::string pubKeyLocation = "/key_pub.txt";    // Pub key
  std::string multKeyLocation = "/key_mult.txt";  // relinearization key
  std::string rotKeyLocation = "/key_rot.txt";    // automorphism / rotation key

  // Save-load locations for RAW ciphertexts
  std::string cipherOneLocation = "/ciphertext1.txt";
  std::string cipherTwoLocation = "/ciphertext2.txt";

  // Save-load locations for evaluated ciphertexts
  std::string cipherMultLocation = "/ciphertextMult.txt";
  std::string cipherAddLocation = "/ciphertextAdd.txt";
  std::string cipherRotLocation = "/ciphertextRot.txt";
  std::string cipherRotNegLocation = "/ciphertextRotNegLocation.txt";
  std::string clientVectorLocation = "/ciphertextVectorFromClient.txt";
};

/**
 * Demarcate - Visual separator between the sections of code
 * @param msg - string message that you want displayed between blocks of
 * characters
 */
void demarcate(const std::string &msg) {
  std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
  std::cout << msg << std::endl;
  std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
}

/**
 * vectorsEqual - test if two vectors (really, two indexable containers) are
 * equal element-wise to within some tolerance
 * @tparam T some iterable
 * @param v1 vector1
 * @param v2 vector2
 * @param tol float
 * @return
 */
template <typename T>
bool validateData(const T &v1, const T &v2, const float &tol = 0.0001) {
  if (v1.size() != v2.size()) {
    return false;
  }
  for (unsigned int i = 0; i < v1.size(); i++) {
    // do a scale check. Fails for numbers that are extremely close to 0.
    if (std::abs((v1[i] - v2[i]) / v1[i]) > tol) {
      // if the above fails, we assume it's close to 0 and we check that both
      // numbers are extremely small
      if (std::abs(v1[i] - v2[i]) > tol) {
        return false;
      }  // Pass ABSOLUTE CHECK: it's true and we continue
    }
  }
  return true;
}

/**
 * displayVectors - "zip" the two indexable containers and display them as pairs
 * of values
 * @tparam T - an indexable container
 * @param v1 - container 1
 * @param v2 - container 2
 */
template <typename T>
void displayVectors(T v1, T v2) {
  for (unsigned int i = 0; i < v1.size(); i++) {
    std::cout << v1[i] << "," << v2[i] << '\n';
  }
}

/////////////////////////////////////////////////////////////////
// Synchronization material
//  - uses a "lock" to move between the two processes
/////////////////////////////////////////////////////////////////

int display() {
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir(".")) != NULL) {
    /* print all the files and directories within directory */
    while ((ent = readdir(dir)) != NULL) {
      std::cout << ent->d_name << ',';
      auto v = ent->d_name;
      if (!(strcmp(v, ".") || strcmp(v, "..") || strcmp(v, ".idea"))) {
        std::cout << ent->d_name << ',';
      }
    }

    closedir(dir);
    return 1;
  } else {
    /* could not open directory */
    perror("");
    return EXIT_FAILURE;
  }
}
/** fExists: check if the lock already exists
 * @param filename
 * @return
 *  bool: if true then the lock already exists so the current query-er should
 * sleep if false then feel free to grab it
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

/**
 * acquireLock
 *  - "get" the lock. Do this by writing the file
 */
void acquireLock(const std::string &lockName) { std::ofstream file{lockName}; }

/**
 * releaseLock
 *  - "release" the lock by deleting the file which then allows the other
 * process to get it
 */
void releaseLock(const std::string &lockName) {
  char lockCharArr[lockName.length()];
  unsigned int i;
  for (i = 0; i < sizeof(lockCharArr); i++) {
    lockCharArr[i] = lockName[i];
  }
  std::remove(lockCharArr);
}

/**
 * Take a powernap of 0.5 seconds
 */
void nap(const int &ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}

#endif  // PALISADE_SRC_PKE_EXAMPLES_REAL_NUMBER_SERIALIZATION_CLIENT_SERVER_UTILS_H_
