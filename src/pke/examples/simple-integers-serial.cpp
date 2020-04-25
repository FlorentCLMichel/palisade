/*
 * @file  simple-integers-serial.cpp - Simple example for BFVrns (integer arithmetic) with serialization.
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "palisade.h"

// header files needed for serialization
#include "utils/serialize-binary.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main()
{
  #ifdef NO_QUADMATH
  std::cout << "This demo uses BFVrns which is currently not available for this architecture"<<std::endl;
  exit(0);
#endif
    // Sample Program: Step 1 � Set CryptoContext

	// Set the main parameters
	int plaintextModulus = 65537;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;

	// Instantiate the crypto context
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

	// Enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	cout << "\nThe cryptocontext has been generated." << std::endl;

	// Serialize cryptocontext
	if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
		cerr << "Error writing serialization of the crypto context to cryptocontext.txt" << endl;
		return 1;
	}
	else
		cout << "The cryptocontext has been serialized." << std::endl;

	// Deserialize the crypto context
	CryptoContext<DCRTPoly> cc;
	if ( !Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY) ) {
		cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << endl;
		return 1;
	}
	else
		cout << "The cryptocontext has been deserialized." << std::endl;

	//Sample Program: Step 2 � Key Generation

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	// Generate a public/private key pair
	keyPair = cc->KeyGen();

	cout << "The key pair has been generated." << std::endl;

	// Serialize the public key
	if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
		cerr << "Error writing serialization of public key to key-public.txt" << endl;
		return 1;
	}
	else
		cout << "The public key has been serialized." << std::endl;

	// Serialize the secret key
	if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
		cerr << "Error writing serialization of private key to key-private.txt" << endl;
		return 1;
	}
	else
		cout << "The secret key has been serialized." << std::endl;

	// Generate the relinearization key
	cc->EvalMultKeyGen(keyPair.secretKey);

	cout << "The eval mult keys have been generated." << std::endl;

	// Serialize the relinearization (evaluation) key for homomorphic multiplication
	ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out|std::ios::binary);
	if( emkeyfile.is_open() ) {
		if( cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false ) {
			cerr << "Error writing serialization of the eval mult keys to key-eval-mult.txt" << endl;
			return 1;
		}
		else
			cout << "The eval mult keys have been serialized." << std::endl;

		emkeyfile.close();
	}
	else {
		cerr << "Error serializing eval mult keys" << endl;
		return 1;
	}

	// Generate the rotation evaluation keys
	cc->EvalAtIndexKeyGen(keyPair.secretKey,{1,2,-1,-2});

	cout << "The rotation keys have been generated." << std::endl;

	// Serialize the rotation keyhs
	ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out|std::ios::binary);
	if( erkeyfile.is_open() ) {
		if( cc->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false ) {
			cerr << "Error writing serialization of the eval rotation keys to key-eval-rot.txt" << endl;
			return 1;
		}
		else
			cout << "The eval rotation keys have been serialized." << std::endl;

		erkeyfile.close();
	}
	else {
		cerr << "Error serializing eval rotation keys" << endl;
		return 1;
	}

	//Sample Program: Step 3 � Encryption

	// First plaintext vector is encoded
	std::vector<int64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
	// Second plaintext vector is encoded
	std::vector<int64_t> vectorOfInts2 = {3,2,1,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
	// Third plaintext vector is encoded
	std::vector<int64_t> vectorOfInts3 = {1,2,5,2,5,6,7,8,9,10,11,12};
	Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);

	cout << "Plaintext #1: " << plaintext1 << std::endl;
	cout << "Plaintext #2: " << plaintext2 << std::endl;
	cout << "Plaintext #3: " << plaintext3 << std::endl;

	LPPublicKey<DCRTPoly> pk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
		cerr << "Could not read public key" << endl;
		return 1;
	}
	else
		cout << "The public key has been deserialized." << std::endl;

	// The encoded vectors are encrypted
	auto ciphertext1 = cc->Encrypt(pk, plaintext1);
	auto ciphertext2 = cc->Encrypt(pk, plaintext2);
	auto ciphertext3 = cc->Encrypt(pk, plaintext3);

	cout << "The plaintexts have been encrypted." << std::endl;

	if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext1.txt", ciphertext1, SerType::BINARY)) {
		cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << endl;
		return 1;
	}
	else
		cout << "The first ciphertext has been serialized." << std::endl;

	Ciphertext<DCRTPoly> ct1;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext1.txt", ct1, SerType::BINARY) == false) {
		cerr << "Could not read the ciphertext" << endl;
		return 1;
	}
	else
		cout << "The first ciphertext has been deserialized." << std::endl;

	//Sample Program: Step 4 � Evaluation

	// Removing evaluation keys stored in the current cryptocontext
	// so we could load them from file
	cc->ClearEvalMultKeys();
	cc->ClearEvalAutomorphismKeys();

	std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in|std::ios::binary);
	if( !emkeys.is_open() ) {
		cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << endl;
		return 1;
	}
	if( cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false ) {
		cerr << "Could not deserialize the eval mult key file" << endl;
		return 1;
	}
	cout << "Deserialized the eval mult keys." << std::endl;

	std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in|std::ios::binary);
	if( !erkeys.is_open() ) {
		cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << endl;
		return 1;
	}
	if( cc->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false ) {
		cerr << "Could not deserialize the eval rotation key file" << endl;
		return 1;
	}
	cout << "Deserialized the eval rotation keys." << std::endl;

	// Homomorphic additions
	auto ciphertextAdd12 = cc->EvalAdd(ct1,ciphertext2);
	auto ciphertextAddResult = cc->EvalAdd(ciphertextAdd12,ciphertext3);

	// Homomorphic multiplications
	auto ciphertextMul12 = cc->EvalMult(ct1,ciphertext2);
	auto ciphertextMultResult = cc->EvalMult(ciphertextMul12,ciphertext3);

	// Homomorphic rotations
	auto ciphertextRot1 = cc->EvalAtIndex(ct1,1);
	auto ciphertextRot2 = cc->EvalAtIndex(ct1,2);
	auto ciphertextRot3 = cc->EvalAtIndex(ct1,-1);
	auto ciphertextRot4 = cc->EvalAtIndex(ct1,-2);

	//Sample Program: Step 5 � Decryption

	LPPrivateKey<DCRTPoly> sk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk, SerType::BINARY) == false) {
		cerr << "Could not read secret key" << endl;
		return 1;
	}
	else
		cout << "The secret key has been deserialized." << std::endl;

	// Decrypt the result of additions
	Plaintext plaintextAddResult;
	cc->Decrypt(sk, ciphertextAddResult, &plaintextAddResult);

	// Decrypt the result of multiplications
	Plaintext plaintextMultResult;
	cc->Decrypt(sk, ciphertextMultResult, &plaintextMultResult);

	// Decrypt the result of rotations
	Plaintext plaintextRot1;
	cc->Decrypt(sk, ciphertextRot1, &plaintextRot1);
	Plaintext plaintextRot2;
	cc->Decrypt(sk, ciphertextRot2, &plaintextRot2);
	Plaintext plaintextRot3;
	cc->Decrypt(sk, ciphertextRot3, &plaintextRot3);
	Plaintext plaintextRot4;
	cc->Decrypt(sk, ciphertextRot4, &plaintextRot4);

	// Shows only the same number of elements as in the original plaintext vector
	// By default it will show all coefficients in the BFV-encoded polynomial
	plaintextRot1->SetLength(vectorOfInts1.size());
	plaintextRot2->SetLength(vectorOfInts1.size());
	plaintextRot3->SetLength(vectorOfInts1.size());
	plaintextRot4->SetLength(vectorOfInts1.size());

	// Output results
	cout << "\nResults of homomorphic computations" << endl;
	cout << "#1 + #2 + #3: " << plaintextAddResult << endl;
	cout << "#1 * #2 * #3: " << plaintextMultResult << endl;
	cout << "Left rotation of #1 by 1: " << plaintextRot1 << endl;
	cout << "Left rotation of #1 by 2: " << plaintextRot2 << endl;
	cout << "Right rotation of #1 by 1: " << plaintextRot3 << endl;
	cout << "Right rotation of #1 by 2: " << plaintextRot4 << endl;

	return 0;
}
