/*
 * @file json.cpp - Serialization example.
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @section LICENSE
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
 * @section DESCRIPTION
 * Demo software for BFV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"

#include "utils/serialize-json.h"
#include "scheme/bfv/bfv-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"

using namespace std;
using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

void
keymaker(CryptoContext<Poly> ctx, string keyname)
{

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = ctx->KeyGen();

	if( kp.publicKey && kp.secretKey ) {

		if( !Serial::SerializeToFile(DATAFOLDER + "/" + keyname + "PUB.txt", kp.publicKey, SerType::JSON) ) {
			cerr << "Error writing serialization of public key to " + keyname + "PUB.txt" << endl;
			return;
		}

		if( !Serial::SerializeToFile(DATAFOLDER + "/" + keyname + "PRI.txt", kp.secretKey, SerType::JSON) ) {
			cerr << "Error writing serialization of private key to " + keyname + "PRI.txt" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	return;
}


void
encrypter(CryptoContext<Poly> ctx, Plaintext iPlaintext, string pubkeyname, string ciphertextname)
{

	ofstream ctSer(DATAFOLDER + "/" + ciphertextname, ios::binary);

	// Initialize the public key containers.
	LPPublicKey<Poly> pk;
	if( Serial::DeserializeFromFile(DATAFOLDER + "/" + pubkeyname, pk, SerType::JSON) == false ) {
		cerr << "Could not read public key" << endl;
		return;
	}

	if( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		ctSer.close();
		return;
	}

	// now encrypt iPlaintext
	auto ciphertext = ctx->Encrypt(pk, iPlaintext);

	if( !Serial::SerializeToFile(DATAFOLDER + "/" + ciphertextname, ciphertext, SerType::JSON) ) {
		cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
		return;
	}

	return;
}


Plaintext
decrypter(CryptoContext<Poly> ctx, string ciphertextname, string prikeyname)
{
	Plaintext iPlaintext;

	LPPrivateKey<Poly> sk;
	if( Serial::DeserializeFromFile(DATAFOLDER + "/" + prikeyname, sk, SerType::JSON) == false ) {
		cerr << "Could not read private key" << endl;
		return iPlaintext;
	}

	if( !sk ) {
		cerr << "Could not deserialize private key" << endl;
		return iPlaintext;
	}

	Ciphertext<Poly> ct;
	if( Serial::DeserializeFromFile(DATAFOLDER + "/" + ciphertextname, ct, SerType::JSON) == false ) {
		cerr << "Could not read ciphertext" << endl;
		return iPlaintext;
	}

	// now decrypt iPlaintext
	ctx->Decrypt(sk, ct, &iPlaintext);

	return iPlaintext;
}

int main(int argc, char *argv[])
{

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code demonstrates a simple use of json serialization for BFV schemes with public key encryption. " << std::endl;
	std::cout << "This code creates and saves keys to disk, loads the keys from disk, encrypts data and saves ciphertext to disk. " << std::endl;
	std::cout << "The code then loads the ciphertext from disk and decrypts. " << std::endl;

	int relWindow = 1;
	int plaintextModulus = 64;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextBFV(
	            plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 1, 0);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	string keyFileName = "demo_json_key";
	string keyFileNamePublic = "demo_json_keyPUB.txt";
	string keyFileNamePrivate = "demo_json_keyPRI.txt";

	keymaker(cryptoContext, keyFileName);

	std::vector<int64_t> vectorOfInts1 = {3,1,4,2,1,1,0,1,0,0,0,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	std::vector<int64_t> vectorOfInts2 = {1,1,1,0,1,1,0,1,0,0,0,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	string ciphertextFileName1 = "ciphertext1.txt";
	string ciphertextFileName2 = "ciphertext2.txt";

	encrypter(cryptoContext, plaintext1, keyFileNamePublic, ciphertextFileName1);
	encrypter(cryptoContext, plaintext2, keyFileNamePublic, ciphertextFileName2);
	
	Plaintext plaintext1_dec;
	Plaintext plaintext2_dec;

	plaintext1_dec = decrypter(cryptoContext, ciphertextFileName1, keyFileNamePrivate);
	plaintext2_dec = decrypter(cryptoContext, ciphertextFileName2, keyFileNamePrivate);

	plaintext1_dec->SetLength(plaintext1->GetLength());
	plaintext2_dec->SetLength(plaintext2->GetLength());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintext1_dec << endl;
	cout << plaintext2_dec << endl;

	return 0;
}
