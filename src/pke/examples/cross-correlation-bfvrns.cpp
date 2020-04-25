/*
 * @file cross-correlation-bfvrns.cpp Code that demonstrates the use of serialization, DCRT, arbitrary cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
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
 * Commands to run
 *
 *
 */

#include <iostream>
#include <fstream>


#include "palisade.h"

#include "utils/serialize-binary.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include <random>

#include "../../core/lib/math/matrix.cpp"

using namespace std;
using namespace lbcrypto;

#include <iterator>

void KeyGen();
void Encrypt();
void Compute();
void Decrypt();
NativeInteger CRTInterpolate(const std::vector<Plaintext> &crtVector);
template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector);

// number of primitive prime plaintext moduli in the CRT representation of plaintext
const size_t SIZE = 3;
const size_t VECTORS = 30;
const std::string DATAFOLDER = "demoData";


int main(int argc, char* argv[]) {
#ifdef NO_QUADMATH
    std::cout << "This demo uses BFVrns which is currently not available for this architecture"<<std::endl;
	exit(0);
#endif
	if (argc < 2) { // called with no arguments
		std::cout << "Usage is `" << argv[0] << " arg1 ' where: " << std::endl;
		std::cout << "  arg1 can be one of the following: keygen, encrypt, compute, or decrypt" << std::endl;
	}


	if (argc == 2) {

		if (std::string(argv[1]) == "keygen")
			KeyGen();
		else {
			if (std::string(argv[1]) == "encrypt")
				Encrypt();
			else if (std::string(argv[1]) == "compute")
				Compute();
			else if (std::string(argv[1]) == "decrypt")
				Decrypt();
			else {
				std::cerr << "the argument is invalid";
				return 1;
			}
		}
	}

	PackedEncoding::Destroy();

	return 0;
}


void KeyGen()
{

	size_t batchSize = 1024;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	for (size_t k = 0; k < SIZE; k++) {

		PlaintextModulus p;

		// the values of prime p that satisfy 8192 | (p-1)
		switch (k) {
		case 0:
			p = 40961;
			break;
		case 1:
			p = 65537;
			break;
		case 2:
			p = 114689;
			break;
		}

		BigInteger modulusP(p);

		std::cout << "\nKEY GENERATION AND SERIALIZATION FOR p = " << p << "\n" << std::endl;

		EncodingParams encodingParams(new EncodingParamsImpl(p));

		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
				encodingParams, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,2,30,60);

		uint32_t m = cc->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);
		encodingParams->SetBatchSize(batchSize);

		std::cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "n = " << m / 2 << std::endl;
		std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		////////////////////////////////////////////////////////////
		//Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if (kp.publicKey && kp.secretKey) {

			if (!Serial::SerializeToFile(DATAFOLDER + "/" + "key-public" + std::to_string(k) + ".txt", kp.publicKey, SerType::BINARY)) {
				cerr << "Error writing serialization of public key to key-public" + std::to_string(k) + ".txt" << endl;
				return;
			}

			if (!Serial::SerializeToFile(DATAFOLDER + "/" +"key-private" + std::to_string(k) + ".txt", kp.secretKey, SerType::BINARY)) {
				cerr << "Error writing serialization of private key to key-private" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		// EvalMultKey

		std::cout << "Generating multiplication evaluation key...";

		cc->EvalMultKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// EvalSumKey

		std::cout << "Generating summation evaluation keys...";

		cc->EvalSumKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// CryptoContext

		std::cout << "Serializing crypto context...";

		if (!Serial::SerializeToFile(DATAFOLDER + "/" + "cryptocontext" + std::to_string(k) + ".txt", cc, SerType::BINARY)) {
			cerr << "Error writing serialization of the crypto context to cryptocontext" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Serializing evaluation keys...";

		ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult" + std::to_string(k) + ".txt", std::ios::out|std::ios::binary);
		if( emkeyfile.is_open() ) {
			if( cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false ) {
				cerr << "Error writing serialization of the eval mult keys to key-eval-mult" + std::to_string(k) + ".txt" << endl;
				return;
			}
			emkeyfile.close();
		}
		else {
			cerr << "Error serializing eval mult keys" << endl;
			return;
		}

		ofstream eskeyfile(DATAFOLDER + "/" + "key-eval-sum" + std::to_string(k) + ".txt", std::ios::out|std::ios::binary);
		if( eskeyfile.is_open() ) {
			if( cc->SerializeEvalSumKey(eskeyfile, SerType::BINARY) == false ) {
				cerr << "Error writing serialization of the eval sum keys to key-eval-sum" + std::to_string(k) + ".txt" << endl;
				return;
			}
			eskeyfile.close();
		}
		else {
			cerr << "Error serializing eval sum keys" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Encrypt() {

	size_t batchSize = 1024;

	auto singleAlloc = [=]() { return 0; };

	Matrix<uint64_t> x(singleAlloc, VECTORS, batchSize);
	Matrix<uint64_t> y(singleAlloc, VECTORS, batchSize);

	DiscreteUniformGenerator dug;
	dug.SetModulus(BigInteger(8191));

	//create the dataset for processing
	for (size_t i = 0; i < VECTORS; i++)
	{
		BigVector randomVectorX = dug.GenerateVector(batchSize);
		BigVector randomVectorY = dug.GenerateVector(batchSize);
		for (size_t j = 0; j < batchSize; j++) {
			x(i, j) = randomVectorX.at(j).ConvertToInt();
			y(i, j) = randomVectorY.at(j).ConvertToInt();
		}
	}

	auto product = x * y.Transpose();
	uint64_t result = 0;

	for (size_t i = 0; i < VECTORS; i++)
	{
		result += product(i,i);
	}

	std::cout << "Result of plaintext computation is " << result << std::endl;

	// Key deserialization is done here

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/ENCRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";
		string pkFileName = "key-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cc;
		if ( !Serial::DeserializeFromFile(DATAFOLDER + "/" + ccFileName, cc, SerType::BINARY) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		if( !cc ) {
			cerr << "Could not deserialize a context" << endl;
			return;
		}

		std::ifstream emkeys(DATAFOLDER + "/" + emFileName, std::ios::in|std::ios::binary);
		if( !emkeys.is_open() ) {
			cerr << "Could not read the eval mult key file " << endl;
			return;
		}

		std::ifstream eskeys(DATAFOLDER + "/" + esFileName, std::ios::in|std::ios::binary);
		if( !eskeys.is_open() ) {
			cerr << "Could not read the eval sum key file" << endl;
			return;
		}

		if( cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval mult key file" << endl;
			return;
		}

		if( cc->DeserializeEvalSumKey(eskeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval sum key file" << endl;
			return;
		}

		emkeys.close();
		eskeys.close();

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		//std::cout << "plaintext modulus = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;

		// Deserialize the public key

		std::cout << "Deserializing the public key...";

		LPPublicKey<DCRTPoly> pk;
		if (Serial::DeserializeFromFile(DATAFOLDER + "/" + pkFileName, pk, SerType::BINARY) == false) {
			cerr << "Could not read public key" << endl;
			return;
		}

		if (!pk) {
			cerr << "Could not deserialize public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Encoding the data...";

		auto zeroAlloc = [=]() { return cc->MakePackedPlaintext({0}); };

		Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, VECTORS, 1);
		Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, VECTORS, 1);

		for (size_t i = 0; i < VECTORS; i++)
		{
			std::vector<int64_t> tempX(batchSize);
			std::vector<int64_t> tempY(batchSize);
			for (size_t j = 0; j < batchSize; j++)
			{
				tempX[j] = x(i, j);
				tempY[j] = y(i, j);
			}
			xP(i,0) = cc->MakePackedPlaintext(tempX);
			yP(i,0) = cc->MakePackedPlaintext(tempY);
		}

		std::cout << "Completed" << std::endl;

		// Packing and encryption

		std::cout << "Batching/encrypting X..." << std::flush;

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xC = cc->EncryptMatrix(pk, xP);

		std::cout << "Completed" << std::endl;

		std::cout << "Batching/encrypting Y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yC = cc->EncryptMatrix(pk, yP);

		std::cout << "Completed" << std::endl;

		//Serialization
		std::cout << "Serializing X...";

		if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext-x-" + std::to_string(k) + ".txt", xC, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X to " << "ciphertext-x-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing y...";

		if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext-y-" + std::to_string(k) + ".txt", yC, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext y to " << "ciphertext-y-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}


}

void Compute() {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nCOMPUTATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc;
		if ( !Serial::DeserializeFromFile(DATAFOLDER + "/" + ccFileName, cc, SerType::BINARY) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		std::ifstream emkeys(DATAFOLDER + "/" + emFileName, std::ios::in|std::ios::binary);
		if( !emkeys.is_open() ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + emFileName << endl;
			return;
		}

		std::ifstream eskeys(DATAFOLDER + "/" + esFileName, std::ios::in|std::ios::binary);
		if( !eskeys.is_open() ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + esFileName << endl;
			return;
		}

		if( cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval mult key file" << endl;
			return;
		}

		if( cc->DeserializeEvalSumKey(eskeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval sum key file" << endl;
			return;
		}

		emkeys.close();
		eskeys.close();

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();

		// Deserialize X

		string xFileName = DATAFOLDER + "/" +  "ciphertext-x-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing vector x...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> x(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(xFileName, x, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X" << endl;
			return;
		}

		x->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize y

		string yFileName = DATAFOLDER + "/" +  "ciphertext-y-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing vector y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> y(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(yFileName, y, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext y" << endl;
			return;
		}

		y->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Compute cross-correlation

		std::cout << "Computing the cross-correlation ...";

		double start, finish;

		start = currentDateTime();

		Ciphertext<DCRTPoly> result = cc->EvalCrossCorrelation(x,y,batchSize);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "Cross-correlation computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		std::cout << "Average inner product computation time: " << "\t" << (finish - start)/VECTORS << " ms" << std::endl;

		// Serialize cross-correlation

		std::cout << "Serializing cross-correlation...";

		if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext-cc-" + std::to_string(k) + ".txt", result, SerType::BINARY)) {
			cerr << "Error writing serialization of cross-correlation ciphertext to " << "ciphertext-cc-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Decrypt() {

	std::vector<Plaintext> crossCorr;

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/DECRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";
		string skFileName = "key-private" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc;
		if ( !Serial::DeserializeFromFile(DATAFOLDER + "/" + ccFileName, cc, SerType::BINARY) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		std::ifstream emkeys(DATAFOLDER + "/" + emFileName, std::ios::in|std::ios::binary);
		if( !emkeys.is_open() ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + emFileName << endl;
			return;
		}

		std::ifstream eskeys(DATAFOLDER + "/" + esFileName, std::ios::in|std::ios::binary);
		if( !eskeys.is_open() ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + esFileName << endl;
			return;
		}

		if( cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval mult key file" << endl;
			return;
		}

		if( cc->DeserializeEvalSumKey(eskeys, SerType::BINARY) == false ) {
			cerr << "Could not deserialize the eval sum key file" << endl;
			return;
		}

		emkeys.close();
		eskeys.close();

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		
		// Deserialize the private key

		std::cout << "Deserializing the private key...";

		LPPrivateKey<DCRTPoly> sk;
		if (Serial::DeserializeFromFile(DATAFOLDER + "/" + skFileName, sk, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!sk) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize cross-correlation

		string cFileName = DATAFOLDER + "/" + "ciphertext-cc-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing cross-correlation..";

		Ciphertext<DCRTPoly> c((new CiphertextImpl<DCRTPoly>(cc)));
		if (Serial::DeserializeFromFile(cFileName, c, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext" << endl;
			return;
		}

		if (!c) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Decrypt cross-correlation

		std::cout << "Decrypting cross-correlation...";

		Plaintext ccResult;

		cc->Decrypt(sk, c, &ccResult);

		std::cout << "Completed" << std::endl;

		//std::cout << ccResult << std::endl;

		crossCorr.push_back(ccResult);

	}

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plainext modulus...";

	NativeInteger result = CRTInterpolate(crossCorr);

	std::cout << "Completed" << std::endl;

	std::cout << "Ciphertext result: " << result << std::endl;

}

NativeInteger CRTInterpolate(const std::vector<Plaintext> &crtVector) {

	NativeInteger result(0);

	std::vector<NativeInteger> q = { 40961, 65537, 114689 };

	NativeInteger Q(1);

	for (size_t i = 0; i < crtVector.size(); i++) {
		Q = Q*q[i];
	}

	std::vector<NativeInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++) {
		qInverse.push_back((Q / q[i]).ModInverse(q[i]));
	}

	for (size_t i = 0; i < crtVector.size(); i++) {
		NativeInteger value;
		if ((crtVector[i]->GetPackedValue()[0]) < 0)
			value = NativeInteger(q[i]-NativeInteger((uint64_t)std::llabs(crtVector[i]->GetPackedValue()[0])));
		else
			value = NativeInteger(crtVector[i]->GetPackedValue()[0]);

		result += ((value*qInverse[i]).Mod(q[i])*(Q / q[i])).Mod(Q);
	}

	return result.Mod(Q);

}

template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector) {

	output << "[";

	for (unsigned int i = 0; i < vector.size(); i++) {

		if (i > 0) {
			output << ", ";
		}

		output << vector[i];
	}

	output << "]";
	return output;
}
