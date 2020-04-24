/*
 * @file threshold-fhe.cpp  - Example of threshold FHE.
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
 *
 * @section DESCRIPTION
 * Demo software for PKE multiparty fusion operations for various schemes.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"

using namespace std;
using namespace lbcrypto;

//static const usint ORDER = 2048;
//static const usint PTM = 256;
//double currentDateTime();

int run_demo_fusion(string input);

void usage()
{
  std::cout << "-i (optional) run interactively to select parameters" << std::endl
			<< " <PARAMETER SET> to run with that parameter set" <<std::endl;
}

// trim whitespace from string from start (in place)
// code from to https://stackoverflow.com/a/44973498/524503 
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}
// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}
// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////
    bool interactive = false;
	string input = "";
	string progname = *argv;
	while( argc-- > 1 ) {
		string arg(*++argv);

		if( arg == "-help" || arg == "-?" ) {
			usage();
			return 0;
		}
		else if (arg == "-i"){
  		    interactive = true;
		}
		else if( arg[0] == '-' ) {
			usage();
			return(0);
			
		}else{
		  input = arg;
		}
	}
	std::cout << "This code shows how to use schemes and pre-computed parameters for those schemes that can be selected during run-time. " << std::endl;
	if (input.compare("") == 0) {
	  std::cout << "\nThis code demonstrates the use of multiple schemes for basic public key encryption fusion operations. " ;
	  std::cout << "This code shows how to use schemes and pre-computed parameters for those schemes can be selected during run-time. " ;
	  std::cout << "In this demonstration we encrypt data and then proxy re-encrypt it. " ;

	  std::cout << "\nThis demo can be run as "<<progname<<" <PARAMETER SET> " <<std::endl;
	  std::cout << "\nRunning this demo as "<<progname<<" ALL or without any parameters will run all schemes " <<std::endl;
	  std::cout << "\nRunning this demo as "<<progname<<" -i enters interactive mode " <<std::endl;
	  
	}
	std::cout << "time using Math backend "<<MATHBACKEND <<std::endl;

	std::ostringstream stream;
	//CryptoContextHelper::printParmSetNamesByExcludeFilter(stream,"BFVrns");
	CryptoContextHelper::printParmSetNamesByExcludeFilter(stream,"BFVrns");
	string parameter_set_list =  stream.str();

	
	//tokenize the string that lists parameters, separated by commas
	char delim = ','; // our delimiter
	std::istringstream ss(stream.str());
	std::string token;
	
	std::vector<std::string> tokens;
	while(std::getline(ss, token, delim)) {
	  //remove any leading or trailing whitespace from token
	  trim(token);
	  if (token.find("StSt") != std::string::npos){
		  //this is a kludge CryptoContextHelper::printParmSetNamesByExcludeFilter() needs to handle multiple exclusions. 
		  continue;
	  }
	  tokens.push_back(token);
	}
	

	if (interactive){ 
	  std::cout << "Choose parameter set: "<< parameter_set_list;
	  std::cout << "or enter ALL to run every set."<<std::endl;
 	  std::cin >> input;

	  
	  
	} else if (input.compare("")==0){ //input can be specified on the command line
	  input = "ALL";
	}

	if (input.compare("ALL")!=0) { //run a particular parameter set

	  //validate input
	  bool valid = false;
	  for(string param : tokens) {
		if (input.compare(param) == 0){
		  valid = true;
		  break;
		}
	  }
	  if (!valid) {
		std::cout<<"Error: "<< input <<" is not a valid parameter set."<<std::endl;
		std::cout<<"Valid sets are: "<<parameter_set_list;
		exit(1);
	  }
	  std::cout << "Running using parameter set: "<<input<<std::endl;
	  
	  
	  int rc= run_demo_fusion(input);

	  if (rc) { //there could be an error
		exit(1);
	  }
	} else { //run ALL parameter sets
	  // tokens contain the array of parameter name strings
	  for(string param : tokens) {
		std::cout << "Running using parameter set: "<<param<<std::endl;
		int rc= run_demo_fusion(param);

		if (rc) { //there could be an error
		  exit(1);	
		}
	  }
	}
	exit (0); //successful return
}

int run_demo_fusion(string input){
	//Generate parameters.
	double diff, start, finish;

	start = currentDateTime();

	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	if( !cc ) {
		cout << "Error using " << input << endl;
		return 1;
	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	//Turn on features
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);

	std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<Poly> kp1;
	LPKeyPair<Poly> kp2;
	LPKeyPair<Poly> kp3;

	LPKeyPair<Poly> kpMultiparty;

	LPEvalKey<Poly> evalKey1;
	LPEvalKey<Poly> evalKey2;
	LPEvalKey<Poly> evalKey3;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	kp1 = cc->KeyGen();
	kp2 = cc->MultipartyKeyGen(kp1.publicKey,false,true);
	kp3 = cc->MultipartyKeyGen(kp1.publicKey,false,true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kp1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp3.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Generating a Multiparty key..." << std::endl;

	start = currentDateTime();


	vector<LPPrivateKey<Poly>> secretKeys;
	secretKeys.push_back(kp1.secretKey);
	secretKeys.push_back(kp2.secretKey);
	secretKeys.push_back(kp3.secretKey);

	kpMultiparty = cc->MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kpMultiparty.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	start = currentDateTime();

	evalKey1 = cc->ReKeyGen(kpMultiparty.publicKey, kp1.secretKey);
	evalKey2 = cc->ReKeyGen(kpMultiparty.publicKey, kp2.secretKey);
	evalKey3 = cc->ReKeyGen(kpMultiparty.publicKey, kp3.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////
	std::vector<int64_t> vectorOfInts1 = {1,1,1,1,1,1,1,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts2 = {1,0,0,1,1,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};

	Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);
	Plaintext plaintext3 = cc->MakeCoefPackedPlaintext(vectorOfInts3);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	Ciphertext<Poly> ciphertext1;
	Ciphertext<Poly> ciphertext2;
	Ciphertext<Poly> ciphertext3;

	ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1);
	ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
	ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////


	start = currentDateTime();

	Ciphertext<Poly> ciphertext1New;
	Ciphertext<Poly> ciphertext2New;
	Ciphertext<Poly> ciphertext3New;

	ciphertext1New = cc->ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc->ReEncrypt(evalKey2, ciphertext2);
	ciphertext3New = cc->ReEncrypt(evalKey3, ciphertext3);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	Ciphertext<Poly> ciphertextAddNew12;
	Ciphertext<Poly> ciphertextAddVectNew;

	start = currentDateTime();

	ciphertextAddNew12 = cc->EvalAdd(ciphertext1New,ciphertext2New);
	ciphertextAddVectNew = cc->EvalAdd(ciphertextAddNew12,ciphertext3New);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encrypted Data Evaluation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	Plaintext plaintextAddNew;

	start = currentDateTime();

	cc->Decrypt(kpMultiparty.secretKey, ciphertextAddVectNew, &plaintextAddNew);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAddNew->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
	cout << plaintextAddNew << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data with Multiparty
	////////////////////////////////////////////////////////////

	Plaintext plaintextAddNew1;
	Plaintext plaintextAddNew2;
	Plaintext plaintextAddNew3;

	Poly partialPlaintext1;
	Poly partialPlaintext2;
	Poly partialPlaintext3;

	Plaintext plaintextMultipartyNew;

	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();

	start = currentDateTime();

	auto ciphertextPartial1 = cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAddVectNew});
	auto ciphertextPartial2 = cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAddVectNew});
	auto ciphertextPartial3 = cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextAddVectNew});

	vector<Ciphertext<Poly>> partialCiphertextVec;
	partialCiphertextVec.push_back(ciphertextPartial1[0]);
	partialCiphertextVec.push_back(ciphertextPartial2[0]);
	partialCiphertextVec.push_back(ciphertextPartial3[0]);

	cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	cout << "\n Original Plaintext (note trailing zero terms are elided): \n" << endl;
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	plaintextMultipartyNew->SetLength(plaintext1->GetLength());

	cout << "\n Resulting Fused Plaintext with Re-Encryption: \n" << endl;
	cout << plaintextMultipartyNew << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	//std::cout << "Execution Completed. Press any key to continue." << std::endl;

	//std::cin.get();

	return 0;

}
