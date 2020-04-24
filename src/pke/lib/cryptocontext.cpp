/*
 * @file cryptocontext.cpp -- Control for encryption operations.
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
 */

#include "cryptocontext.h"
#include "utils/serial.h"

namespace lbcrypto {

template <typename Element>
std::map<string,std::vector<LPEvalKey<Element>>>					CryptoContextImpl<Element>::evalMultKeyMap;

template <typename Element>
std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	CryptoContextImpl<Element>::evalSumKeyMap;

template <typename Element>
std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	CryptoContextImpl<Element>::evalAutomorphismKeyMap;

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeyGen(const LPPrivateKey<Element> key) {

	if( key == NULL || Mismatched(key->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Key passed to EvalMultKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	LPEvalKey<Element> k = GetEncryptionAlgorithm()->EvalMultKeyGen(key);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

	evalMultKeyMap[ k->GetKeyTag() ] = { k };
}

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeysGen(const LPPrivateKey<Element> key) {

	if( key == NULL || Mismatched(key->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Key passed to EvalMultsKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	const vector<LPEvalKey<Element>> &evalKeys = GetEncryptionAlgorithm()->EvalMultKeysGen(key);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

	evalMultKeyMap[ evalKeys[0]->GetKeyTag() ] = evalKeys;
}

template <typename Element>
const vector<LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalMultKeyVector(const string& keyID) {
	auto ekv = evalMultKeyMap.find(keyID);
	if( ekv == evalMultKeyMap.end() )
		PALISADE_THROW(not_available_error, "You need to use EvalMultKeyGen so that you have an EvalMultKey available for this ID");
	return ekv->second;
}

template <typename Element>
const std::map<string,std::vector<LPEvalKey<Element>>>& CryptoContextImpl<Element>::GetAllEvalMultKeys() {
	return evalMultKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys() {
	evalMultKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const string& id) {
	auto kd = evalMultKeyMap.find(id);
	if( kd != evalMultKeyMap.end() )
		evalMultKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const CryptoContext<Element> cc) {
	for( auto it = evalMultKeyMap.begin(); it != evalMultKeyMap.end(); ) {
		if( it->second[0]->GetCryptoContext() == cc ) {
			it = evalMultKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(const std::vector<LPEvalKey<Element>>& vectorToInsert) {
	evalMultKeyMap[ vectorToInsert[0]->GetKeyTag() ] = vectorToInsert;
}

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(
		const LPPrivateKey<Element> privateKey,
		const LPPublicKey<Element> publicKey) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		PALISADE_THROW(config_error, "Private key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		PALISADE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumKeyGen(privateKey,publicKey);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumKeyGen, currentDateTime() - start) );
	}
	evalSumKeyMap[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> CryptoContextImpl<Element>::EvalSumRowsKeyGen(
	const LPPrivateKey<Element> privateKey,
	const LPPublicKey<Element> publicKey, usint rowSize) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		PALISADE_THROW(config_error, "Private key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		PALISADE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumRowsKeyGen(privateKey,publicKey,rowSize);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumRowsKeyGen, currentDateTime() - start) );
	}

	return evalKeys;
}

template <typename Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> CryptoContextImpl<Element>::EvalSumColsKeyGen(
	const LPPrivateKey<Element> privateKey,
	const LPPublicKey<Element> publicKey) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		PALISADE_THROW(config_error, "Private key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		PALISADE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumColsKeyGen(privateKey,publicKey);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumColsKeyGen, currentDateTime() - start) );
	}

	return evalKeys;
}

template <typename Element>
const std::map<usint, LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalSumKeyMap(const string& keyID) {
	auto ekv = evalSumKeyMap.find(keyID);
	if( ekv == evalSumKeyMap.end() )
		PALISADE_THROW(not_available_error, "You need to use EvalSumKeyGen so that you have EvalSumKeys available for this ID");
	return *ekv->second;
}

template <typename Element>
const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& CryptoContextImpl<Element>::GetAllEvalSumKeys() {
	return evalSumKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys() {
	evalSumKeyMap.clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const string& id) {
	auto kd = evalSumKeyMap.find(id);
	if( kd != evalSumKeyMap.end() )
		evalSumKeyMap.erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const CryptoContext<Element> cc) {
	for( auto it = evalSumKeyMap.begin(); it != evalSumKeyMap.end(); ) {
		if( it->second->begin()->second->GetCryptoContext() == cc ) {
			it = evalSumKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalSumKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert) {
	// find the tag
	auto onekey = mapToInsert->begin();
	evalSumKeyMap[ onekey->second->GetKeyTag() ] = mapToInsert;
}

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<int32_t> &indexList, const LPPublicKey<Element> publicKey) {

	if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) ) {
		PALISADE_THROW(config_error, "Private key passed to EvalAtIndexKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && privateKey->GetKeyTag() != publicKey->GetKeyTag() ) {
		PALISADE_THROW(config_error, "Public key passed to EvalAtIndexKeyGen does not match private key");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalAtIndexKeyGen(publicKey,privateKey,indexList);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalAtIndexKeyGen, currentDateTime() - start) );
	}

	evalAutomorphismKeyMap[privateKey->GetKeyTag()] = evalKeys;
}


template <typename Element>
const std::map<usint, LPEvalKey<Element>>& CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(const string& keyID) {
	auto ekv = evalAutomorphismKeyMap.find(keyID);
	if( ekv == evalAutomorphismKeyMap.end() )
		PALISADE_THROW(not_available_error, "You need to use EvalAutomorphismKeyGen so that you have EvalAutomorphismKeys available for this ID");
	return *ekv->second;
}

template <typename Element>
const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys() {
	return evalAutomorphismKeyMap;
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys() {
	evalAutomorphismKeyMap.clear();
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const string& id) {
	auto kd = evalAutomorphismKeyMap.find(id);
	if( kd != evalAutomorphismKeyMap.end() )
		evalAutomorphismKeyMap.erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const CryptoContext<Element> cc) {
	for( auto it = evalAutomorphismKeyMap.begin(); it != evalAutomorphismKeyMap.end(); ) {
		if( it->second->begin()->second->GetCryptoContext() == cc ) {
			it = evalAutomorphismKeyMap.erase(it);
		}
		else
			++it;
	}
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert) {
	// find the tag
	auto onekey = mapToInsert->begin();
	evalAutomorphismKeyMap[ onekey->second->GetKeyTag() ] = mapToInsert;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalSum was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSum, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
		const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalSum was not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSumRows(ciphertext, rowSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumRows, currentDateTime() - start) );
	}
	return rv;
}


template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumCols(ConstCiphertext<Element> ciphertext, usint rowSize,
		const std::map<usint, LPEvalKey<Element>> &evalSumKeysRight) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalSum was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSumCols(ciphertext, rowSize, evalSumKeys, evalSumKeysRight);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumCols, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const {

	if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalAtIndex was not generated with this crypto context");

	auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalAtIndex(ciphertext, index, evalAutomorphismKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalAtIndex, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalMerge(const vector<Ciphertext<Element>> &ciphertextVector) const {

	if( ciphertextVector[0] == NULL || Mismatched(ciphertextVector[0]->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalMerge was not generated with this crypto context");

	auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertextVector[0]->GetKeyTag());
	double start = 0;
	if( doTiming ) start = currentDateTime();

	auto rv = GetEncryptionAlgorithm()->EvalMerge(ciphertextVector, evalAutomorphismKeys);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMerge, currentDateTime() - start) );
	}

	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || ct1->GetKeyTag() != ct2->GetKeyTag() ||
			Mismatched(ct1->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalInnerProduct was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());
	auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstPlaintext ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || Mismatched(ct1->GetCryptoContext()) )
		PALISADE_THROW(config_error, "Information passed to EvalInnerProduct was not generated with this crypto context");

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
Ciphertext<Element>
CryptoContextImpl<Element>::EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
		usint indexStart, usint length) const {

	//need to add exception handling

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
	auto ek = GetEvalMultKeyVector((*x)(0,0).GetNumerator()->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalCrossCorrelation, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Matrix<RationalCiphertext<Element>>>
CryptoContextImpl<Element>::EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const
		{
	//need to add exception handling

	auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap((*x)(0,0).GetNumerator()->GetKeyTag());
	auto ek = GetEvalMultKeyVector((*x)(0,0).GetNumerator()->GetKeyTag());

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, ek[0]);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalLinRegressionBatched, currentDateTime() - start) );
	}
	return rv;
}

}
