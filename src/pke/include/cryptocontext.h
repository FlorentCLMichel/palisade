/**
 * @file cryptocontext.h -- Control for encryption operations.
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

#ifndef SRC_PKE_CRYPTOCONTEXT_H_
#define SRC_PKE_CRYPTOCONTEXT_H_

#include "palisade.h"
#include "scheme/allscheme.h"
#include "cryptocontexthelper.h"
#include "cryptotiming.h"

#include "utils/serial.h"
#include "utils/serialize-binary.h"
#include "utils/serialize-json.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextFactory;

template<typename Element>
class CryptoContextImpl;

template<typename Element>
using CryptoContext = shared_ptr<CryptoContextImpl<Element>>;

/**
 * @brief CryptoContextImpl
 *
 * A CryptoContextImpl is the object used to access the PALISADE library
 *
 * All PALISADE functionality is accessed by way of an instance of a CryptoContextImpl; we say that various objects are
 * "created in" a context, and can only be used in the context in which they were created
 *
 * All PALISADE methods are accessed through CryptoContextImpl methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using the CryptoContextFactory, and can be serialized and recovered from a serialization
 */
template<typename Element>
class CryptoContextImpl : public Serializable {
	friend class CryptoContextFactory<Element>;

protected:
	shared_ptr<LPCryptoParameters<Element>>				params;			/*!< crypto parameters used for this context */
	shared_ptr<LPPublicKeyEncryptionScheme<Element>>	scheme;			/*!< algorithm used; accesses all crypto methods */

	static std::map<string,std::vector<LPEvalKey<Element>>>					evalMultKeyMap;	/*!< cached evalmult keys, by secret key UID */
	static std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	evalSumKeyMap;	/*!< cached evalsum keys, by secret key UID */
	static std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	evalAutomorphismKeyMap;	/*!< cached evalautomorphism keys, by secret key UID */

	bool doTiming;
	vector<TimingInfo>* timeSamples;

	string m_schemeId;

	size_t m_keyGenLevel;


	/**
	 * TypeCheck makes sure that an operation between two ciphertexts is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(ConstCiphertext<Element> a, ConstCiphertext<Element> b) const {
		if( a == NULL || b == NULL )
			PALISADE_THROW( type_error, "Null Ciphertext");
		if( a->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContext");
		if( a->GetCryptoContext() != b->GetCryptoContext() )
			PALISADE_THROW( type_error, "Ciphertexts were not created in the same CryptoContext");
		if( a->GetKeyTag() != b->GetKeyTag() )
			PALISADE_THROW( type_error, "Ciphertexts were not encrypted with same keys" );
		if( a->GetEncodingType() != b->GetEncodingType() ) {
			stringstream ss;
			ss << "Ciphertext encoding types " << a->GetEncodingType();
			ss << " and " << b->GetEncodingType();
			ss << " do not match";
			PALISADE_THROW( type_error, ss.str() );
		}
	}

	/**
	 * TypeCheck makes sure that an operation between two ciphertexts is permitted
	 * This is intended for mutable methods, hence inputs are Ciphretext instead
	 * of ConstCiphertext.
	 *
	 * @param a
	 * @param b
	 */
	void TypeCheck(Ciphertext<Element> a, Ciphertext<Element> b) const {
		if( a == NULL || b == NULL )
			PALISADE_THROW( type_error, "Null Ciphertext");
		if( a->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContext");
		if( a->GetCryptoContext() != b->GetCryptoContext() )
			PALISADE_THROW( type_error, "Ciphertexts were not created in the same CryptoContext");
		if( a->GetKeyTag() != b->GetKeyTag() )
			PALISADE_THROW( type_error, "Ciphertexts were not encrypted with same keys" );
		if( a->GetEncodingType() != b->GetEncodingType() ) {
			stringstream ss;
			ss << "Ciphertext encoding types " << a->GetEncodingType();
			ss << " and " << b->GetEncodingType();
			ss << " do not match";
			PALISADE_THROW( type_error, ss.str() );
		}
	}

	/**
	 * TypeCheck makes sure that an operation between a ciphertext and a plaintext is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(ConstCiphertext<Element> a, ConstPlaintext b) const {
		if( a == NULL )
			PALISADE_THROW( type_error, "Null Ciphertext");
		if( b == NULL )
			PALISADE_THROW( type_error, "Null Plaintext");
		if( a->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContext");
		if( a->GetEncodingType() != b->GetEncodingType() ) {
			stringstream ss;
			ss << "Ciphertext encoding type " << a->GetEncodingType();
			ss << " and Plaintext encoding type " << b->GetEncodingType();
			ss << " do not match";
			PALISADE_THROW( type_error, ss.str() );
		}
	}

	/**
	 * TypeCheck makes sure that an operation between two ciphertexts is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const RationalCiphertext<Element>& a, const RationalCiphertext<Element>& b) const {
		if( a.GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a.GetCryptoContext() != b.GetCryptoContext() )
			PALISADE_THROW( type_error, "Ciphertexts were not created in the same CryptoContextImpl");
		if( a.GetKeyTag() != b.GetKeyTag() )
			PALISADE_THROW( type_error, "Ciphertexts were not encrypted with same keys" );
		if( a.GetNumerator()->GetEncodingType() != b.GetNumerator()->GetEncodingType() ) {
			stringstream ss;
			ss << "RationalCiphertext encoding types " << a.GetNumerator()->GetEncodingType();
			ss << " and " << b.GetNumerator()->GetEncodingType();
			ss << " do not match";
			PALISADE_THROW( type_error, ss.str() );
		}
	}

	/**
	 * TypeCheck makes sure that an operation between a ciphertext and a plaintext is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const RationalCiphertext<Element>& a, ConstPlaintext b) const {
		if( b == NULL )
			PALISADE_THROW( type_error, "Null Plaintext");
		if( a.GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a.GetNumerator()->GetEncodingType() != b->GetEncodingType() ){
			stringstream ss;
			ss << "RationalCiphertext encoding type " << a.GetNumerator()->GetEncodingType();
			ss << " and Plaintext encoding type " << b->GetEncodingType();
			ss << " do not match";
			PALISADE_THROW( type_error, ss.str() );
		}
	}

	bool Mismatched(const CryptoContext<Element> a) const {
		if( a.get() != this ) {
			return true;
		}
		return false;
	}

public:

	LPPrivateKey<Element> privateKey;

	/**
	 * This stores the private key in the crypto context.
	 * This is only intended for debugging and should not be
	 * used in production systems. Please define DEBUG_KEY in
	 * palisade.h to enable this.
	 *
	 * If used, one can create a key pair and store the secret
	 * key in th crypto context like this:
	 *
	 * auto keys = cc->KeyGen();
	 * cc->SetPrivateKey(keys.secretKey);
	 *
	 * After that, anyone in the code, one can access the
	 * secret key by getting the crypto context and doing the
	 * following:
	 *
	 * auto sk = cc->GetPrivateKey();
	 *
	 * This key can be used for decrypting any intermediate
	 * ciphertexts for debugging purposes.
	 *
	 * @param sk the secret key
	 *
	 */
	void SetPrivateKey(const LPPrivateKey<Element> sk) {
#ifdef DEBUG_KEY
			cerr << "Warning - SetPrivateKey is only intended to be used for debugging purposes - not for production systems." << endl;
			this->privateKey = sk;
#else
			PALISADE_THROW(not_available_error, "SetPrivateKey is only allowed if DEBUG_KEY is set in palisade.h");
#endif
	}

	/**
	 * This gets the private key from the crypto context.
	 * This is only intended for debugging and should not be
	 * used in production systems. Please define DEBUG_KEY in
	 * palisade.h to enable this.
	 *
	 * If used, one can create a key pair and store the secret
	 * key in th crypto context like this:
	 *
	 * auto keys = cc->KeyGen();
	 * cc->SetPrivateKey(keys.secretKey);
	 *
	 * After that, anyone in the code, one can access the
	 * secret key by getting the crypto context and doing the
	 * following:
	 *
	 * auto sk = cc->GetPrivateKey();
	 *
	 * This key can be used for decrypting any intermediate
	 * ciphertexts for debugging purposes.
	 *
	 * @return the secret key
	 *
	 */
	const LPPrivateKey<Element> GetPrivateKey() {
#ifdef DEBUG_KEY
		return this->privateKey;
#else
		PALISADE_THROW(not_available_error, "GetPrivateKey is only allowed if DEBUG_KEY is set in palisade.h");
#endif
	}

	void setSchemeId(string schemeTag) {
		this->m_schemeId = schemeTag;
	}

	string getSchemeId() {
		return this->m_schemeId;
	}

	/**
	 * CryptoContextImpl constructor from pointers to parameters and scheme
	 * @param params - pointer to CryptoParameters
	 * @param scheme - pointer to Crypto Scheme
	 */
	CryptoContextImpl(LPCryptoParameters<Element> *params = 0, LPPublicKeyEncryptionScheme<Element> *scheme = 0, const string & schemeId = "Not") {
		this->params.reset(params);
		this->scheme.reset(scheme);
		this->doTiming = false;
		this->timeSamples = 0;
		this->m_keyGenLevel = 0;
		this->m_schemeId = schemeId;
	}

	/**
	 * CryptoContextImpl constructor from shared pointers to parameters and scheme
	 * @param params - shared pointer to CryptoParameters
	 * @param scheme - sharedpointer to Crypto Scheme
	 */
	CryptoContextImpl(shared_ptr<LPCryptoParameters<Element>> params, shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme, const string & schemeId = "Not") {
		this->params = params;
		this->scheme = scheme;
		this->doTiming = false;
		this->timeSamples = 0;
		this->m_keyGenLevel = 0;
		this->m_schemeId = schemeId;
	}

	/**
	 * Copy constructor
	 * @param c - source
	 */
	CryptoContextImpl(const CryptoContextImpl<Element>& c) {
		params = c.params;
		scheme = c.scheme;
		doTiming = c.doTiming;
		timeSamples = c.timeSamples;
		this->m_keyGenLevel = 0;
		this->m_schemeId = c.m_schemeId;
	}

	/**
	 * Assignment
	 * @param rhs - assigning from
	 * @return this
	 */
	CryptoContextImpl<Element>& operator=(const CryptoContextImpl<Element>& rhs) {
		params = rhs.params;
		scheme = rhs.scheme;
		doTiming = rhs.doTiming;
		timeSamples = rhs.timeSamples;
		m_keyGenLevel = rhs.m_keyGenLevel;
		m_schemeId = rhs.m_schemeId;
		return *this;
	}

	/**
	 * A CryptoContextImpl is only valid if the shared pointers are both valid
	 */
	operator bool() const { return bool(params) && bool(scheme); }

	/**
	 * Private methods to compare two contexts; this is only used internally and is not generally available
	 * @param a - operand 1
	 * @param b - operand 2
	 * @return true if the implementations have identical parms and scheme
	 */
	friend bool operator==(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
		// Identical if the parameters and the schemes are identical... the exact same object,
		// OR the same type and the same values
		if( a.params.get() == b.params.get() ) {
			return true;
		}
		else {
			if( typeid(*a.params.get()) != typeid(*b.params.get()) ) {
				return false;
			}
			if( *a.params.get() != *b.params.get() )
				return false;
		}

		if( a.scheme.get() == b.scheme.get() ) {
			return true;
		}
		else {
			if( typeid(*a.scheme.get()) != typeid(*b.scheme.get()) ) {
				return false;
			}
			if( *a.scheme.get() != *b.scheme.get() )
				return false;
		}

		return true;
	}

	friend bool operator!=(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
		return !( a == b );
	}

	// TIMING METHODS
	/**
	 * StartTiming method activates timing of CryptoMethods
	 *
	 * @param timeSamples points to a vector in which timing samples will be stored
	 */
	void StartTiming(vector<TimingInfo>* timeSamples) {
		this->timeSamples = timeSamples;
		doTiming = true;
	}

	/*
	 * StopTiming - turns off timing
	 */
	void StopTiming() {
		doTiming = false;
	}

	/**
	 * ResumeTiming - re-enables timing with existing TimingInfo vector
	 */
	void ResumeTiming() {
		doTiming = true;
	}

	/**
	 * ResetTiming - erases measurements
	 */
	void ResetTiming() {
		this->timeSamples->clear();
	}

	static bool SerializeEvalMultKey(Serialized* serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalMultKey(Serialized* serObj, const string& id) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalMultKey(Serialized* serObj, const CryptoContext<Element> cc) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool DeserializeEvalMultKey(Serialized* serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	/**
	 * SerializeEvalMultKey for a single EvalMult key or all EvalMult keys
	 *
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @param id for key to serialize - if empty string, serialize them all
	 * @return true on success
	 */
	template<typename ST>
	static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, string id = "") {
		decltype(evalMultKeyMap)	*smap;
		decltype(evalMultKeyMap)	omap;

		if( id.length() == 0 )
			smap = &evalMultKeyMap;
		else {
			auto k = evalMultKeyMap.find(id);

			if( k == evalMultKeyMap.end() )
				return false; // no such id

			smap = &omap;
			omap[ k->first ] = k->second;
		}
		Serial::Serialize(*smap, ser, sertype);
		return true;
	}

	/**
	 * SerializeEvalMultKey for all EvalMultKeys made in a given context
	 *
	 * @param cc whose keys should be serialized
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @return true on success (false on failure or no keys found)
	 */
	template<typename ST>
	static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {

		decltype(evalMultKeyMap) omap;
		for( const auto& k : evalMultKeyMap ) {
			if( k.second[0]->GetCryptoContext() == cc ) {
				omap[k.first] = k.second;
			}
		}

		if( omap.size() == 0 )
			return false;

		Serial::Serialize(omap, ser, sertype);
		return true;
	}


	/**
	 * DeserializeEvalMultKey deserialize all keys in the serialization
	 * deserialized keys silently replace any existing matching keys
	 * deserialization will create CryptoContextImpl if necessary
	 *
	 * @param serObj - stream with a serialization
	 * @return true on success
	 */
	template<typename ST>
	static bool DeserializeEvalMultKey(std::istream& ser, const ST& sertype) {

		decltype(evalMultKeyMap) evalMultKeys;

		Serial::Deserialize(evalMultKeys, ser, sertype);

		// The deserialize call created any contexts that needed to be created.... so all we need to do
		// is put the keys into the maps for their context

		for( auto k : evalMultKeys ) {

			evalMultKeyMap[ k.first ] = k.second;
		}

		return true;
	}

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache
	 */
	static void ClearEvalMultKeys();

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
	 * @param id
	 */
	static void ClearEvalMultKeys(const string& id);

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
	 * @param cc
	 */
	static void ClearEvalMultKeys(const CryptoContext<Element> cc);

	/**
	 * InsertEvalMultKey - add the given vector of keys to the map, replacing the existing vector if there
	 * @param vectorToInsert
	 */
	static void InsertEvalMultKey(const std::vector<LPEvalKey<Element>>& vectorToInsert);

	static bool SerializeEvalSumKey(Serialized* serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalSumKey(Serialized* serObj, const string& id) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalSumKey(Serialized* serObj, const CryptoContext<Element> cc) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool DeserializeEvalSumKey(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	/**
	 * SerializeEvalSumKey for a single EvalSum key or all of the EvalSum keys
	 *
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @param id - key to serialize; empty string means all keys
	 * @return true on success
	 */
	template<typename ST>
	static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, string id = "") {
		decltype(evalSumKeyMap)*	smap;
		decltype(evalSumKeyMap)		omap;

		if( id.length() == 0 )
			smap = &evalSumKeyMap;
		else {
			auto k = evalSumKeyMap.find(id);

			if( k == evalSumKeyMap.end() )
				return false; // no such id

			smap = &omap;
			omap[ k->first ] = k->second;
		}
		Serial::Serialize(*smap, ser, sertype);
		return true;
	}

	/**
	 * SerializeEvalSumKey for all of the EvalSum keys for a context
	 *
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @param cc - context
	 * @return true on success
	 */
	template<typename ST>
	static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {

		decltype(evalSumKeyMap) omap;
		for( const auto& k : evalSumKeyMap ) {
			if( k.second->begin()->second->GetCryptoContext() == cc ) {
				omap[k.first] = k.second;
			}
		}

		if( omap.size() == 0 )
			return false;

		Serial::Serialize(omap, ser, sertype);
		return true;
	}

	/**
	 * DeserializeEvalSumKey deserialize all keys in the serialization
	 * deserialized keys silently replace any existing matching keys
	 * deserialization will create CryptoContextImpl if necessary
	 *
	 * @param ser - stream to serialize from
	 * @param sertype - type of serialization
	 * @return true on success
	 */
	template<typename ST>
	static bool DeserializeEvalSumKey(std::istream& ser, const ST& sertype) {

		decltype(evalSumKeyMap) evalSumKeys;

		Serial::Deserialize(evalSumKeys, ser, sertype);

		// The deserialize call created any contexts that needed to be created.... so all we need to do
		// is put the keys into the maps for their context

		for( auto k : evalSumKeys ) {
			evalSumKeyMap[ k.first ] = k.second;
		}

		return true;
	}

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache
	 */
	static void ClearEvalSumKeys();

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache for a given id
	 * @param id
	 */
	static void ClearEvalSumKeys(const string& id);

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache for a given context
	 * @param cc
	 */
	static void ClearEvalSumKeys(const CryptoContext<Element> cc);

	/**
	 * InsertEvalSumKey - add the given map of keys to the map, replacing the existing map if there
	 * @param mapToInsert
	 */
	static void InsertEvalSumKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert);

	static bool SerializeEvalAutomorphismKey(Serialized* serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalAutomorphismKey(Serialized* serObj, const string& id) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool SerializeEvalAutomorphismKey(Serialized* serObj, const CryptoContext<Element> cc) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static bool DeserializeEvalAutomorphismKey(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	/**
	 * SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys
	 *
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @param id - key to serialize; empty string means all keys
	 * @return true on success
	 */
	template<typename ST>
	static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, string id = "") {
		decltype(evalAutomorphismKeyMap)*	smap;
		decltype(evalAutomorphismKeyMap)		omap;
		if( id.length() == 0 )
			smap = &evalAutomorphismKeyMap;
		else {
			auto k = evalAutomorphismKeyMap.find(id);

			if( k == evalAutomorphismKeyMap.end() )
				return false; // no such id

			smap = &omap;
			omap[ k->first ] = k->second;
		}
		Serial::Serialize(*smap, ser, sertype);
		return true;
	}


	/**
	 * SerializeEvalAutomorphismKey for all of the EvalAuto keys for a context
	 *
	 * @param ser - stream to serialize to
	 * @param sertype - type of serialization
	 * @param cc - context
	 * @return true on success
	 */
	template<typename ST>
	static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {

		decltype(evalAutomorphismKeyMap) omap;
		for( const auto& k : evalAutomorphismKeyMap ) {
			if( k.second->begin()->second->GetCryptoContext() == cc ) {
				omap[k.first] = k.second;
			}
		}

		if( omap.size() == 0 )
			return false;

		Serial::Serialize(omap, ser, sertype);
		return true;
	}

	/**
	 * DeserializeEvalAutomorphismKey deserialize all keys in the serialization
	 * deserialized keys silently replace any existing matching keys
	 * deserialization will create CryptoContextImpl if necessary
	 *
	 * @param ser - stream to serialize from
	 * @param sertype - type of serialization
	 * @return true on success
	 */
	template<typename ST>
	static bool DeserializeEvalAutomorphismKey(std::istream& ser, const ST& sertype) {

		decltype(evalAutomorphismKeyMap) evalSumKeys;

		Serial::Deserialize(evalSumKeys, ser, sertype);

		// The deserialize call created any contexts that needed to be created.... so all we need to do
		// is put the keys into the maps for their context

		for( auto k : evalSumKeys ) {
			evalAutomorphismKeyMap[ k.first ] = k.second;
		}

		return true;
	}

	/**
	 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache
	 */
	static void ClearEvalAutomorphismKeys();

	/**
	 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
	 * @param id
	 */
	static void ClearEvalAutomorphismKeys(const string& id);

	/**
	 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given context
	 * @param cc
	 */
	static void ClearEvalAutomorphismKeys(const CryptoContext<Element> cc);

	/**
	 * InsertEvalAutomorphismKey - add the given map of keys to the map, replacing the existing map if there
	 * @param mapToInsert
	 */
	static void InsertEvalAutomorphismKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert);


	// TURN FEATURES ON
	/**
	 * Enable a particular feature for use with this CryptoContextImpl
	 * @param feature - the feature that should be enabled
	 */
	void Enable(PKESchemeFeature feature) { scheme->Enable(feature); }

	/**
	 * Enable several features at once
	 * @param featureMask - bitwise or of several PKESchemeFeatures
	 */
	void Enable(usint featureMask) { scheme->Enable(featureMask); }

	// GETTERS
	/**
	* Getter for Scheme
	* @return scheme
	*/
	const shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetEncryptionAlgorithm() const { return scheme; }

	/**
	* Getter for CryptoParams
	* @return params
	*/
	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return params; }

	const size_t GetKeyGenLevel() const { return m_keyGenLevel; }

	void SetKeyGenLevel(size_t level) { m_keyGenLevel = level; }

	/**
	 * Getter for element params
	 * @return
	 */
	const shared_ptr<typename Element::Params> GetElementParams() const { return params->GetElementParams(); }

	/**
	 * Getter for encoding params
	 * @return
	 */
	const EncodingParams GetEncodingParams() const { return params->GetEncodingParams(); }

	/**
	 * Get the cyclotomic order used for this context
	 *
	 * @return
	 */
	const usint GetCyclotomicOrder() const { return params->GetElementParams()->GetCyclotomicOrder(); }

	/**
	 * Get the ring dimension used for this context
	 *
	 * @return
	 */
	const usint GetRingDimension() const { return params->GetElementParams()->GetRingDimension(); }

	/**
	 * Get the ciphertext modulus used for this context
	 *
	 * @return
	 */
	const typename Element::Integer& GetModulus() const { return params->GetElementParams()->GetModulus(); }

	/**
	 * Get the ciphertext modulus used for this context
	 *
	 * @return
	 */
	const typename Element::Integer& GetRootOfUnity() const { return params->GetElementParams()->GetRootOfUnity(); }

	/**
	* KeyGen generates a key pair using this algorithm's KeyGen method
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> KeyGen() {
		TimeVar t;
		if( doTiming ) TIC(t);
		auto r = GetEncryptionAlgorithm()->KeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), false);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeyGen, TOC_US(t)) );
		}
		return r;
	}

	/**
	* KeyGen generates a Multiparty key pair using this algorithm's KeyGen method from two keys
	* @param pk first public key used to coordinate the creation of later public keys.
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> MultipartyKeyGen(
		const LPPublicKey<Element> pk, bool makeSparse=false, bool pre=false) {
		TimeVar t;
		if( doTiming ) TIC(t);
		auto r = GetEncryptionAlgorithm()->MultipartyKeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), pk, makeSparse, pre);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyKeyGenKey, TOC_US(t)) );
		}
		return r;
	}

	/**
	* KeyGen generates a Multiparty key pair using a vector of secret keys
	* @param secretKeys a vector of the secret keys to be used for multiparty computation.
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> MultipartyKeyGen(
		const vector<LPPrivateKey<Element>>& secretKeys) {
		TimeVar t;
		if( doTiming ) TIC(t);
		auto r =  GetEncryptionAlgorithm()->MultipartyKeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), secretKeys, false);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyKeyGenKeyvec, TOC_US(t)) );
		}
		return r;
	}

	/**
	* Lead Multiparty Decryption method for PALISADE multiparty operations.
	* This should be performed by exactly one of the clients.
	* All other clients should perform the MultipartyDecryptMain operation.
	* @param privateKey the secret key of the lead decryption client
	* @param ciphertext vector of encrypted ciphertext
	* @return vector of partially decrypted ciphertexts
	*/
	vector<Ciphertext<Element>> MultipartyDecryptLead(
		const LPPrivateKey<Element> privateKey,
		const vector<Ciphertext<Element>>& ciphertext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to MultipartyDecryptLead was not generated with this crypto context");

        vector<Ciphertext<Element>> newCiphertext;

		TimeVar t;
		if( doTiming ) TIC(t);
		for( size_t i = 0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || Mismatched(ciphertext[i]->GetCryptoContext()) )
				PALISADE_THROW(config_error, "A ciphertext passed to MultipartyDecryptLead was not generated with this crypto context");

			newCiphertext.push_back( GetEncryptionAlgorithm()->MultipartyDecryptLead(privateKey, ciphertext[i]) );

		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptLead, TOC_US(t)) );
		}

		return newCiphertext;
	}

	/**
	* Multiparty decryption method for PALISADE multiparty operations.
	* The lead multiparty decryption operation should be performed by exactly one of the clients.
	* All other clients should perform this MultipartyDecryptMain operation.
	* @param privateKey - for decryption
	* @param ciphertext - vector of encrypted ciphertext
	* @return vector of partially decrypted ciphertexts
	*/
	vector<Ciphertext<Element>> MultipartyDecryptMain(
		const LPPrivateKey<Element> privateKey,
		const vector<Ciphertext<Element>>& ciphertext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to MultipartyDecryptMain was not generated with this crypto context");

		vector<Ciphertext<Element>> newCiphertext;

		TimeVar t;
		if( doTiming ) TIC(t);

		for( size_t i = 0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || Mismatched(ciphertext[i]->GetCryptoContext()) )
				PALISADE_THROW(config_error, "A ciphertext passed to MultipartyDecryptMain was not generated with this crypto context");

			newCiphertext.push_back( GetEncryptionAlgorithm()->MultipartyDecryptMain(privateKey, ciphertext[i]) );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptMain, TOC_US(t)) );
		}

		return newCiphertext;
	}

	/**
	* Final multiparty decryption method to fuse the partially decrypted ciphertexts into a decrypted plaintext.
	* The lead multiparty decryption operation should be performed by exactly one of the clients.
	* All other clients should perform the MultipartyDecryptMain operation.
	* @param partialCiphertextVec - vector of partially decrypted ciphertexts.
	* @param plaintext - pointer to destination for the result of decryption
	* @param doPadding - true if input plaintext was padded; causes unpadding on last piece of ciphertext
	* @return size of plaintext
	*/
	DecryptResult MultipartyDecryptFusion(
		const vector<Ciphertext<Element>>& partialCiphertextVec,
		Plaintext *plaintext) const
	{

		DecryptResult result;

		//Make sure we're processing ciphertexts.
		size_t last_ciphertext = partialCiphertextVec.size();
		if ( last_ciphertext < 1 )
			return result;

		TimeVar t;
		if( doTiming ) TIC(t);

		for( size_t i = 0; i < last_ciphertext; i++ ) {
			if (partialCiphertextVec[i] == NULL || Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
				PALISADE_THROW(config_error, "A ciphertext passed to MultipartyDecryptFusion was not generated with this crypto context");
			if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
				PALISADE_THROW(type_error, "Ciphertexts passed to MultipartyDecryptFusion have mismatched encoding types");
		}

		// determine which type of plaintext that you need to decrypt into
		Plaintext decrypted = GetPlaintextForDecrypt(partialCiphertextVec[0]->GetEncodingType(), partialCiphertextVec[0]->GetElements()[0].GetParams(), this->GetEncodingParams());

		if ((partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) && (typeid(Element) != typeid(NativePoly)))
			result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<Poly>());
		else
			result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<NativePoly>());

		if (result.isValid == false) return result;

		if (partialCiphertextVec[0]->GetEncodingType() == CKKSPacked){
			shared_ptr<CKKSPackedEncoding> decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
			const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsCKKS =
							std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(this->GetCryptoParameters());
			decryptedCKKS->Decode(partialCiphertextVec[0]->GetDepth(),
					partialCiphertextVec[0]->GetScalingFactor(),
					cryptoParamsCKKS->GetRescalingTechnique());
		}
		else
			decrypted->Decode();

		*plaintext = decrypted;

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptFusion, TOC_US(t)) );
		}
		return result;
	}


	/**
	* SparseKeyGen generates a key pair with special structure, and without full entropy,
	* for use in special cases like Ring Reduction
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> SparseKeyGen() {
		TimeVar t;
		if( doTiming ) TIC(t);
		auto r = GetEncryptionAlgorithm()->KeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), true);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpSparseKeyGen, TOC_US(t)) );
		}
		return r;
	}

	/**
	* ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
	* @param newKey (public)
	* @param oldKey (private)
	* @return new evaluation key
	*/
	LPEvalKey<Element> ReKeyGen(
		const LPPublicKey<Element> newKey,
		const LPPrivateKey<Element> oldKey) const {

		if( newKey == NULL || oldKey == NULL ||
				Mismatched(newKey->GetCryptoContext()) ||
				Mismatched(oldKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Keys passed to ReKeyGen were not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto r = GetEncryptionAlgorithm()->ReKeyGen(newKey, oldKey);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpReKeyGenPubPri, TOC_US(t)) );
		}
		return r;
	}

	/**
	 * ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
	 * NOTE this functionality has been completely removed from PALISADE
	 * @param newKey (private)
	 * @param oldKey (private)
	 * @return new evaluation key
	 */
	LPEvalKey<Element> ReKeyGen(
			const LPPrivateKey<Element> newKey,
			const LPPrivateKey<Element> oldKey) const
					__attribute__ ((deprecated("functionality removed from PALISADE")));

	/**
	* EvalMultKeyGen creates a key that can be used with the PALISADE EvalMult operator
	* @param key
	* @return new evaluation key
	*/
	void EvalMultKeyGen(const LPPrivateKey<Element> key);

	/**
	* EvalMultsKeyGen creates a vector evalmult keys that can be used with the PALISADE EvalMult operator
	* 1st key (for s^2) is used for multiplication of ciphertexts of depth 1
	* 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
	*
	* @param key
	* @return a vector of evaluation keys
	*/
	void EvalMultKeysGen(const LPPrivateKey<Element> key);

	/**
	 * GetEvalMultKeyVector fetches the eval mult keys for a given KeyID
	 * @param keyID
	 * @return key vector from ID
	 */
	static const vector<LPEvalKey<Element>>& GetEvalMultKeyVector(const string& keyID);

	/**
	 * GetEvalMultKeys
	 * @return map of all the keys
	 */
	static const std::map<string,std::vector<LPEvalKey<Element>>>& GetAllEvalMultKeys();

	/**
	* KeySwitchGen creates a key that can be used with the PALISADE KeySwitch operation
	* @param key1
	* @param key2
	* @return new evaluation key
	*/
	LPEvalKey<Element> KeySwitchGen(
		const LPPrivateKey<Element> key1, const LPPrivateKey<Element> key2) const {

		if( key1 == NULL || key2 == NULL ||
				Mismatched(key1->GetCryptoContext()) ||
				Mismatched(key2->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Keys passed to KeySwitchGen were not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto r = GetEncryptionAlgorithm()->KeySwitchGen(key1, key2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeySwitchGen, TOC_US(t)) );
		}
		return r;
	}

	/**
	 * Encrypt a plaintext using a given public key
	 * @param publicKey
	 * @param plaintext
	 * @return ciphertext (or null on failure)
	 */
	Ciphertext<Element> Encrypt(
			const LPPublicKey<Element> publicKey,
			Plaintext plaintext)
	{
		if( publicKey == NULL )
			PALISADE_THROW(type_error, "null key passed to Encrypt");

		if( plaintext == NULL )
			PALISADE_THROW(type_error, "null plaintext passed to Encrypt");

		if( Mismatched(publicKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "key passed to Encrypt was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);

		Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, plaintext->GetElement<Element>());

		if (ciphertext) {
			ciphertext->SetEncodingType( plaintext->GetEncodingType() );
			ciphertext->SetScalingFactor( plaintext->GetScalingFactor() );
			ciphertext->SetDepth( plaintext->GetDepth() );
			ciphertext->SetLevel( plaintext->GetLevel() );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptPub, TOC_US(t)) );
		}
		return ciphertext;
	}

	/**
	 * Encrypt a plaintext using a given private key
	 * @param privateKey
	 * @param plaintext
	 * @return ciphertext (or null on failure)
	 */
	Ciphertext<Element> Encrypt(
		const LPPrivateKey<Element> privateKey,
		Plaintext plaintext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "key passed to Encrypt was not generated with this crypto context");
		if( plaintext == NULL )
			PALISADE_THROW(type_error, "null plaintext passed to Encrypt");

		TimeVar t;
		if( doTiming ) TIC(t);

		Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(privateKey, plaintext->GetElement<Element>());

		if (ciphertext) {
			ciphertext->SetEncodingType( plaintext->GetEncodingType() );
			ciphertext->SetScalingFactor( plaintext->GetScalingFactor() );
			ciphertext->SetDepth( plaintext->GetDepth() );
			ciphertext->SetLevel( plaintext->GetLevel() );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptPriv, TOC_US(t)) );
		}
		return ciphertext;
	}
	
	/**
	* Encrypt a matrix of Plaintext
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>> EncryptMatrix(
		const LPPublicKey<Element> publicKey,
		Matrix<Plaintext> &plaintext)
	{
		if (publicKey == NULL || Mismatched(publicKey->GetCryptoContext()))
			PALISADE_THROW(config_error, "key passed to EncryptMatrix was not generated with this crypto context");

		auto zeroAlloc = [=]() { return RationalCiphertext<Element>(publicKey->GetCryptoContext(), true); };

		shared_ptr<Matrix<RationalCiphertext<Element>>> cipherResults(new Matrix<RationalCiphertext<Element>>
			(zeroAlloc, plaintext.GetRows(), plaintext.GetCols()));

		TimeVar t;
		if( doTiming ) TIC(t);
		for (size_t row = 0; row < plaintext.GetRows(); row++)
		{
			for (size_t col = 0; col < plaintext.GetCols(); col++)
			{
				if( plaintext(row,col)->Encode() == false )
					return 0;

				Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, plaintext(row,col)->GetElement<Element>());

				if (ciphertext) {
					ciphertext->SetEncodingType( plaintext(row,col)->GetEncodingType() );
				}

				(*cipherResults)(row, col).SetNumerator(ciphertext);
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptMatrixPlain, TOC_US(t)) );
		}
		return cipherResults;
	}

	/**
	* Encrypt a matrix of Plaintext
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	Matrix<Ciphertext<Element>> EncryptMatrixCiphertext(
		const LPPublicKey<Element> publicKey,
		Matrix<Plaintext> &plaintext)
	{
		if (publicKey == NULL || Mismatched(publicKey->GetCryptoContext()))
			PALISADE_THROW(config_error, "key passed to EncryptMatrix was not generated with this crypto context");

		auto zeroAlloc = [=]() { return Ciphertext<Element>(new CiphertextImpl<Element>(publicKey->GetCryptoContext())); };
		Matrix<Ciphertext<Element>> cipherResults(zeroAlloc, plaintext.GetRows(), plaintext.GetCols());

		TimeVar t;
		if( doTiming ) TIC(t);
		for (size_t row = 0; row < plaintext.GetRows(); row++)
		{
			for (size_t col = 0; col < plaintext.GetCols(); col++)
			{
				if( plaintext(row,col)->Encode() == false )
					PALISADE_THROW(math_error, "Plaintext is not encoded");

				Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, plaintext(row,col)->GetElement<Element>());

				if (ciphertext) {
					ciphertext->SetEncodingType( plaintext(row,col)->GetEncodingType() );
				}

				cipherResults(row, col) = (ciphertext);
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptMatrixPlain, TOC_US(t)) );
		}
		return cipherResults;
	}

	/**
	* Perform an encryption by reading plaintext from a stream, serializing each piece of ciphertext,
	* and writing the serializations to an output stream
	* @param publicKey - the encryption key in use
	* @param instream - where to read the input from
	* @param ostream - where to write the serialization to
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return
	*/
	void EncryptStream(
		const LPPublicKey<Element> publicKey,
		std::istream& instream,
		std::ostream& outstream) const __attribute__ ((deprecated("serialization changed, see wiki for details")));

	// PLAINTEXT FACTORY METHODS
	// FIXME to be deprecated in 2.0
	/**
	 * MakeScalarPlaintext constructs a ScalarEncoding in this context
	 * @param value
	 * @param isSigned
	 * @return plaintext
	 */
	Plaintext MakeScalarPlaintext(int64_t value) const {
		auto p = PlaintextFactory::MakePlaintext( Scalar, this->GetElementParams(), this->GetEncodingParams(), value );
		return p;
	}

	/**
	 * MakeStringPlaintext constructs a StringEncoding in this context
	 * @param str
	 * @return plaintext
	 */
	Plaintext MakeStringPlaintext(const string& str) const {
		auto p = PlaintextFactory::MakePlaintext( String, this->GetElementParams(), this->GetEncodingParams(), str );
		return p;
	}

	/**
	 * MakeIntegerPlaintext constructs an IntegerEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakeIntegerPlaintext(int64_t value) const {
		auto p = PlaintextFactory::MakePlaintext( Integer, this->GetElementParams(), this->GetEncodingParams(), value );
		return p;
	}

	/**
	 * MakeIntegerPlaintext constructs a FractionalEncoding in this context
	 * @param value
	 * @param truncatedBits limit on fractional
	 * @return plaintext
	 */
	Plaintext MakeFractionalPlaintext(int64_t value, size_t truncatedBits = 0) const {
		auto p =  PlaintextFactory::MakePlaintext( Fractional, this->GetElementParams(), this->GetEncodingParams(), value, truncatedBits );
		return p;
	}

	/**
	 * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakeCoefPackedPlaintext(const vector<int64_t>& value) const {
		auto p = PlaintextFactory::MakePlaintext( CoefPacked, this->GetElementParams(), this->GetEncodingParams(), value );
		return p;
	}

	/**
	 * MakePackedPlaintext constructs a PackedEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakePackedPlaintext(const vector<int64_t>& value) const {
		auto p = PlaintextFactory::MakePlaintext( Packed, this->GetElementParams(), this->GetEncodingParams(), value );
		return p;
	}

	/**
	 * MakePlaintext static that takes a cc and calls the Plaintext Factory
	 * @param encoding
	 * @param cc
	 * @param value
	 * @return
	 */
	template<typename Value1>
	static Plaintext MakePlaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value) {
		return PlaintextFactory::MakePlaintext( encoding, cc->GetElementParams(), cc->GetEncodingParams(), value );
	}

	template<typename Value1, typename Value2>
	static Plaintext MakePlaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value, const Value2& value2) {
		return PlaintextFactory::MakePlaintext( encoding, cc->GetElementParams(), cc->GetEncodingParams(), value, value2 );
	}

	/**
	 * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakeCKKSPackedPlaintext(const std::vector<std::complex<double>> &value,
			size_t depth=1,	uint32_t level=0,
			const shared_ptr<typename Element::Params> params=nullptr) const {

		Plaintext p;
		const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsCKKS =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(this->GetCryptoParameters());
		double ptxtMod = cryptoParamsCKKS->GetEncodingParams()->GetPlaintextModulus();

		double scFact = 1.0;
		if (cryptoParamsCKKS->GetRescalingTechnique() == EXACTRESCALE) {
			scFact = cryptoParamsCKKS->GetScalingFactorOfLevel(level);
		} else {
			scFact = pow(2, ptxtMod);
		}

		if (params == nullptr) {

			shared_ptr<ILDCRTParams<DCRTPoly::Integer>> elemParamsPtr;
			if (level != 0) {
				ILDCRTParams<DCRTPoly::Integer> elemParams = *(cryptoParamsCKKS->GetElementParams());
				for (uint32_t i=0; i<level; i++) {
					elemParams.PopLastParam();
				}
				elemParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(elemParams);
			} else {
				elemParamsPtr = cryptoParamsCKKS->GetElementParams();
			}

			p = Plaintext( new CKKSPackedEncoding( elemParamsPtr, this->GetEncodingParams(), value, depth, level, scFact) );
		} else
			p = Plaintext( new CKKSPackedEncoding( params, this->GetEncodingParams(), value, depth, level, scFact) );

		p->Encode();
		return p;
	}

	/**
	 * GetPlaintextForDecrypt returns a new Plaintext to be used in decryption.
	 *
	 * @param pte Type of plaintext we want to return
	 * @param evp Element parameters
	 * @param ep Encoding parameters
	 * @return plaintext
	 */
	static Plaintext
	GetPlaintextForDecrypt(PlaintextEncodings pte, shared_ptr<typename Element::Params> evp, EncodingParams ep) {
		shared_ptr<typename NativePoly::Params> vp(
				new typename NativePoly::Params(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1) );

		Plaintext tempPlaintext;

		if (pte == CKKSPacked)
		{
			if (evp->GetModulus().GetMSB() < MAX_MODULUS_SIZE + 1)
				tempPlaintext = PlaintextFactory::MakePlaintext(pte, vp, ep);
			else
				tempPlaintext = PlaintextFactory::MakePlaintext(pte, evp, ep);
		}
		else
			tempPlaintext = PlaintextFactory::MakePlaintext(pte, vp, ep);

		return tempPlaintext;
	}

public:

	/**
	 * Decrypt a single ciphertext into the appropriate plaintext
	 *
	 * @param privateKey - decryption key
	 * @param ciphertext - ciphertext to decrypt
	 * @param plaintext - resulting plaintext object pointer is here
	 * @return
	 */
	DecryptResult Decrypt(
			const LPPrivateKey<Element> privateKey,
			ConstCiphertext<Element> ciphertext,
			Plaintext* plaintext)
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to Decrypt was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);

		// determine which type of plaintext that you need to decrypt into
		//Plaintext decrypted = GetPlaintextForDecrypt(ciphertext->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		Plaintext decrypted = GetPlaintextForDecrypt(ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams());

		DecryptResult result;

		if ((ciphertext->GetEncodingType() == CKKSPacked) && (typeid(Element) != typeid(NativePoly))) {
			if (typeid(Element) == typeid(DCRTPoly))
			{
				if (ciphertext->GetElements()[0].GetModulus().GetMSB() < MAX_MODULUS_SIZE + 1) // only one tower in DCRTPoly
					result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext, &decrypted->GetElement<NativePoly>());
				else
					result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext, &decrypted->GetElement<Poly>());
			}
			else
				result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext, &decrypted->GetElement<Poly>());
		}
		else
			result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext, &decrypted->GetElement<NativePoly>());

		if (result.isValid == false) return result;

		if (ciphertext->GetEncodingType() == CKKSPacked){
			shared_ptr<CKKSPackedEncoding> decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
			decryptedCKKS->SetDepth(ciphertext->GetDepth());
			decryptedCKKS->SetLevel(ciphertext->GetLevel());
			decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());

			const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsCKKS =
										std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(this->GetCryptoParameters());

			decryptedCKKS->Decode(ciphertext->GetDepth(), ciphertext->GetScalingFactor(), cryptoParamsCKKS->GetRescalingTechnique());

		}
		else
			decrypted->Decode();

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecrypt, TOC_US(t)) );
		}

		*plaintext = decrypted;
		return result;
	}


	/**
	* Decrypt method for a matrix of ciphertexts
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrix(
		const LPPrivateKey<Element> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		shared_ptr<Matrix<Plaintext>> *numerator,
		shared_ptr<Matrix<Plaintext>> *denominator) const
	{

		// edge case
		if ((ciphertext->GetCols()== 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if (privateKey == NULL || Mismatched(privateKey->GetCryptoContext()))
			PALISADE_THROW(config_error, "Information passed to DecryptMatrix was not generated with this crypto context");

		const Ciphertext<Element> ctN = (*ciphertext)(0, 0).GetNumerator();

		// need to build matrices for the result
		Plaintext ptx = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		auto zeroPackingAlloc = [=]() { return Plaintext(ptx); };
		*numerator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );
		*denominator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );

		TimeVar t;
		if( doTiming ) TIC(t);
		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if (Mismatched((*ciphertext)(row, col).GetCryptoContext()))
					PALISADE_THROW(config_error, "A ciphertext passed to DecryptMatrix was not generated with this crypto context");

				const Ciphertext<Element> ctN = (*ciphertext)(row, col).GetNumerator();

				// determine which type of plaintext that you need to decrypt into
				Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

				if (resultN.isValid == false) return resultN;

				(**numerator)(row,col) = decryptedNumerator;

				(**numerator)(row,col)->Decode();

				Plaintext decryptedDenominator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				if( (*ciphertext)(row,col).GetIntegerFlag() == true ) {
					decryptedDenominator->GetElement<Poly>().SetValuesToZero();
					decryptedDenominator->GetElement<Poly>().at(0) = 1;
				}
				else {

					const Ciphertext<Element> ctD = (*ciphertext)(row, col).GetDenominator();

					DecryptResult resultD = GetEncryptionAlgorithm()->Decrypt(privateKey, ctD, &decryptedDenominator->GetElement<NativePoly>());

					if (resultD.isValid == false) return resultD;

					(**denominator)(row,col) = decryptedDenominator;
				}

				(**denominator)(row, col)->Decode();

			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecryptMatrixPlain, TOC_US(t)) );
		}
		return DecryptResult((**numerator)((*numerator)->GetRows()-1,(*numerator)->GetCols()-1)->GetLength());

	}

	/**
	* Decrypt method for a matrix of ciphertexts
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrixCiphertext(
		const LPPrivateKey<Element> privateKey,
		const Matrix<Ciphertext<Element>> ciphertext,
		Matrix<Plaintext> *numerator) const
	{

		// edge case
		if ((ciphertext.GetCols()== 0) && (ciphertext.GetRows() == 0))
			return DecryptResult();

		if (privateKey == NULL || Mismatched(privateKey->GetCryptoContext()))
			PALISADE_THROW(config_error, "Information passed to DecryptMatrix was not generated with this crypto context");

		const Ciphertext<Element> ctN = (ciphertext)(0, 0);

		// need to build matrices for the result
//		Plaintext ptx = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
//		auto zeroPackingAlloc = [=]() { return Plaintext(ptx); };
//		numerator = new Matrix<Plaintext>(zeroPackingAlloc, ciphertext.GetRows(), ciphertext.GetCols());

		TimeVar t;
		if( doTiming ) TIC(t);
		for (size_t row = 0; row < ciphertext.GetRows(); row++)
		{
			for (size_t col = 0; col < ciphertext.GetCols(); col++)
			{
				if (Mismatched( (ciphertext(row, col))->GetCryptoContext() ))
					PALISADE_THROW(config_error, "A ciphertext passed to DecryptMatrix was not generated with this crypto context");

				const Ciphertext<Element> ctN = (ciphertext)(row, col);

				// determine which type of plaintext that you need to decrypt into
				Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

				if (resultN.isValid == false) return resultN;

				(*numerator)(row,col) = decryptedNumerator;

				(*numerator)(row,col)->Decode();

			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecryptMatrixPlain, TOC_US(t)) );
		}
		return DecryptResult((*numerator)( numerator->GetRows()-1, numerator->GetCols()-1)->GetLength());

	}

	/**
	* Decrypt method for numerators in a matrix of ciphertexts (packed encoding)
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrixNumerator(
		const LPPrivateKey<Element> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		shared_ptr<Matrix<Plaintext>> *numerator) const
	{
		// edge case
		if ((ciphertext->GetCols() == 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if (privateKey == NULL || Mismatched(privateKey->GetCryptoContext()))
			PALISADE_THROW(config_error, "Information passed to DecryptMatrix was not generated with this crypto context");

		TimeVar t;
		if (doTiming) TIC(t);

		//force all precomputations to take place in advance
		if( Mismatched((*ciphertext)(0, 0).GetCryptoContext()) )
			PALISADE_THROW(config_error, "A ciphertext passed to DecryptMatrix was not generated with this crypto context");

		const Ciphertext<Element> ctN = (*ciphertext)(0, 0).GetNumerator();

		// need to build a numerator matrix for the result
		Plaintext ptx = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		auto zeroPackingAlloc = [=]() { return Plaintext(ptx); };
		*numerator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );

		Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

		if (resultN.isValid == false) return resultN;

		(**numerator)(0, 0) = decryptedNumerator;
		(**numerator)(0, 0)->Decode();

		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
#pragma omp parallel for
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if (row + col > 0)
				{
					if( Mismatched((*ciphertext)(row, col).GetCryptoContext()) )
						PALISADE_THROW(config_error, "A ciphertext passed to DecryptMatrix was not generated with this crypto context");

					const Ciphertext<Element> ctN = (*ciphertext)(row, col).GetNumerator();

					Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
					GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

					(**numerator)(row, col) = decryptedNumerator;
					(**numerator)(row, col)->Decode();
				}

			}
		}

		if (doTiming) {
			timeSamples->push_back(TimingInfo(OpDecryptMatrixPacked, TOC_US(t)));
		}
		return DecryptResult((**numerator)((*numerator)->GetRows() - 1, (*numerator)->GetCols() - 1)->GetLength());

	}

	/**
	* read instream for a sequence of serialized ciphertext; deserialize it, decrypt it, and write it to outstream
	* @param privateKey - reference to the decryption key
	* @param instream - input stream with sequence of serialized ciphertexts
	* @param outstream - output stream for plaintext
	* @return total bytes processed
	*/
	size_t DecryptStream(
		const LPPrivateKey<Element> privateKey,
		std::istream& instream,
		std::ostream& outstream) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	/**
	* ReEncrypt - Proxy Re Encryption mechanism for PALISADE
	* @param evalKey - evaluation key from the PRE keygen method
	* @param ciphertext - vector of shared pointers to encrypted Ciphertext
	* @param publicKey the public key of the recipient of the re-encrypted ciphertext.
	* @return vector of shared pointers to re-encrypted ciphertexts
	*/
	Ciphertext<Element> ReEncrypt(
		LPEvalKey<Element> evalKey,
		ConstCiphertext<Element> ciphertext,
		const LPPublicKey<Element> publicKey = nullptr) const
	{
		if( evalKey == NULL || Mismatched(evalKey->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to ReEncrypt was not generated with this crypto context");

		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			PALISADE_THROW(config_error, "The ciphertext passed to ReEncrypt was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);

		Ciphertext<Element> newCiphertext = GetEncryptionAlgorithm()->ReEncrypt(evalKey, ciphertext, publicKey);

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpReEncrypt, TOC_US(t)) );
		}

		return newCiphertext;
	}

	/**
	* read instream for a serialized ciphertext. deserialize, re-encrypt, serialize, and write to outstream
	* @param evalKey - reference to the re-encryption key
	* @param instream - input stream with sequence of serialized ciphertext
	* @param outstream - output stream with sequence of serialized re-encrypted ciphertext
	*/
	void ReEncryptStream(
		const LPEvalKey<Element> evalKey,
		std::istream& instream,
		std::ostream& outstream,
		const LPPublicKey<Element> publicKey = nullptr) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	/**
	 * EvalAdd - PALISADE EvalAdd method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 + ct2
	 */
	Ciphertext<Element>
	EvalAdd(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAdd(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAdd, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalAdd - PALISADE EvalAddMutable method for a pair of ciphertexts.
	 * This is a mutable version - input ciphertexts may get automatically
	 * rescaled, or level-reduced.
	 *
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 + ct2
	 */
	Ciphertext<Element>
	EvalAddMutable(Ciphertext<Element> &ct1, Ciphertext<Element> &ct2) const
	{
		TypeCheck(ct1, ct2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAddMutable(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAdd, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalAddMatrix - PALISADE EvalAdd method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalAddMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		Matrix<RationalCiphertext<Element>> rv = *ct1 + *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddMatrix, TOC_US(t)) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	 * EvalAddMatrix - PALISADE EvalAdd method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	Matrix<Ciphertext<Element>>
	EvalAddMatrix(const Matrix<Ciphertext<Element>> &ct1, const Matrix<Ciphertext<Element>> &ct2) const
	{
		TypeCheck(ct1(0,0), ct2(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		Matrix<Ciphertext<Element>> rv = ct1 + ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddMatrix, TOC_US(t)) );
		}
//		Matrix<Ciphertext<Element>> a(rv);
		return rv;
	}

	/**
	 * EvalSub - PALISADE EvalSub method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 - ct2
	 */
	Ciphertext<Element>
	EvalSub(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalSub(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSub, TOC_US(t)) );
		}
		return rv;
	}


	/**
	 * EvalSub - PALISADE EvalSubMutable method for a pair of ciphertexts
	 * This is a mutable version - input ciphertexts may get automatically
	 * rescaled, or level-reduced.
	 *
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 - ct2
	 */
	Ciphertext<Element>
	EvalSubMutable(Ciphertext<Element> &ct1, Ciphertext<Element> &ct2) const
	{
		TypeCheck(ct1, ct2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalSubMutable(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSub, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalSubMatrix - PALISADE EvalSub method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalSubMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		Matrix<RationalCiphertext<Element>> rv = *ct1 - *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubMatrix, TOC_US(t)) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	 * EvalSubMatrix - PALISADE EvalSub method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	Matrix<Ciphertext<Element>>
	EvalSubMatrix(const Matrix<Ciphertext<Element>> &ct1, const Matrix<Ciphertext<Element>> &ct2) const
	{
		TypeCheck(ct1(0,0), ct2(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		Matrix<Ciphertext<Element>> rv = ct1 - ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubMatrix, TOC_US(t)) );
		}
		Matrix<Ciphertext<Element>> a(rv);
		return a;
	}


	/**
	* EvalAdd - PALISADE EvalAdd method for a ciphertext and plaintext
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext + plaintext 
	*/
	Ciphertext<Element>
	EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const
	{
		TypeCheck(ciphertext, plaintext);

		TimeVar t;
		if( doTiming ) TIC(t);
		plaintext->SetFormat(EVALUATION);

		auto rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddPlain, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalAdd - PALISADE EvalAddMutable method for a ciphertext and plaintext
	* This is a mutable version - input ciphertexts may get automatically
	* rescaled, or level-reduced.
	*
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext + plaintext
	*/
	Ciphertext<Element>
	EvalAddMutable(Ciphertext<Element> &ciphertext, Plaintext plaintext) const
	{
		TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext) plaintext);

		TimeVar t;
		if( doTiming ) TIC(t);
		plaintext->SetFormat(EVALUATION);

		auto rv = GetEncryptionAlgorithm()->EvalAddMutable(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddPlain, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalAdd - PALISADE EvalAdd method for a ciphertext and constant
	* @param ciphertext
	* @param constant
	* @return new ciphertext for ciphertext + constant
	*/
	Ciphertext<Element>
	EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const
	{
		TimeVar t;

		Ciphertext<Element> rv;

		if ( constant >= 0 ) {
			if( doTiming ) TIC(t);
			rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, constant);
			if( doTiming ) {
				timeSamples->push_back( TimingInfo(OpEvalAddConst, TOC_US(t)) );
			}
		} else {
			TimeVar t;
			if( doTiming ) TIC(t);
			rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, -constant);
			if( doTiming ) {
				timeSamples->push_back( TimingInfo(OpEvalAddConst, TOC_US(t)) );
			}
		}

		return rv;
	}

	/**
	* EvalLinearWSum - PALISADE EvalLinearWSum method to compute a linear weighted sum
	*
	* @param ciphertexts a list of ciphertexts
	* @param constants a list of weights
	* @return new ciphertext containing the weighted sum
	*/
	Ciphertext<Element> EvalLinearWSum(
			vector<Ciphertext<Element>> ciphertexts,
			vector<double> constants) const
	{
		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalLinearWSum(ciphertexts, constants);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalLinearWSum, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalLinearWSum - method to compute a linear weighted sum.
	* This is a mutable version, meaning the level/depth of input
	* ciphertexts may change in the process.
	*
	* @param ciphertexts a list of ciphertexts
	* @param constants a list of weights
	* @return new ciphertext containing the weighted sum
	*/
	Ciphertext<Element> EvalLinearWSumMutable(
			vector<Ciphertext<Element>> ciphertexts,
			vector<double> constants) const
	{
		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalLinearWSumMutable(ciphertexts, constants);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalLinearWSum, TOC_US(t)) );
		}
		return rv;
	}


	inline Ciphertext<Element>
	EvalLinearWSum(vector<double> constants,
			vector<Ciphertext<Element>> ciphertexts) const
	{
		return EvalLinearWSum(ciphertexts, constants);
	}

	inline Ciphertext<Element>
	EvalLinearWSumMutable(vector<double> constants,
			vector<Ciphertext<Element>> ciphertexts) const
	{
		return EvalLinearWSumMutable(ciphertexts, constants);
	}

	inline Ciphertext<Element>
	EvalAdd(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const
	{
		return EvalAdd(ciphertext, plaintext);
	}

	inline Ciphertext<Element>
	EvalAddMutable(Plaintext plaintext, Ciphertext<Element> &ciphertext) const
	{
		return EvalAddMutable(ciphertext, plaintext);
	}

	inline Ciphertext<Element>
	EvalAdd(double constant, ConstCiphertext<Element> ciphertext) const
	{
		return EvalAdd(ciphertext, constant);
	}

	/**
	* EvalSubPlain - PALISADE EvalSub method for a ciphertext and plaintext
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext - plaintext
	*/
	Ciphertext<Element>
	EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const
	{
		TypeCheck(ciphertext, plaintext);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubPlain, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalSubPlain - PALISADE EvalSubMutable method for a ciphertext and plaintext
	* This is a mutable version - input ciphertexts may get automatically
	* rescaled, or level-reduced.
	*
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext - plaintext
	*/
	Ciphertext<Element>
	EvalSubMutable(Ciphertext<Element> &ciphertext, Plaintext plaintext) const
	{
		TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext) plaintext);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalSubMutable(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubPlain, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalSub - PALISADE EvalSub method for a ciphertext and constant
	* @param ciphertext
	* @param constant
	* @return new ciphertext for ciphertext - constant
	*/
	Ciphertext<Element>
	EvalSub(ConstCiphertext<Element> ciphertext, double constant) const
	{
		TimeVar t;

		Ciphertext<Element> rv;

		if ( constant >= 0 ) {
			if( doTiming ) TIC(t);
			rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, constant);
			if( doTiming ) {
				timeSamples->push_back( TimingInfo(OpEvalSubConst, TOC_US(t)) );
			}
		} else {
			if( doTiming ) TIC(t);
			rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, -constant);
			if( doTiming ) {
				timeSamples->push_back( TimingInfo(OpEvalSubConst, TOC_US(t)) );
			}
		}

		return rv;
	}

	inline Ciphertext<Element>
	EvalSub(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const
	{
		return EvalAdd(EvalNegate(ciphertext), plaintext);
	}

	inline Ciphertext<Element>
	EvalSubMutable(Plaintext plaintext, Ciphertext<Element> &ciphertext) const
	{
		Ciphertext<Element> negated = EvalNegate(ciphertext);
		Ciphertext<Element> result = EvalAddMutable(negated, plaintext);
		ciphertext = EvalNegate(negated);
		return result;
	}

	inline Ciphertext<Element>
	EvalSub(double constant, ConstCiphertext<Element> ciphertext) const
	{
		return EvalAdd(EvalNegate(ciphertext), constant);
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - with key switching
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	Ciphertext<Element>
	EvalMult(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek[0]);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - with key switching
	 * This is a mutable version - input ciphertexts may get automatically
	 * rescaled, or level-reduced.
	 *
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	Ciphertext<Element>
	EvalMultMutable(Ciphertext<Element> &ct1, Ciphertext<Element> &ct2) const
	{
		TypeCheck(ct1, ct2);

		auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ct1, ct2, ek[0]);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - no key switching (relinearization)
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	Ciphertext<Element>
	EvalMultNoRelin(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalMultMany - PALISADE function for evaluating multiplication on ciphertext followed by relinearization operation (at the end).
	* It computes the multiplication in a binary tree manner. Also, it reduces the number of
	* elements in the ciphertext to two after each multiplication.
	* Currently it assumes that the consecutive two input arguments have
	* total depth smaller than the supported depth. Otherwise, it throws an error.
	*
	* @param cipherTextList  is the ciphertext list.
	*
	* @return new ciphertext.
	*/
	Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& ct) const{

		const auto ek = GetEvalMultKeyVector(ct[0]->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMultMany(ct, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultMany, TOC_US(t)) );
		}
		return rv;

	}

	/**
	* EvalAddMany - Evaluate addition on a vector of ciphertexts.
	* It computes the addition in a binary tree manner.
	*
	* @param ctList is the list of ciphertexts.
	*
	* @return new ciphertext.
	*/
	Ciphertext<Element> EvalAddMany(const vector<Ciphertext<Element>>& ctList) const{

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAddMany(ctList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddMany, TOC_US(t)) );
		}
		return rv;

	}

	/**
	* EvalAddManyInPlace - Evaluate addition on a vector of ciphertexts.
	* Addition is computed in a binary tree manner. Difference with EvalAddMany
	* is that EvalAddManyInPlace uses the input ciphertext vector to store
	* intermediate results, to avoid the overhead of using extra tepmorary
	* space.
	*
	* @param ctList is the list of ciphertexts.
	*
	* @return new ciphertext.
	*/
	Ciphertext<Element> EvalAddManyInPlace(vector<Ciphertext<Element>>& ctList) const{

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAddManyInPlace(ctList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddManyInPlace, TOC_US(t)) );
		}
		return rv;

	}

	/**
	* Function for evaluating multiplication on ciphertext followed by relinearization operation.
	* Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error.
	*
	* @param ct1 first input ciphertext.
	* @param ct2 second input ciphertext.
	*
	* @return new ciphertext
	*/
	Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const {

		const auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMultAndRelinearize(ct1, ct2, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;

	}

	/**
	* Function for relinearization of a ciphertext.
	*
	* @param ct input ciphertext.
	*
	* @return relinearized ciphertext
	*/
	Ciphertext<Element> Relinearize(ConstCiphertext<Element> ct) const {

		const auto ek = GetEvalMultKeyVector(ct->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->Relinearize(ct, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalRelin, TOC_US(t)) );
		}
		return rv;

	}

	/**
	 * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
	 * @param pt2
	 * @param ct1
	 * @return new ciphertext for ct1 * pt2
	 */
	inline Ciphertext<Element>
	EvalMult(ConstPlaintext pt2, ConstCiphertext<Element> ct1) const
	{
		return EvalMult(ct1, pt2);
	}

	/**
	 * EvalMult - PALISADE EvalMultMutable method for plaintext * ciphertext
	 * @param pt2
	 * @param ct1
	 * @return new ciphertext for ct1 * pt2
	 */
	inline Ciphertext<Element>
	EvalMultMutable(Plaintext pt2, Ciphertext<Element> &ct1) const
	{
		return EvalMultMutable(ct1, pt2);
	}

	/**
	 * EvalMult - PALISADE EvalMult method for constant * ciphertext
	 * @param constant
	 * @param ct1
	 * @return new ciphertext for ct1 * constant
	 */
	inline Ciphertext<Element>
	EvalMult(double constant, ConstCiphertext<Element> ct1) const
	{
		return EvalMult(ct1, constant);
	}

	inline Ciphertext<Element>
	EvalMultMutable(double constant, Ciphertext<Element> &ct1) const
	{
		return EvalMultMutable(ct1, constant);
	}

	/**
	 * EvalShiftRight - works only for Fractional Encoding
	 * @param pt2
	 * @param ct1
	 * @return new ciphertext for ct1 * pt2
	 */
	Ciphertext<Element>
	EvalRightShift(ConstCiphertext<Element> ct1, size_t divisor) const
	{
		if( ct1 && ct1->GetEncodingType() != Fractional ) {
			stringstream ss;
			ss << "A " << Fractional << " encoded ciphertext is required for the EvalRightShift operation";
			PALISADE_THROW( type_error, ss.str() );
		}

		Plaintext plaintextShift = MakeFractionalPlaintext(0,divisor);
		TypeCheck(ct1, plaintextShift);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = EvalMult(ct1, plaintextShift);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalRightShift, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
	 * @param ct1
	 * @param pt2
	 * @return new ciphertext for ct1 * pt2
	 */
	Ciphertext<Element>
	EvalMult(ConstCiphertext<Element> ct1, ConstPlaintext pt2) const
	{
		TypeCheck(ct1, pt2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, pt2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMultMutable method for plaintext * ciphertext
	 * This is a mutable version - input ciphertexts may get automatically
	 * rescaled, or level-reduced.
	 *
	 * @param ct1
	 * @param pt2
	 * @return new ciphertext for ct1 * pt2
	 */
	Ciphertext<Element>
	EvalMultMutable(Ciphertext<Element> &ct1, Plaintext pt2) const
	{
		TypeCheck((ConstCiphertext<Element>) ct1, (ConstPlaintext) pt2);

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ct1, pt2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalMult - PALISADE EvalSub method for a ciphertext and constant
	* @param ciphertext
	* @param constant
	* @return new ciphertext for ciphertext - constant
	*/
	Ciphertext<Element>
	EvalMult(ConstCiphertext<Element> ciphertext, double constant) const
	{

		TimeVar t;
		if( doTiming ) TIC(t);

		auto rv = GetEncryptionAlgorithm()->EvalMult(ciphertext, constant);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultConst, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalMult - PALISADE EvalSub method for a ciphertext and constant
	* This is a mutable version - input ciphertexts may get automatically
	* rescaled, or level-reduced.
	*
	* @param ciphertext
	* @param constant
	* @return new ciphertext for ciphertext - constant
	*/
	Ciphertext<Element>
	EvalMultMutable(Ciphertext<Element> &ciphertext, double constant) const
	{

		TimeVar t;
		if( doTiming ) TIC(t);

		auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ciphertext, constant);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultConst, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalMultMatrix - PALISADE EvalMult method for two matrices of ciphertext
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 * ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalMultMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		Matrix<RationalCiphertext<Element>> rv = *ct1 * *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultMatrix, TOC_US(t)) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	* EvalSub - PALISADE Negate method for a ciphertext
	* @param ct
	* @return new ciphertext -ct
	*/
	Ciphertext<Element>
	EvalNegate(ConstCiphertext<Element> ct) const
	{
		if (ct == NULL || Mismatched(ct->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to EvalNegate was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalNegate(ct);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalNeg, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalSub - PALISADE Negate method for a ciphertext
	* @param ct
	* @return new ciphertext -ct
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalNegateMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct) const
	{
		if (ct == NULL || Mismatched((*ct)(0,0).GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to EvalNegateMatrix was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		shared_ptr<Matrix<RationalCiphertext<Element>>> m(
				new Matrix<RationalCiphertext<Element>>(ct->GetAllocator(), ct->GetRows(), ct->GetCols()));
		for( size_t r = 0; r < m->GetRows(); r++ )
			for( size_t c = 0; c < m->GetCols(); c++ )
				(*m)(r,c) = -((*ct)(r,c));
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalNegMatrix, TOC_US(t)) );
		}
		return m;
	}

	/**
	* Generate automophism keys for a given private key
	*
	* @param publicKey original public key.
	* @param origPrivateKey original private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
		const LPPrivateKey<Element> origPrivateKey, const std::vector<usint> &indexList) const {

		if( publicKey == NULL || origPrivateKey == NULL )
			PALISADE_THROW( type_error, "Null Keys");
		if( publicKey->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Key was not created in this CryptoContextImpl");
		if( publicKey->GetCryptoContext() != origPrivateKey->GetCryptoContext() )
			PALISADE_THROW( type_error, "Keys were not created in the same CryptoContextImpl");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(publicKey, origPrivateKey, indexList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismKeyGen, TOC_US(t)) );
		}
		return rv;
	}



	/**
	* Function for evaluating automorphism of ciphertext at index i
	*
	* @param ciphertext the input ciphertext.
	* @param i automorphism index
	* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

		auto mf = evalKeys.begin();
		if( mf == evalKeys.end() )
			PALISADE_THROW( type_error, "Empty key map");
		auto tk = mf->second;
		if( ciphertext == NULL || tk == NULL )
			PALISADE_THROW( type_error, "Null inputs");
		if( ciphertext->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( ciphertext->GetCryptoContext() != tk->GetCryptoContext() )
			PALISADE_THROW( type_error, "Items were not created in the same CryptoContextImpl");
		if( ciphertext->GetKeyTag() != tk->GetKeyTag() )
			PALISADE_THROW( type_error, "Items were not encrypted with same keys" );

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphism(ciphertext, i, evalKeys);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismI, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* Generate automophism keys for a given private key; Uses the private key for encryption
	*
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const {

		if( privateKey == NULL )
			PALISADE_THROW( type_error, "Null input");
		if( privateKey->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Key was not created in this CryptoContextImpl");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(privateKey, indexList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismK, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* EvalSumKeyGen Generates the key map to be used by evalsum
	*
	* @param privateKey private key.
	* @param publicKey public key (used in NTRU schemes).
	*/
	void EvalSumKeyGen(
		const LPPrivateKey<Element> privateKey, 
		const LPPublicKey<Element> publicKey = nullptr);

	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(
		const LPPrivateKey<Element> privateKey,
		const LPPublicKey<Element> publicKey = nullptr, usint rowSize = 0);

	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(
		const LPPrivateKey<Element> privateKey,
		const LPPublicKey<Element> publicKey = nullptr);

	/**
	 * GetEvalSumKey  returns the map
	 *
	 * @return the EvalSum key map
	 */
	static const std::map<usint, LPEvalKey<Element>>& GetEvalSumKeyMap(const string& id);

	static const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& GetAllEvalSumKeys();

	/**
	* Function for evaluating a sum of all components
	*
	* @param ciphertext the input ciphertext.
	* @param batchSize size of the batch
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const;

	Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize, const std::map<usint, LPEvalKey<Element>> &evalKeys) const;

	Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint rowSize, const std::map<usint, LPEvalKey<Element>> &evalKeys) const;

	/**
	* EvalSumKeyGen Generates the key map to be used by evalsum
	*
	* @param privateKey private key.
	* @param indexList list of indices.
	* @param publicKey public key (used in NTRU schemes).
	*/
	void EvalAtIndexKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<int32_t> &indexList, const LPPublicKey<Element> publicKey = nullptr);


	/**
	 * EvalFastRotationPrecompute implements the precomputation step of
	 * hoisted automorphisms.
	 *
	 * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
	 * linear transformations in HELib." for more details, link:
	 * https://eprint.iacr.org/2018/244.
	 *
	 * Generally, automorphisms are performed with three steps: (1) the automorphism is
	 * applied on the ciphertext, (2) the automorphed values are decomposed into digits,
	 * and (3) key switching is applied to make it possible to further compute on the
	 * ciphertext.
	 *
	 * Hoisted automorphisms is a technique that performs the digit decomposition for the
	 * original ciphertext first, and then performs the automorphism and the key switching
	 * on the decomposed digits. The benefit of this is that the digit decomposition is
	 * independent of the automorphism rotation index, so it can be reused for multiple
	 * different indices. This can greatly improve performance when we have to compute many
	 * automorphisms on the same ciphertext. This routinely happens when we do permutations
	 * (EvalPermute).
	 *
	 * EvalFastRotationPrecompute implements the digit decomposition step of hoisted
	 * automorphisms.
	 *
	 * @param ct the input ciphertext on which to do the precomputation (digit decomposition)
	 */
	shared_ptr<vector<Element>> EvalFastRotationPrecompute(
			ConstCiphertext<Element> ct
			) const {

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalFastRotationPrecompute(ct);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpFastRotPrecomp, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * EvalFastRotation implements the automorphism and key switching step of
	 * hoisted automorphisms.
	 *
	 * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
	 * linear transformations in HELib." for more details, link:
	 * https://eprint.iacr.org/2018/244.
	 *
	 * Generally, automorphisms are performed with three steps: (1) the automorphism is
	 * applied on the ciphertext, (2) the automorphed values are decomposed into digits,
	 * and (3) key switching is applied to make it possible to further compute on the
	 * ciphertext.
	 *
	 * Hoisted automorphisms is a technique that performs the digit decomposition for the
	 * original ciphertext first, and then performs the automorphism and the key switching
	 * on the decomposed digits. The benefit of this is that the digit decomposition is
	 * independent of the automorphism rotation index, so it can be reused for multiple
	 * different indices. This can greatly improve performance when we have to compute many
	 * automorphisms on the same ciphertext. This routinely happens when we do permutations
	 * (EvalPermute).
	 *
	 * EvalFastRotation implements the automorphism and key swithcing step of hoisted
	 * automorphisms.
	 *
	 * This method assumes that all required rotation keys exist. This may not be true
	 * if we are using baby-step/giant-step key switching. Please refer to Section 5.1 of
	 * the above reference and EvalPermuteBGStepHoisted to see how to deal with this issue.
	 *
	 * @param ct the input ciphertext to perform the automorphism on
	 * @param index the index of the rotation. Positive indices correspond to left rotations
	 * 		  and negative indices correspond to right rotations.
	 * @param m is the cyclotomic order
	 * @param digits the digit decomposition created by EvalFastRotationPrecompute at
	 * 		  the precomputation step.
	 */
	Ciphertext<Element> EvalFastRotation(
			ConstCiphertext<Element> ct,
			const usint index,
			const usint m,
			const shared_ptr<vector<Element>> digits
			) const {

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalFastRotation(ct, index, m, digits);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpFastRot, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext
	* The slot assignment is done based on the order of ciphertexts in the vector
	*
	* @param ciphertextVector vector of ciphertexts to be merged.
	* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalMerge(const vector<Ciphertext<Element>> &ciphertextVector) const;

	/**
	 * GetEvalAutomorphismKey  returns the map
	 *
	 * @return the EvalAutomorphism key map
	 */
	static const std::map<usint, LPEvalKey<Element>>& GetEvalAutomorphismKeyMap(const string& id);

	static const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& GetAllEvalAutomorphismKeys();

	/**
	* Moves i-th slot to slot 0
	*
	* @param ciphertext.
	* @param i the index.
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const;

	/**
	* Evaluates inner product in batched encoding
	*
	* @param ciphertext1 first vector.
	* @param ciphertext2 second vector.
	* @param batchSize size of the batch to be summed up
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2, usint batchSize) const;

	/**
	* Evaluates inner product in batched encoding
	*
	* @param ciphertext1 first vector.
	* @param ciphertext2 second vector.
	* @param batchSize size of the batch to be summed up
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1, ConstPlaintext ciphertext2, usint batchSize) const;

	/**
	* EvalCrossCorrelation - Computes the sliding sum of inner products (known as
	* as cross-correlation, sliding inner product, or sliding dot product in
	* image processing
	* @param x - first vector of row vectors
	* @param y - second vector of row vectors
	* @param batchSize - batch size for packed encoding
	* @param indexStart - starting index in the vectors of row vectors
	* @param length - length of the slice in the vectors of row vectors; default is 0 meaning to use the full length of the vector
	* @return sum(x_i*y_i), i.e., a sum of inner products
	*/
	Ciphertext<Element>
		EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
			usint indexStart = 0, usint length = 0) const;

	/**
	* EvalLinRegressBatched- Computes the parameter vector for linear regression using the least squares method
	* Supported only in batched mode; currently works only for two regressors
	* @param x - matrix of regressors
	* @param y - vector of dependent variables
	* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
		EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const;

	/**
	* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
	* @param x - matrix of regressors
	* @param y - vector of dependent variables
	* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
		EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
	{
		TypeCheck((*x)(0,0), (*y)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->EvalLinRegression(x, y);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpLinRegression, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* KeySwitch - PALISADE KeySwitch method
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	* @return new CiphertextImpl after applying key switch
	*/
	Ciphertext<Element> KeySwitch(
		const LPEvalKey<Element> keySwitchHint,
		ConstCiphertext<Element> ciphertext) const
	{
		if( keySwitchHint == NULL || Mismatched(keySwitchHint->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Key passed to KeySwitch was not generated with this crypto context");

		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Ciphertext passed to KeySwitch was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->KeySwitch(keySwitchHint, ciphertext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeySwitch, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * Rescale - An alias for PALISADE ModReduce method.
	 * This is because ModReduce is called Rescale in CKKS.
	 *
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	Ciphertext<Element> Rescale(ConstCiphertext<Element> ciphertext) const {
		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to Rescale was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->ModReduce(ciphertext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduce, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext) const {
		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Information passed to ModReduce was not generated with this crypto context");

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->ModReduce(ciphertext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduce, TOC_US(t)) );
		}
		return rv;
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	RationalCiphertext<Element> ModReduceRational(RationalCiphertext<Element> ciphertext) const {

		TimeVar t;
		if( doTiming ) TIC(t);
		Ciphertext<Element> n = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetNumerator());
		Ciphertext<Element> d = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetDenominator());
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduce, TOC_US(t)) );
		}
		return RationalCiphertext<Element>(n,d);
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>> ModReduceMatrix(shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext) const {
		// needs context check

		TimeVar t;
		if( doTiming ) TIC(t);
		shared_ptr<Matrix<RationalCiphertext<Element>>> m(
				new Matrix<RationalCiphertext<Element>>(ciphertext->GetAllocator(), ciphertext->GetRows(), ciphertext->GetCols()));
		for( size_t r = 0; r < m->GetRows(); r++ )
			for( size_t c = 0; c < m->GetCols(); c++ )
				(*m)(r,c) = ModReduceRational((*ciphertext)(r,c));
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduceMatrix, TOC_US(t)) );
		}
		return m;
	}

	/**
	* LevelReduce - PALISADE LevelReduce method
	* @param cipherText1
	* @param linearKeySwitchHint
	* @return vector of level reduced ciphertext
	*/
	Ciphertext<Element> LevelReduce(ConstCiphertext<Element> cipherText1,
		const LPEvalKeyNTRU<Element> linearKeySwitchHint, size_t levels = 1) const {

		const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(cipherText1->GetCryptoParameters());

		if( cipherText1 == NULL ||
				Mismatched(cipherText1->GetCryptoContext()) ) {
			PALISADE_THROW(config_error, "Information passed to LevelReduce was not generated with this crypto context");
		}

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->LevelReduce(cipherText1, linearKeySwitchHint, levels);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpLevelReduce, TOC_US(t)) );
		}
		return rv;
	}

	/**
	* ComposedEvalMult - PALISADE composed evalmult
	* @param ciphertext1 - vector for first cipher text
	* @param ciphertext2 - vector for second cipher text
	* @param quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* return vector of resulting ciphertext
	*/
	Ciphertext<Element> ComposedEvalMult(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{
		if( ciphertext1 == NULL || ciphertext2 == NULL || ciphertext1->GetKeyTag() != ciphertext2->GetKeyTag() ||
				Mismatched(ciphertext1->GetCryptoContext()) )
			PALISADE_THROW(config_error, "Ciphertexts passed to ComposedEvalMult were not generated with this crypto context");

		auto ek = GetEvalMultKeyVector(ciphertext1->GetKeyTag());

		TimeVar t;
		if( doTiming ) TIC(t);
		auto rv = GetEncryptionAlgorithm()->ComposedEvalMult(ciphertext1, ciphertext2, ek[0]);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpComposedEvalMult, TOC_US(t)) );
		}
		return rv;
	}

	static LPPublicKey<Element>	deserializePublicKey(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static LPPrivateKey<Element> deserializeSecretKey(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static LPEvalKey<Element> deserializeEvalKey(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
	static LPEvalKey<Element> deserializeEvalKeyInContext(const Serialized& serObj, CryptoContext<Element> cc) __attribute__ ((deprecated("serialization changed, see wiki for details")));

	template <class Archive>
	void save( Archive & ar, std::uint32_t const version ) const
	{
		ar( cereal::make_nvp("cc", params) );
		ar( cereal::make_nvp("kt", scheme) );
		ar( cereal::make_nvp("si", m_schemeId) );
	}

	template <class Archive>
	void load( Archive & ar, std::uint32_t const version )
	{
		if( version > SerializedVersion() ) {
			PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
		}
		ar( cereal::make_nvp("cc", params) );
		ar( cereal::make_nvp("kt", scheme) );
		ar( cereal::make_nvp("si", m_schemeId) );

		// NOTE: a pointer to this object will be wrapped in a shared_ptr, and is a "CryptoContext".
		// PALISADE relies on the notion that identical CryptoContextImpls are not duplicated in memory
		// Once we deserialize this object, we must check to see if there is a matching object
		// for this object that's already existing in memory
		// if it DOES exist, use it. If it does NOT exist, add this to the cache of all contexts

	}

	virtual std::string SerializedObjectName() const { return "CryptoContext"; }
	static uint32_t	SerializedVersion() { return 1; }

};

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template<typename Element>
class CryptoObject {
protected:
	CryptoContext<Element>	context;		/*!< crypto context this object belongs to */
	string					keyTag;		/*!< tag used to find the evaluation key needed for SHE/FHE operations */

public:

	CryptoObject(CryptoContext<Element> cc = 0, const string& tag = "") : context(cc), keyTag(tag) {}

	CryptoObject(const CryptoObject& rhs) {
		context = rhs.context;
		keyTag = rhs.keyTag;
	}

	CryptoObject(const CryptoObject&& rhs) {
		context = std::move(rhs.context);
		keyTag = std::move(rhs.keyTag);
	}

	virtual ~CryptoObject() {}

	const CryptoObject& operator=(const CryptoObject& rhs) {
		this->context = rhs.context;
		this->keyTag = rhs.keyTag;
		return *this;
	}

	const CryptoObject& operator=(const CryptoObject&& rhs) {
		this->context = std::move(rhs.context);
		this->keyTag = std::move(rhs.keyTag);
		return *this;
	}

	bool operator==(const CryptoObject& rhs) const {
		return context.get() == rhs.context.get() &&
				keyTag == rhs.keyTag;
	}

	CryptoContext<Element> GetCryptoContext() const { return context; }

	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return context->GetCryptoParameters(); }

	const EncodingParams GetEncodingParameters() const { return context->GetCryptoParameters()->GetEncodingParams(); }



	const string GetKeyTag() const { return keyTag; }

	void SetKeyTag(const string& tag) { keyTag = tag; }

	template <class Archive>
	void save( Archive & ar, std::uint32_t const version ) const
	{
		ar( ::cereal::make_nvp("cc", context) );
		ar( ::cereal::make_nvp("kt", keyTag) );
	}

	template <class Archive>
	void load( Archive & ar, std::uint32_t const version )
	{
		if( version > SerializedVersion() ) {
			PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
		}
		ar( ::cereal::make_nvp("cc", context) );
		ar( ::cereal::make_nvp("kt", keyTag) );

		context = CryptoContextFactory<Element>::GetContext(context->GetCryptoParameters(),context->GetEncryptionAlgorithm());
	}

	std::string SerializedObjectName() const { return "CryptoObject"; }
	static uint32_t	SerializedVersion() { return 1; }
};

/**
* @brief CryptoContextFactory
*
* A class that contains static methods to generate new crypto contexts from user parameters
*
*/
template<typename Element>
class CryptoContextFactory {

protected:

	static vector<CryptoContext<Element>>		AllContexts;

public:

	static void ReleaseAllContexts();

	static int GetContextCount();

	static CryptoContext<Element> GetSingleContext();

	static CryptoContext<Element> GetContext(
			shared_ptr<LPCryptoParameters<Element>> params,
			shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
			const string & schemeId = "Not");

	static CryptoContext<Element> GetContextForPointer(CryptoContextImpl<Element>* cc);

	static const vector<CryptoContext<Element>>& GetAllContexts();

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme
	* @param params ring parameters
	* @param plaintextModulus plaintext modulus
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param delta - the plaintext scaling parameter floor(q/t) in BFV
	* @param mode - mode for generating secret keys (RLWE vs OPTIMIZED)
	* @param bigmodulus - large modulus used in tensoring of homomorphic multiplication
	* @param bigrootofunity - root of unity for bigmodulus
	* @param depth of supported computation circuit (not used; for future use)
	* @param assuranceMeasure alpha - effective bound for gaussians: - sqrt{alpha}*sigma..sqrt{alpha}*sigma
	* @param security level - root Hermite factor
	* @param bigmodulusarb - additional large modulus for bigmoduls for the case of general (non-power-of-two) cyclotomics
	* @param bigrootofunityarb - root of unity for bigmodulusarb
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0", int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme
	* @param params ring parameters
	* @param encodingParams plaintext encoding parameters
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param delta - the plaintext scaling parameter floor(q/t) in BFV
	* @param mode - mode for generating secret keys (RLWE vs OPTIMIZED)
	* @param bigmodulus - large modulus used in tensoring of homomorphic multiplication
	* @param bigrootofunity - root of unity for bigmodulus
	* @param depth of supported computation circuit (not used; for future use)
	* @param assuranceMeasure alpha - effective bound for gaussians: - sqrt{alpha}*sigma..sqrt{alpha}*sigma
	* @param security level - root Hermite factor
	* @param bigmodulusarb - additional large modulus for bigmoduls for the case of general (non-power-of-two) cyclotomics
	* @param bigrootofunityarb - root of unity for bigmodulusarb
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0", int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel standard security level
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel standard security level
	* @param distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		EncodingParams encodingParams, SecurityLevel securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow the key switching window (bits in the base for digits) used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel standard secuirity level
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow the key switching window (bits in the base for digits) used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel standard security level
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus plaintext modulus
	* @param securityLevel standard security level
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel root Hermite factor (lattice security parameter)
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrnsB(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the scheme's ParamsGen methods
	* @param encodingParams plaintext encoding parameters
	* @param securityLevel standard security level
	* @param dist distribution parameter for Gaussian noise generation
	* @param numAdds additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero)
	* @param numMults multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
	* @param numKeyswitches  key-switching depth for homomorphic computations  (assumes numAdds and numMults are set to zero)
 	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization
	* @param relinWindow  the key switching window used for digit decomposition (0 - means to use only CRT decomposition)
	* @param dcrtBits size of "small" CRT moduli
	* @param n ring dimension in case the user wants to use a custom ring dimension
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrnsB(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
		uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

	/**
	* construct a PALISADE CryptoContextImpl for the BGV Scheme
	* @param params ring parameters
	* @param plaintextModulus plaintext modulus
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param depth of supported computation circuit (not used; for future use)
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBGV(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContextImpl for the BGV Scheme
	* @param params ring parameters
	* @param encodingParams plaintext encoding parameters
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param mode secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution])
	* @param depth of supported computation circuit (not used; for future use)
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBGV(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContextImpl for the CKKS Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @param depth
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated
	* @param ksTech key switching technique to use (e.g., GHS or BV)
	* @param rsTech rescaling technique to use (e.g., APPROXRESCALE or EXACTRESCALE)
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextCKKS(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1, int maxDepth = 2,
		KeySwitchTechnique ksTech = BV,
		RescalingTechnique rsTech = APPROXRESCALE);

	/**
	* construct a PALISADE CryptoContextImpl for the CKKS Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated
	* @param ksTech key switching technique to use (e.g., GHS or BV)
	* @param rsTech rescaling technique to use (e.g., APPROXRESCALE or EXACTRESCALE)
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextCKKS(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1, int maxDepth = 2,
		enum KeySwitchTechnique ksTech = BV,
		RescalingTechnique rsTech = APPROXRESCALE);

	/**
	* Automatically generate the moduli chain and construct a PALISADE
	* CryptoContextImpl for the CKKS Scheme with it.
	*
	* @param cyclOrder the cyclotomic order M
	* @param numPrimes the number of towers/primes to use when building the moduli chain
	* @param scaleExp the plaintext scaling factor, which is equal to dcrtBits in our implementation of CKKS
	* @param batchSize the batch size of the ciphertext
	* @param mode RLWE or OPTIMIZED
	* @param depth
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated
	* @param firstModSize the bit-length of the first modulus
	* @param ksTech key switching technique to use (e.g., GHS or BV)
	* @param rsTech rescaling technique to use (e.g., APPROXRESCALE or EXACTRESCALE)
	* @param numLargeDigits the number of big digits to use in HYBRID key switching
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextCKKSWithParamsGen(
		   usint cyclOrder,
		   usint numPrimes,
		   usint scaleExp,
		   usint relinWindow,
		   usint batchSize,
		   MODE mode,
		   int depth = 1,
		   int maxDepth = 2,
		   usint firstModSize = 60,
		   enum KeySwitchTechnique ksTech = BV,
		   enum RescalingTechnique rsTech = APPROXRESCALE,
		   uint32_t numLargeDigits = 4);

	/**
	* Construct a PALISADE CryptoContextImpl for the CKKS Scheme.
	*
	* @param multiplicativeDepth the depth of multiplications supported by the scheme (equal to number of towers - 1)
	* @param scalingFactorBits the size of the scaling factor in bits
	* @param batchSize the number of slots being used in the ciphertext
	* @param stdLevel the standard security level we want the scheme to satisfy
	* @param ringDim the ring dimension (if not specified selected automatically based on stdLevel)
	* @param ksTech key switching technique to use (e.g., HYBRID, GHS or BV)
	* @param rsTech rescaling technique to use (e.g., APPROXRESCALE or EXACTRESCALE)
	* @param numLargeDigits the number of big digits to use in HYBRID key switching
	* @param maxDepth the maximum power of secret key for which the relinearization key is generated
	* @param firstModSize the bit-length of the first modulus
	* @param relinWindow the relinearization windows (used in BV key switching, use 0 for RNS decomposition)
	* @param mode RLWE (gaussian distribution) or OPTIMIZED (ternary distribution)
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextCKKS(
			   usint multiplicativeDepth,
			   usint scalingFactorBits,
			   usint batchSize,
			   SecurityLevel stdLevel = HEStd_128_classic,
			   usint ringDim = 0,
			   enum RescalingTechnique rsTech = EXACTRESCALE,
			   enum KeySwitchTechnique ksTech = HYBRID,
			   uint32_t numLargeDigits = 0,
			   int maxDepth = 2,
			   usint firstModSize = 60,
			   usint relinWindow = 0,
			   MODE mode = OPTIMIZED);

	/**
	* construct a PALISADE CryptoContextImpl for the StehleSteinfeld Scheme
	* @param params ring parameters
	* @param plaintextModulus plaintext modulus
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param stdDev distribution parameter for secret key distribution
	* @param depth of supported computation circuit (not used; for future use)
	* @param assuranceMeasure alpha - effective bound for gaussians: - sqrt{alpha}*sigma..sqrt{alpha}*sigma
	* @param security level - root Hermite factor
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the StehleSteinfeld Scheme
	* @param params ring parameters
	* @param encodingParams plaintext encoding parameters
	* @param relinWindow bits in the base of digits in key switching/relinearization
	* @param stdDev sigma - distribution parameter for error distribution
	* @param stdDev distribution parameter for secret key distribution
	* @param depth of supported computation circuit (not used; for future use)
	* @param assuranceMeasure alpha - effective bound for gaussians: - sqrt{alpha}*sigma..sqrt{alpha}*sigma
	* @param security level - root Hermite factor
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the Null Scheme
	* @param m cyclotomic order (ring dimension n = m/2 for power-of-two cyclotomics)
	* @param plaintextModulus plaintext modulus
	* @return
	*/
	static CryptoContext<Element> genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus);

	/**
	* construct a PALISADE CryptoContextImpl for the Null Scheme
	* @param m cyclotomic order (ring dimension n = m/2 for power-of-two cyclotomics)
	* @param encodingParams plaintext encoding parameters
	* @return
	*/
	static CryptoContext<Element> genCryptoContextNull(unsigned int m, EncodingParams encodingParams);

	static CryptoContext<Element> DeserializeAndCreateContext(const Serialized& serObj) __attribute__ ((deprecated("serialization changed, see wiki for details")));
};


}

#endif /* SRC_PKE_CRYPTOCONTEXT_H_ */
