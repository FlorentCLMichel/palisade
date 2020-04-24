/**
 * @file pubkeylp.h -- Public key type for lattice crypto operations.
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

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

//Includes Section
#include <vector>
#include <iomanip>
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/inttypes.h"
#include "utils/hashutil.h"
#include "math/distrgen.h"
#include "encoding/encodingparams.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/* This struct holds the different options for
	 * key switching algorithms that are supported
	 * by the library.
	 *
	 */
	enum KeySwitchTechnique {
		BV,
		GHS,
		HYBRID
	};

	//forward declarations, used to resolve circular header dependencies
	template<typename Element>
	class CiphertextImpl;

	template<typename Element>
	class RationalCiphertext;

	template<typename Element>
	class LPCryptoParameters;

	template<typename Element>
	class LPCryptoParametersBGV;

	template<typename Element>
	class LPCryptoParametersBFV;

	template<typename Element>
	class LPCryptoParametersStehleSteinfeld;

	template<typename Element>
	class CryptoObject;

	struct EncryptResult {

		explicit EncryptResult() : isValid(false), numBytesEncrypted(0) {}

		explicit EncryptResult(size_t len) : isValid(true), numBytesEncrypted(len) {}

		bool isValid;				/**< whether the encryption was successful */
		usint	numBytesEncrypted;	/**< count of the number of plaintext bytes that were encrypted */
	};

	/** 
	 * @brief Decryption result.  This represents whether the decryption of a cipheretext was performed correctly.
	 *
     * This is intended to eventually incorporate information about the amount of padding in a decoded ciphertext,
     * to ensure that the correct amount of padding is stripped away.
	 * It is intended to provided a very simple kind of checksum eventually.
	 * This notion of a decoding output is inherited from the crypto++ library.
	 * It is also intended to be used in a recover and restart robust functionality if not all ciphertext is recieved over a lossy channel, so that if all information is eventually recieved, decoding/decryption can be performed eventually.
	 * This is intended to be returned with the output of a decryption operation.
	 */
	struct DecryptResult {
		/**
		 * Constructor that initializes all message lengths to 0.
		 */
		explicit DecryptResult() : isValid(false), messageLength(0) {}

		/**
		 * Constructor that initializes all message lengths.
		 * @param len the new length.
		 */
		explicit DecryptResult(size_t len) : isValid(true), messageLength(len) {}

		bool isValid;			/**< whether the decryption was successful */
		usint messageLength;	/**< the length of the decrypted plaintext message */
	};

	/**
	 * @brief Abstract interface class for LP Keys
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKey : public CryptoObject<Element>, public Serializable {
	public:
		LPKey(CryptoContext<Element> cc, const string& id = "") : CryptoObject<Element>(cc, id) {}

		LPKey(shared_ptr<CryptoObject<Element>> co) : CryptoObject<Element>(co) {}

		virtual ~LPKey() {}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<CryptoObject<Element>>( this ) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
		    ar( ::cereal::base_class<CryptoObject<Element>>( this ) );
		}
	};

	template<typename Element>
	class LPPublicKeyImpl;

	template<typename Element>
	using LPPublicKey = shared_ptr<LPPublicKeyImpl<Element>>;

	/**
	 * @brief Class for LP public keys
	 * @tparam Element a ring element.
	 */
	template <typename Element>
	class LPPublicKeyImpl : public LPKey<Element> {
	public:

		/**
		 * Basic constructor
		 *
		 * @param cc - CryptoContext
		 * @param id - key identifier
		 */
		LPPublicKeyImpl(CryptoContext<Element> cc = 0, const string& id = "") : LPKey<Element>(cc, id) {}

		/**
		 * Copy constructor
		 *
		 *@param &rhs LPPublicKeyImpl to copy from
		 */
		explicit LPPublicKeyImpl(const LPPublicKeyImpl<Element> &rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			m_h = rhs.m_h;
		}

		/**
		 * Move constructor
		 *
		 *@param &rhs LPPublicKeyImpl to move from
		 */
		explicit LPPublicKeyImpl(LPPublicKeyImpl<Element> &&rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			m_h = std::move(rhs.m_h);
		}

		operator bool() const { return bool(this->context) && m_h.size() != 0; }

		/**
		 * Assignment Operator.
		 *
		 * @param &rhs LPPublicKeyImpl to copy from
		 */
		const LPPublicKeyImpl<Element>& operator=(const LPPublicKeyImpl<Element> &rhs) {
			CryptoObject<Element>::operator=(rhs);
			this->m_h = rhs.m_h;
			return *this;
		}

		/**
		 * Move Assignment Operator.
		 *
		 * @param &rhs LPPublicKeyImpl to copy from
		 */
		const LPPublicKeyImpl<Element>& operator=(LPPublicKeyImpl<Element> &&rhs) {
			CryptoObject<Element>::operator=(rhs);
			m_h = std::move(rhs.m_h);
			return *this;
		}

		//@Get Properties

		/**
		 * Gets the computed public key
		 * @return the public key element.
		 */
		const std::vector<Element> &GetPublicElements() const {
			return this->m_h;
		}

		//@Set Properties

		/**
		 * Sets the public key vector of Element.
		 * @param &element is the public key Element vector to be copied.
		 */
		void SetPublicElements(const std::vector<Element> &element) {
			m_h = element;
		}

		/**
		 * Sets the public key vector of Element.
		 * @param &&element is the public key Element vector to be moved.
		 */
		void SetPublicElements(std::vector<Element> &&element) {
			m_h = std::move(element);
		}

		/**
		 * Sets the public key Element at index idx.
		 * @param &element is the public key Element to be copied.
		 */
		void SetPublicElementAtIndex(usint idx, const Element &element) {
			m_h.insert(m_h.begin() + idx, element);
		}

		/**
		 * Sets the public key Element at index idx.
		 * @param &&element is the public key Element to be moved.
		 */
		void SetPublicElementAtIndex(usint idx, Element &&element) {
			m_h.insert(m_h.begin() + idx, std::move(element));
		}

		bool operator==(const LPPublicKeyImpl& other) const {
			if( !CryptoObject<Element>::operator ==(other) ) {
				return false;
			}

			if( m_h.size() != other.m_h.size() ) {
				return false;
			}

			for( size_t i = 0; i < m_h.size(); i++ ) {
				if( m_h[i] != other.m_h[i] ) {
					return false;
				}
			}

			return true;
		}

		bool operator!=(const LPPublicKeyImpl& other) const { return ! (*this == other); }

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
			ar( ::cereal::base_class<LPKey<Element>>( this ) );
			ar( ::cereal::make_nvp("h",m_h) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
			ar( ::cereal::base_class<LPKey<Element>>( this ) );
			ar( ::cereal::make_nvp("h",m_h) );
		}

		std::string SerializedObjectName() const { return "PublicKey"; }
		static uint32_t	SerializedVersion() { return 1; }

	private:
		std::vector<Element> m_h;
	};

	template<typename Element>
	class LPEvalKeyImpl;

	template<typename Element>
	using LPEvalKey = shared_ptr<LPEvalKeyImpl<Element>>;

	/**
	* @brief Abstract interface for LP evaluation/proxy keys
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyImpl : public LPKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyImpl(CryptoContext<Element> cc = 0) : LPKey<Element>(cc) {}

		virtual ~LPEvalKeyImpl() {}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element vector to be copied.
		*/

		virtual void SetAVector(const std::vector<Element> &a) {
			PALISADE_THROW(not_implemented_error, "SetAVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element vector to be moved.
		*/

		virtual void SetAVector(std::vector<Element> &&a) {
			PALISADE_THROW(not_implemented_error, "SetAVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @return Element vector A.
		*/

		virtual const std::vector<Element> &GetAVector() const {
			PALISADE_THROW(not_implemented_error, "GetAVector operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &b is the Element vector to be copied.
		*/

		virtual void SetBVector(const std::vector<Element> &b) {
			PALISADE_THROW(not_implemented_error, "SetBVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&b is the Element vector to be moved.
		*/

		virtual void SetBVector(std::vector<Element> &&b) {
			PALISADE_THROW(not_implemented_error, "SetBVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element vector B.
		*/

		virtual const std::vector<Element> &GetBVector() const {
			PALISADE_THROW(not_implemented_error, "GetBVector operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element to be copied.
		*/

		virtual void SetA(const Element &a) {
			PALISADE_THROW(not_implemented_error, "SetA copy operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			PALISADE_THROW(not_implemented_error, "SetA move operation not supported");
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const Element &GetA() const {
			PALISADE_THROW(not_implemented_error, "GetA operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element to be copied.
		*/

		virtual void SetAinDCRT(const DCRTPoly &a) {
			PALISADE_THROW(not_implemented_error, "SetAinDCRT copy operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element to be moved.
		*/
		virtual void SetAinDCRT(DCRTPoly &&a) {
			PALISADE_THROW(not_implemented_error, "SetAinDCRT move operation not supported");
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const DCRTPoly &GetAinDCRT() const {
			PALISADE_THROW(not_implemented_error, "GetAinDCRT operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &b is the Element to be copied.
		*/

		virtual void SetBinDCRT(const DCRTPoly &b) {
			PALISADE_THROW(not_implemented_error, "SetAinDCRT copy operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&b is the Element to be moved.
		*/
		virtual void SetBinDCRT(DCRTPoly &&b) {
			PALISADE_THROW(not_implemented_error, "SetAinDCRT move operation not supported");
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const DCRTPoly &GetBinDCRT() const {
			PALISADE_THROW(not_implemented_error, "GetAinDCRT operation not supported");
		}

		virtual void ClearKeys() {
			PALISADE_THROW(not_implemented_error, "ClearKeys operation is not supported");
		}


		friend bool operator==(const LPEvalKeyImpl& a, const LPEvalKeyImpl& b) {
			return a.key_compare(b);
		}

		friend bool operator!=(const LPEvalKeyImpl& a, LPEvalKeyImpl& b) { return ! (a == b); }

		virtual bool key_compare(const LPEvalKeyImpl& other) const { return false; }

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<LPKey<Element>>( this ) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
		    ar( ::cereal::base_class<LPKey<Element>>( this ) );
		}
		std::string SerializedObjectName() const { return "EvalKey"; }
	};

	template<typename Element>
	class LPEvalKeyRelinImpl;

	template<typename Element>
	using LPEvalKeyRelin = shared_ptr<LPEvalKeyRelinImpl<Element>>;

	/**
	* @brief Concrete class for Relinearization keys of RLWE scheme
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyRelinImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/
		LPEvalKeyRelinImpl(CryptoContext<Element> cc = 0) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyRelinImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyRelinImpl(const LPEvalKeyRelinImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = rhs.m_rKey;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyRelinImpl(LPEvalKeyRelinImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = std::move(rhs.m_rKey);
		}

		operator bool() const { return bool(this->context) && m_rKey.size() != 0; }

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyRelinImpl<Element>& operator=(const LPEvalKeyRelinImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_rKey = rhs.m_rKey;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyRelinImpl<Element>& operator=(LPEvalKeyRelinImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_rKey = std::move(rhs.m_rKey);
			return *this;
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			m_rKey.insert(m_rKey.begin() + 0, a);
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey.insert(m_rKey.begin() + 0, std::move(a));
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey.at(0);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &b is the Element vector to be copied.
		*/
		virtual void SetBVector(const std::vector<Element> &b) {
			m_rKey.insert(m_rKey.begin() + 1, b);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &&b is the Element vector to be moved.
		*/
		virtual void SetBVector(std::vector<Element> &&b) {
			m_rKey.insert(m_rKey.begin() + 1, std::move(b));
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @return Element vector B.
		*/
		virtual const std::vector<Element> &GetBVector() const {
			return m_rKey.at(1);
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element to be copied.
		*/

		virtual void SetAinDCRT(const DCRTPoly &a) {
			m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, a);
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element to be moved.
		*/
		virtual void SetAinDCRT(DCRTPoly &&a) {
			m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, std::move(a));
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const DCRTPoly &GetAinDCRT() const {
			return m_dcrtKeys.at(0);
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &b is the Element to be copied.
		*/

		virtual void SetBinDCRT(const DCRTPoly &b) {
			m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, b);
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&b is the Element to be moved.
		*/
		virtual void SetBinDCRT(DCRTPoly &&b) {
			m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, std::move(b));
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const DCRTPoly &GetBinDCRT() const {
			return m_dcrtKeys.at(1);
		}

		virtual void ClearKeys() {
			m_rKey.clear();
			m_dcrtKeys.clear();
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const;

		/**
		* SerializeWithoutContext - serializes the object into a Serialized, withut the cryptocontext
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool SerializeWithoutContext(Serialized *serObj) const;

		/**
		 * Deserialize from the serialization
		 * @param serObj - contains the serialization
		 * @return true on success
		 */
		bool Deserialize(const Serialized &serObj);

		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyRelinImpl<Element> &oth = dynamic_cast<const LPEvalKeyRelinImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator==(other) )
				return false;

			if( this->m_rKey.size() != oth.m_rKey.size() ) return false;
			for( size_t i=0; i<this->m_rKey.size(); i++ ) {
				if( this->m_rKey[i].size() != oth.m_rKey[i].size() ) return false;
				for( size_t j=0; j<this->m_rKey[i].size(); j++ ) {
					if( this->m_rKey[i][j] != oth.m_rKey[i][j] )
						return false;
				}
			}
			return true;
		}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_rKey) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_rKey) );
		}
		std::string SerializedObjectName() const { return "EvalKeyRelin"; }
		static uint32_t	SerializedVersion() { return 1; }

	private:
		//private member to store vector of vector of Element.
		std::vector< std::vector<Element> > m_rKey;

		// Used for GHS key switching
		std::vector<DCRTPoly> m_dcrtKeys;

	};

	template<typename Element>
	class LPEvalKeyNTRURelinImpl;

	template<typename Element>
	using LPEvalKeyNTRURelin = shared_ptr<LPEvalKeyNTRURelinImpl<Element>>;

	/**
	* @brief Evaluation Relinearization keys for NTRU scheme.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRURelinImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRURelinImpl(CryptoContext<Element> cc = 0) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyNTRURelinImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyNTRURelinImpl(const LPEvalKeyNTRURelinImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = rhs.m_rKey;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyNTRURelinImpl(LPEvalKeyNTRURelinImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = std::move(rhs.m_rKey);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyNTRURelinImpl<Element>& operator=(const LPEvalKeyNTRURelinImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_rKey = rhs.m_rKey;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyNTRURelinImpl<Element>& operator=(LPEvalKeyNTRURelinImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_rKey = std::move(rhs.m_rKey);
			return *this;
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			for (usint i = 0; i < a.size(); i++) {
				m_rKey.insert(m_rKey.begin() + i, a.at(i));
			}
		}


		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey = std::move(a);
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey;
		}

		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyNTRURelinImpl<Element> &oth = dynamic_cast<const LPEvalKeyNTRURelinImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator ==(other) )
				return false;

			if( this->m_rKey.size() != oth.m_rKey.size() ) return false;
			for( size_t i=0; i<this->m_rKey.size(); i++ ) {
				if( this->m_rKey[i] != oth.m_rKey[i] )
					return false;
			}
			return true;
		}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_rKey) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_rKey) );
		}

		std::string SerializedObjectName() const { return "EvalKeyNTRURelin"; }
		static uint32_t	SerializedVersion() { return 1; }

	private:
		//private member to store vector of Element.
		std::vector<Element>  m_rKey;
	};

	template<typename Element>
	class LPEvalKeyNTRUImpl;

	template<typename Element>
	using LPEvalKeyNTRU = shared_ptr<LPEvalKeyNTRUImpl<Element>>;

	/**
	* @brief Concrete class for facilitating NTRU key switch.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRUImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRUImpl(CryptoContext<Element> cc = 0) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyNTRUImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyNTRUImpl(const LPEvalKeyNTRUImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_Key = rhs.m_Key;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyNTRUImpl(LPEvalKeyNTRUImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_Key = std::move(rhs.m_Key);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyNTRUImpl<Element>& operator=(const LPEvalKeyNTRUImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_Key = rhs.m_Key;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyNTRUImpl<Element>& operator=(LPEvalKeyNTRUImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_Key = std::move(rhs.m_Key);
			return *this;
		}

		/**
		* Setter function to store NTRU key switch element.
		* Function copies the key.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @param &a is the key switch element to be copied.
		*/

		virtual void SetA(const Element &a) {
			m_Key = a;
		}

		/**
		* Setter function to store NTRU key switch Element.
		* Function moves the key.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @param &&a is the key switch Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			m_Key = std::move(a);
		}

		/**
		* Getter function to access NTRU key switch Element.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @return NTRU key switch Element.
		*/

		virtual const Element& GetA() const {
			return m_Key;
		}

		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyNTRUImpl<Element> &oth = dynamic_cast<const LPEvalKeyNTRUImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator ==(other) )
				return false;

			if( this->m_Key != oth.m_Key )
				return false;

			return true;
		}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_Key) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
		    ar( ::cereal::base_class<LPEvalKeyImpl<Element>>( this ) );
		    ar( ::cereal::make_nvp("k", m_Key) );
		}

		std::string SerializedObjectName() const { return "EvalKeyNTRU"; }
		static uint32_t	SerializedVersion() { return 1; }

	private:

		/**
		* private member Element to store key.
		*/
		Element m_Key;
	};
	
	template<typename Element>
	class LPPrivateKeyImpl;

	template<typename Element>
	using LPPrivateKey = shared_ptr<LPPrivateKeyImpl<Element>>;

	/**
	 * @brief Class fpr LP Private keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPrivateKeyImpl : public LPKey<Element> {
	public:

		/**
		 * Construct in context
		 */

		LPPrivateKeyImpl(CryptoContext<Element> cc = 0) : LPKey<Element>(cc, GenerateUniqueKeyID()) {}

		/**
		 * Copy constructor
		 *@param &rhs the LPPrivateKeyImpl to copy from
		 */
		explicit LPPrivateKeyImpl(const LPPrivateKeyImpl<Element> &rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			this->m_sk = rhs.m_sk;
		}

		/**
		 * Move constructor
		 *@param &rhs the LPPrivateKeyImpl to move from
		 */
		explicit LPPrivateKeyImpl(LPPrivateKeyImpl<Element> &&rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			this->m_sk = std::move(rhs.m_sk);
		}

		operator bool() const { return bool(this->context); }

		/**
		 * Assignment Operator.
		 *
		 * @param &rhs LPPrivateKeyto assign from.
		 * @return the resulting LPPrivateKeyImpl
		 */
		const LPPrivateKeyImpl<Element>& operator=(const LPPrivateKeyImpl<Element> &rhs) {
			CryptoObject<Element>::operator=(rhs);
			this->m_sk = rhs.m_sk;
			return *this;
		}

		/**
		 * Move Assignment Operator.
		 *
		 * @param &rhs LPPrivateKeyImpl to assign from.
		 * @return the resulting LPPrivateKeyImpl
		 */
		const LPPrivateKeyImpl<Element>& operator=(LPPrivateKeyImpl<Element> &&rhs) {
			CryptoObject<Element>::operator=(rhs);
			this->m_sk = std::move(rhs.m_sk);
			return *this;
		}

		/**
		 * Implementation of the Get accessor for private element.
		 * @return the private element.
		 */
		const Element & GetPrivateElement() const { return m_sk; }

		/**
		 * Set accessor for private element.
		 * @private &x private element to set to.
		 */
		void SetPrivateElement(const Element &x) {
			m_sk = x;
		}

		/**
		 * Set accessor for private element.
		 * @private &x private element to set to.
		 */
		void SetPrivateElement(Element &&x) {
			m_sk = std::move(x);
		}

		bool operator==(const LPPrivateKeyImpl& other) const {
			return CryptoObject<Element>::operator ==(other) &&
					m_sk == other.m_sk;
		}

		bool operator!=(const LPPrivateKeyImpl& other) const { return ! (*this == other); }

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
			ar( ::cereal::base_class<LPKey<Element>>( this ) );
			ar( ::cereal::make_nvp("s",m_sk) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
			ar( ::cereal::base_class<LPKey<Element>>( this ) );
			ar( ::cereal::make_nvp("s",m_sk) );
		}

		std::string SerializedObjectName() const { return "PrivateKey"; }
		static uint32_t	SerializedVersion() { return 1; }

	private:

		static const size_t intsInID = 128 / (sizeof(uint32_t) * 8);

		static string GenerateUniqueKeyID() {
			std::uniform_int_distribution<uint32_t> distribution(0, std::numeric_limits<uint32_t>::max());
			std::stringstream s;
			s.fill('0');
			s << std::hex;
			for( size_t i = 0; i < intsInID; i++ )
				s << std::setw(8) << distribution(PseudoRandomNumberGenerator::GetPRNG());
			return s.str();
		}

		Element m_sk;
	};

	template <class Element>
	class LPKeyPair {
	public:
		LPPublicKey<Element>		publicKey;
		LPPrivateKey<Element>	secretKey;

		LPKeyPair(LPPublicKeyImpl<Element>* a=0, LPPrivateKeyImpl<Element>* b=0): publicKey(a), secretKey(b) {}

		bool good() { return publicKey && secretKey; }
		
	};

	/**
	* @brief Abstract interface for parameter generation algorithm
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPParameterGenerationAlgorithm {
	public:
		virtual ~LPParameterGenerationAlgorithm() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		* @param dcrtBits number of bits in each CRT modulus*
		* @param n ring dimension in case the user wants to use a custom ring dimension
		*/
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0, size_t dcrtBits = 0, uint32_t n = 0) const = 0;

		/**
		* Method for computing all derived parameters based on chosen primitive parameters.
		* This is intended for CKKS and DCRTPoly.
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param cyclOrder the cyclotomic order.
		* @param numPrimes number of modulus towers to support.
		* @param scaleExp the bit-width for plaintexts and DCRTPoly's.
		* @param relinWindow the relinearization window
		* @param mode
		* @param ksTech the key switching technique used (e.g., BV or GHS)
		* @param firstModSize the bit-size of the first modulus
		* @param rsTech the rescaling technique used (e.g., APPROXRESCALE or EXACTRESCALE)
		*/
        virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                               usint cyclOrder,
                               usint numPrimes,
                               usint scaleExp,
                               usint relinWindow,
                               MODE mode,
                               KeySwitchTechnique ksTech,
                               usint firstModSize,
                               RescalingTechnique) const {
			PALISADE_THROW(config_error, "This signature for ParamsGen is not supported for this scheme.");
		}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters.
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param cyclOrder the cyclotomic order.
		* @param numPrimes number of modulus towers to support.
		* @param scaleExp the bit-width for plaintexts and DCRTPoly's.
		* @param relinWindow the relinearization window
		* @param mode
		* @param ksTech the key switching technique used (e.g., BV or GHS)
		* @param firstModSize the bit-size of the first modulus
		* @param rsTech the rescaling technique used (e.g., APPROXRESCALE or EXACTRESCALE)
		*/
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
					   usint cyclOrder,
					   usint numPrimes,
					   usint scaleExp,
					   usint relinWindow,
					   MODE mode,
					   KeySwitchTechnique ksTech = BV,
					   usint firstModSize = 60,
					   RescalingTechnique = APPROXRESCALE,
					   uint32_t numLargeDigits = 4) const {
			PALISADE_THROW(config_error, "This signature for ParamsGen is not supported for this scheme.");
		}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const {}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version ) {}

		std::string SerializedObjectName() const { return "ParamsGen"; }

	};

	/**
	 * @brief Abstract interface for encryption algorithm
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPEncryptionAlgorithm {
		public:
			virtual ~LPEncryptionAlgorithm() {}

			/**
			 * Method for encrypting plaintext using LBC
			 *
			 * @param&publicKey public key used for encryption.
			 * @param plaintext copy of the plaintext element. NOTE a copy is passed! That is NOT an error!
			 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey, Element plaintext) const = 0;

			/**
			 * Method for encrypting plaintex using LBC
			 *
			 * @param privateKey private key used for encryption.
			 * @param plaintext copy of the plaintext input. NOTE a copy is passed! That is NOT an error!
			 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey, Element plaintext) const = 0;

			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext,
				NativePoly *plaintext) const = 0;

			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext,
				Poly *plaintext) const {
					PALISADE_THROW(config_error, "Decryption to Poly is not supported");
			}

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			virtual LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse=false) = 0;
	};


	/**
	 * @brief Abstract interface for Leveled SHE operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithm {
		public:
		virtual ~LPLeveledSHEAlgorithm() {}

			/**
			 * Method for Modulus Reduction.
			 *
			 * @param &cipherText Ciphertext to perform mod reduce on.
			 */
			virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> cipherText) const = 0;

			/**
			* Method for rescaling.
			*
			* @param cipherText is the ciphertext to perform modreduce on.
			* @return ciphertext after the modulus reduction performed.
			*/
			virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> cipherText) const {
					PALISADE_THROW(config_error, "ModReduceInternal is not supported for this scheme");
			}

			/**
			 * Method for Composed EvalMult
			 *
			 * @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
			 * @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
			 * @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
			 * @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
			 */
			virtual Ciphertext<Element> ComposedEvalMult(
					ConstCiphertext<Element> cipherText1,
					ConstCiphertext<Element> cipherText2,
					const LPEvalKey<Element> quadKeySwitchHint) const = 0;

			/**
			 * Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
			 *
			 * @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
			 * @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
			 * @param &cipherTextResult is the resulting ciphertext.
			 */
			virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element> cipherText1,
					const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const = 0;

			/**
			* Method for Level Reduction in the CKKS scheme. It just drops "levels" number of the towers
			* of the ciphertext without changing the underlying plaintext.
			*
			* @param cipherText1 is the original ciphertext to be level reduced.
			* @param linearKeySwitchHint not used in the CKKS scheme.
			* @param levels the number of towers to drop.
			* @return resulting ciphertext.
			*/
			virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element> cipherText1,
				const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
					PALISADE_THROW(config_error, "LevelReduceInternal is not supported for this scheme");
			}

			template <class Archive>
			void save( Archive & ar, std::uint32_t const version ) const {}

			template <class Archive>
			void load( Archive & ar, std::uint32_t const version ) {}

			std::string SerializedObjectName() const { return "LeveledSHE"; }

	};

	/**
	 * @brief Abstract interface class for LBC PRE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPREAlgorithm {
		public:
			virtual ~LPPREAlgorithm() {}

			/**
			* Virtual function to generate 1..log(q) encryptions for each bit of the original private key
			* Variant that uses the public key for the new secret key.
			*
			* @param &newKey public key for the new secret key.
			* @param &origPrivateKey original private key used for decryption.
			* @param *evalKey the evaluation key.
			* @return the re-encryption key.
			*/
			virtual LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const = 0;
						
			/**
			 * Virtual function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
			 *
			 * @param &evalKey proxy re-encryption key.
			 * @param &ciphertext the input ciphertext.
			 * @param publicKey the public key of the recipient of the re-encrypted ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
				ConstCiphertext<Element> ciphertext,
				const LPPublicKey<Element> publicKey = nullptr) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC Multiparty algorithms.  A version of this multiparty scheme built on the BGV scheme is seen here:
	 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs D. (2012) Multiparty Computation with Low Communication, Computation and Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds) Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in Computer Science, vol 7237. Springer, Berlin, Heidelberg
	 *
	 * During offline key generation, this multiparty scheme relies on the clients coordinating their public key generation.  To do this, a single client generates a public-secret key pair.
	 * This public key is shared with other keys which use an element in the public key to generate their own public keys.
	 * The clients generate a shared key pair using a scheme-specific approach, then generate re-encryption keys.  Re-encryption keys are uploaded to the server.
	 * Clients encrypt data with their public keys and send the encrypted data server.
	 * The data is re-encrypted.  Computations are then run on the data.
	 * The result is sent to each of the clients.
	 * One client runs a "Leader" multiparty decryption operation with its own secret key.  All other clients run a regular "Main" multiparty decryption with their own secret key.
	 * The resulting partially decrypted ciphertext are then fully decrypted with the decryption fusion algorithms.
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPMultipartyAlgorithm {
		public:
			virtual ~LPMultipartyAlgorithm() {}

			/**
			* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
			*
			* @param cc cryptocontext for the keys to be generated.
			* @param pk1 private key used for decryption to be fused.
			* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
			* @param pre set to true if proxy re-encryption is used in multi-party protocol
			* @return key pair including the private and public key
			*/
			virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const LPPublicKey<Element> pk1,
				bool makeSparse=false, bool pre=false) = 0;

			/**
			* Function to generate public and private keys for multiparty homomrophic encryption server key pair in coordination with secret keys of clients.
			*
			* @param cc cryptocontext for the keys to be generated.
			* @param secretkeys private keys used for decryption to be fused.
			* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
			* @return key pair including the private and public key
			*/
			virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const vector<LPPrivateKey<Element>>& secretKeys,
				bool makeSparse=false) = 0;

			/**
			 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
			 *
			 * @param privateKey private key used for decryption.
			 * @param ciphertext ciphertext id decrypted.
			 */
			virtual Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext) const = 0;

			/**
			 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
			 *
			 * @param privateKey private key used for decryption.
			 * @param ciphertext ciphertext id decrypted.
			 */
			virtual Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext) const = 0;


			/**
			 * Method for fusing the partially decrypted ciphertext.
			 *
			 * @param &ciphertextVec ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				NativePoly *plaintext) const = 0;

			/**
			 * Method for fusing the partially decrypted ciphertext.
			 *
			 * @param &ciphertextVec ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				Poly *plaintext) const {
					PALISADE_THROW(config_error, "Decryption to Poly is not supported");
			}

			template <class Archive>
			void save( Archive & ar, std::uint32_t const version ) const {}

			template <class Archive>
			void load( Archive & ar, std::uint32_t const version ) {}

			std::string SerializedObjectName() const { return "MultiParty"; }

	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPSHEAlgorithm {
		public:
			virtual ~LPSHEAlgorithm() {}

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
					ConstCiphertext<Element> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			* This is the mutable version - input ciphertexts may change (automatically
			* rescaled, or towers dropped).
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext1,
					Ciphertext<Element> &ciphertext2) const {
				PALISADE_THROW(not_implemented_error, "EvalAddMutable is not implemented for this scheme");
			}

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			*
			* @param ciphertext the input ciphertext.
			* @param plaintext the input plaintext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
					ConstPlaintext plaintext) const = 0;

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			* This is the mutable version - input ciphertext may change (automatically
			* rescaled, or towers dropped).
			*
			* @param ciphertext the input ciphertext.
			* @param plaintext the input plaintext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext,
					Plaintext plaintext) const {
				PALISADE_THROW(not_implemented_error, "EvalAddMutable is not implemented for this scheme");
			}

			/**
			* Virtual function to define the adding of a scalar to a ciphertext
			*
			* @param ciphertext the input ciphertext.
			* @param constant the input constant.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
					double constant) const {
				PALISADE_THROW(not_implemented_error, "Scalar addition is not implemented for this scheme");
			}

			/**
			* Virtual function for computing the linear weighted sum of a
			* vector of ciphertexts.
			*
			* @param ciphertexts vector of input ciphertexts.
			* @param constants vector containing double weights.
			* @return A ciphertext containing the linear weighted sum.
			*/
			virtual Ciphertext<Element> EvalLinearWSum(
				vector<Ciphertext<Element>> ciphertexts,
				vector<double> constants) const {
				std::string errMsg = "EvalLinearWSum is not implemented for this scheme.";
				PALISADE_THROW(not_implemented_error, errMsg);
			}

			/**
			* Function for computing the linear weighted sum of a
			* vector of ciphertexts. This is a mutable method,
			* meaning that the level/depth of input ciphertexts may change.
			*
			* @param ciphertexts vector of input ciphertexts.
			* @param constants vector containing double weights.
			* @return A ciphertext containing the linear weighted sum.
			*/
			virtual Ciphertext<Element> EvalLinearWSumMutable(
				vector<Ciphertext<Element>> ciphertexts,
				vector<double> constants) const {
				std::string errMsg = "EvalLinearWSumMutable is not implemented for this scheme.";
				PALISADE_THROW(not_implemented_error, errMsg);
			}

			/**
			* Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
				ConstCiphertext<Element> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			* This is the mutable version - input ciphertext may change (automatically
			* rescaled, or towers dropped).
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext1,
				Ciphertext<Element> &ciphertext2) const {
				PALISADE_THROW(not_implemented_error, "EvalSubMutable is not implemented for this scheme");
			}

			/**
			 * Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
					ConstPlaintext plaintext) const = 0;

			/**
			 * Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			 * This is the mutable version - input ciphertext may change (automatically
			 * rescaled, or towers dropped).
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext,
					Plaintext plaintext) const {
				PALISADE_THROW(not_implemented_error, "EvalSubMutable is not implemented for this scheme");
			}

			/**
			* Virtual function to define the subtraction of a scalar from a ciphertext
			*
			* @param ciphertext the input ciphertext.
			* @param constant the input constant.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
					double constant) const {
				PALISADE_THROW(not_implemented_error, "Scalar subtraction is not implemented for this scheme");
			}

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext.
			 *
			 * @param ciphertext1 the input ciphertext.
			 * @param ciphertext2 the input ciphertext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
					ConstCiphertext<Element> ciphertext2) const = 0;

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext.
			 * This is the mutable version - input ciphertexts may change (automatically
			 * rescaled, or towers dropped).
			 *
			 * @param ciphertext1 the input ciphertext.
			 * @param ciphertext2 the input ciphertext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
					Ciphertext<Element> &ciphertext2) const {
				PALISADE_THROW(not_implemented_error, "EvalMultMutable is not implemented for this scheme");
			}

			/**
			 * Virtual function to define the interface for multiplication of ciphertext by plaintext.
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
					ConstPlaintext plaintext) const = 0;

			/**
			 * Virtual function to define the interface for multiplication of ciphertext by plaintext.
			 * This is the mutable version - input ciphertext may change (automatically
			 * rescaled, or towers dropped).
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
					ConstPlaintext plaintext) const {
				PALISADE_THROW(not_implemented_error, "EvalMultMutable is not implemented for this scheme");
			}

			/**
			* Virtual function to define the multiplication of a ciphertext by a constant
			*
			* @param ciphertext the input ciphertext.
			* @param constant the input constant.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
					double constant) const {
				PALISADE_THROW(not_implemented_error, "Scalar multiplication is not implemented for this scheme");
			}

			/**
			* Virtual function to define the multiplication of a ciphertext by a constant.
			* This is the mutable version - input ciphertext may change (automatically
			* rescaled, or towers dropped).
			*
			* @param ciphertext the input ciphertext.
			* @param constant the input constant.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
					double constant) const {
				PALISADE_THROW(not_implemented_error, "EvalMultMutable is not implemented for this scheme");
			}

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
			 *
			 * @param &ciphertext1 first input ciphertext.
			 * @param &ciphertext2 second input ciphertext.
			 * @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
					ConstCiphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const = 0;

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
			 * This is the mutable version - input ciphertext may change (automatically
			 * rescaled, or towers dropped).
			 *
			 * @param &ciphertext1 first input ciphertext.
			 * @param &ciphertext2 second input ciphertext.
			 * @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
								Ciphertext<Element> &ciphertext2, const LPEvalKey<Element> ek) const {
				PALISADE_THROW(not_implemented_error, "EvalMultMutable is not implemented for this scheme");
			}

		/**
		* Virtual function for evaluating multiplication of a ciphertext list which each multiplication is followed by relinearization operation.
		*
		* @param cipherTextList  is the ciphertext list.
		* @param evalKeys is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext list.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& cipherTextList,
				const vector<LPEvalKey<Element>> &evalKeys) const {
			// default implementation if you don't have one in your scheme

			const size_t inSize = cipherTextList.size();
			const size_t lim = inSize * 2 - 2;
			vector<Ciphertext<Element>> cipherTextResults;
			cipherTextResults.resize(inSize - 1);
			size_t ctrIndex = 0;

			for(size_t i=0; i < lim; i = i + 2) {
				cipherTextResults[ctrIndex++] = this->EvalMult(
						i   < inSize ? cipherTextList[i]   : cipherTextResults[i - inSize],
						i+1 < inSize ? cipherTextList[i+1] : cipherTextResults[i + 1 - inSize]);
			}

			return cipherTextResults.back();
		}

		/**
		* Virtual function for evaluating addition of a list of ciphertexts.
		*
		* @param ctList  is the ciphertext list.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalAddMany(const vector<Ciphertext<Element>>& ctList) const {
			// default implementation if you don't have one in your scheme

			const size_t inSize = ctList.size();
			const size_t lim = inSize * 2 - 2;
			vector<Ciphertext<Element>> cipherTextResults;
			cipherTextResults.resize(inSize - 1);
			size_t ctrIndex = 0;

			for(size_t i=0; i < lim; i = i + 2) {
				cipherTextResults[ctrIndex++] = this->EvalAdd(
						i   < inSize ? ctList[i]   : cipherTextResults[i - inSize],
						i+1 < inSize ? ctList[i+1] : cipherTextResults[i + 1 - inSize]);
			}

			return cipherTextResults.back();
		}

		/**
		* Virtual function for evaluating addition of a list of ciphertexts.
		* This version uses no additional space, other than the vector provided.
		*
		* @param ctList  is the ciphertext list.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalAddManyInPlace(vector<Ciphertext<Element>>& ctList) const {
			// default implementation if you don't have one in your scheme
			for(size_t j = 1; j < ctList.size(); j=j*2) {
				for(size_t i = 0; i<ctList.size(); i = i + 2*j) {
					if ((i+j)<ctList.size()) {
						if (ctList[i] != nullptr && ctList[i+j] != nullptr) {
							ctList[i] = EvalAdd(ctList[i],ctList[i+j]);
						} else if (ctList[i] == nullptr && ctList[i+j] != nullptr) {
							ctList[i] = ctList[i+j];
						} // In all remaining cases (ctList[i+j]), ctList[i] needs to remain unchanged.
					}
				}
			}

			Ciphertext<Element> result(new CiphertextImpl<Element>(*(ctList[0])));

			return result;
		}


		/**
		* Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct2, const vector<LPEvalKey<Element>> &ek) const = 0;

		virtual Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext, const vector<LPEvalKey<Element>> &ek) const {
			PALISADE_THROW(config_error, "Relinearize operation not supported");
		}

		/**
		* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
		* @param x - matrix of regressors
		* @param y - vector of dependent variables
		* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
		*/
		virtual shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
		{
			// multiplication is done in reverse order to minimize the number of inner products
			Matrix<RationalCiphertext<Element>> xTransposed = x->Transpose();
			shared_ptr<Matrix<RationalCiphertext<Element>>> result(new Matrix<RationalCiphertext<Element>>(xTransposed * (*y)));

			Matrix<RationalCiphertext<Element>> xCovariance = xTransposed * (*x);

			Matrix<RationalCiphertext<Element>> cofactorMatrix = xCovariance.CofactorMatrix();

			Matrix<RationalCiphertext<Element>> adjugateMatrix = cofactorMatrix.Transpose();

			*result = adjugateMatrix * (*result);

			RationalCiphertext<Element> determinant;
			xCovariance.Determinant(&determinant);

				for (size_t row = 0; row < result->GetRows(); row++)
					for (size_t col = 0; col < result->GetCols(); col++)
						(*result)(row, col).SetDenominator(determinant.GetNumerator());

			return result;
		}

		/**
		* Virtual function to define the interface for homomorphic negation of ciphertext.
		*
		* @param &ciphertext the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const = 0;

		/**
		* Function to add random noise to all plaintext slots except for the first one; used in EvalInnerProduct
		*
		* @param &ciphertext the input ciphertext.
		* @return modified ciphertext
		*/
		virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const {

			std::uniform_real_distribution<double> distribution(0.0, 1.0);

			string kID = ciphertext->GetKeyTag();
			const auto cryptoParams = ciphertext->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint n = elementParams->GetRingDimension();

			auto cc = ciphertext->GetCryptoContext();

			Plaintext plaintext;

			if (ciphertext->GetEncodingType() == CKKSPacked)
			{

				std::vector<std::complex<double>> randomIntVector(n);

				//first plaintext slot does not need to change
				randomIntVector[0].real(0);

				for (usint i = 0; i < n - 1; i++)
				{
					randomIntVector[i + 1].real(distribution(PseudoRandomNumberGenerator::GetPRNG()));
				}

				plaintext = cc->MakeCKKSPackedPlaintext(randomIntVector,ciphertext->GetDepth());

			}
			else
			{
				DiscreteUniformGenerator dug;
				dug.SetModulus(encodingParams->GetPlaintextModulus());
				BigVector randomVector = dug.GenerateVector(n - 1);

				std::vector<int64_t> randomIntVector(n);

				//first plaintext slot does not need to change
				randomIntVector[0] = 0;

				for (usint i = 0; i < n - 1; i++)
				{
					randomIntVector[i + 1] = randomVector[i].ConvertToInt();
				}

				plaintext = cc->MakePackedPlaintext(randomIntVector);

			}

			plaintext->Encode();
			plaintext->GetElement<Element>().SetFormat(EVALUATION);

			auto ans = EvalAdd(ciphertext, plaintext);

			return ans;
		};

		/**
		* Method for KeySwitchGen
		*
		* @param &originalPrivateKey Original private key used for encryption.
		* @param &newPrivateKey New private key to generate the keyswitch hint.
		* @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
		*/
		virtual LPEvalKey<Element> KeySwitchGen(
			const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const = 0;

		/**
		* Method for KeySwitch
		*
		* @param &keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		*/
		virtual Ciphertext<Element> KeySwitch(
			const LPEvalKey<Element> keySwitchHint,
			ConstCiphertext<Element> cipherText) const = 0;

		/**
		* Method for KeySwitching based on RLWE relinearization (used only for the StSt scheme).
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		virtual LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
			const LPPrivateKey<Element> origPrivateKey) const = 0;

		/**
		* Method for KeySwitching based on RLWE relinearization (used only for the StSt scheme).
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		virtual Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			ConstCiphertext<Element> ciphertext) const = 0;

		/**
		* Virtual function to define the interface for generating a evaluation key which is used after each multiplication.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual	LPEvalKey<Element> EvalMultKeyGen(
			const LPPrivateKey<Element> originalPrivateKey) const = 0;

		/**
		* Virtual function to define the interface for generating a evaluation key which is used after each multiplication for depth more than 2.
		*
		* @param &originalPrivateKey Original private key used for encryption.
		* @param *evalMultKeys the resulting evalution key vector list.
		*/
		virtual	vector<LPEvalKey<Element>> EvalMultKeysGen(
			const LPPrivateKey<Element> originalPrivateKey) const = 0;

		/**
		 * Virtual function to generate all isomorphism keys for a given private key
		 *
		 * @param publicKey encryption key for the new ciphertext.
		 * @param origPrivateKey original private key used for decryption.
		 * @param indexList list of automorphism indices to be computed
		 * @return returns the evaluation keys
		 */
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<usint> &indexList) const = 0;

		/**
		 * Virtual function for the precomputation step of hoisted
		 * automorphisms.
		 *
		 * @param ct the input ciphertext on which to do the precomputation (digit decomposition)
		 */
		virtual shared_ptr<vector<Element>> EvalFastRotationPrecompute(
				ConstCiphertext<Element> cipherText
				) const {

			std::string errMsg = "LPSHEAlgorithm::EvalFastRotationPrecompute is not implemented for this Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}


		/**
		 * Virtual function for the automorphism and key switching step of
		 * hoisted automorphisms.
		 *
		 * @param ct the input ciphertext to perform the automorphism on
		 * @param index the index of the rotation. Positive indices correspond to left rotations
		 * 		  and negative indices correspond to right rotations.
		 * @param m is the cyclotomic order
		 * @param digits the digit decomposition created by EvalFastRotationPrecompute at
		 * 		  the precomputation step.
		 */
		virtual Ciphertext<Element> EvalFastRotation(
				ConstCiphertext<Element> cipherText,
				const usint index,
				const usint m,
				const shared_ptr<vector<Element>> digits
				) const {

			std::string errMsg = "LPSHEAlgorithm::EvalFastRotation is not implemented for this Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		 * Generates evaluation keys for a list of indices
		 * Currently works only for power-of-two and cyclic-group cyclotomics
		 *
		 * @param publicKey encryption key for the new ciphertext.
		 * @param origPrivateKey original private key used for decryption.
		 * @param indexList list of indices to be computed
		 * @return returns the evaluation keys
		 */
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAtIndexKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<int32_t> &indexList) const
		{

			const auto cryptoParams = origPrivateKey->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();
			uint32_t m = elementParams->GetCyclotomicOrder();

			std::vector<uint32_t> autoIndices(indexList.size());

			if (!(m & (m-1))) { // power-of-two cyclotomics
				for (size_t i=0; i < indexList.size(); i++) {
                    auto ccInst = origPrivateKey->GetCryptoContext();
					// CKKS Packing
//					if (string(typeid(*this).name()).find("CKKS")!=std::string::npos)
					if (ccInst->getSchemeId() == "CKKS")
						autoIndices[i] = FindAutomorphismIndex2nComplex(indexList[i],m);
					else
						autoIndices[i] = FindAutomorphismIndex2n(indexList[i],m);
				}

			}
			else // cyclic groups
			{
				for (size_t i=0; i < indexList.size(); i++)
					autoIndices[i] = FindAutomorphismIndexCyclic(indexList[i],m,encodingParams->GetPlaintextGenerator());
			}

			if (publicKey)
				// NTRU-based scheme
				return EvalAutomorphismKeyGen(publicKey,origPrivateKey,autoIndices);
			else
				// RLWE-based scheme
				return EvalAutomorphismKeyGen(origPrivateKey,autoIndices);

		}

		/**
		* Virtual function for evaluating automorphism of ciphertext at index i
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const = 0;

		/**
		* Moves i-th slot to slot 0
		*
		* @param ciphertext.
		* @param i the index.
		* @param &evalAtIndexKeys - reference to the map of evaluation keys generated by EvalAtIndexKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext,
			int32_t index, const std::map<usint, LPEvalKey<Element>> &evalAtIndexKeys) const {

			const auto cryptoParams = ciphertext->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();
			uint32_t m = elementParams->GetCyclotomicOrder();

			uint32_t autoIndex;

			  // power-of-two cyclotomics
			if (!(m & (m-1))) {
				if (ciphertext->GetEncodingType() == CKKSPacked)
					autoIndex = FindAutomorphismIndex2nComplex(index,m);
				else
					autoIndex = FindAutomorphismIndex2n(index,m);
			}
			else // cyclyc-group cyclotomics
				autoIndex = FindAutomorphismIndexCyclic(index,m,encodingParams->GetPlaintextGenerator());

			return EvalAutomorphism(ciphertext,autoIndex,evalAtIndexKeys);

		}

		/**
		* Virtual function to generate automophism keys for a given private key; Uses the private key for encryption
		*
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const = 0;

		/**
		* Virtual function to generate the automorphism keys for EvalSum; works only for packed encoding
		*
		* @param privateKey private key.
		* @return returns the evaluation keys
		*/
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const
		{

			const auto cryptoParams = privateKey->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint batchSize = encodingParams->GetBatchSize();
			usint m = elementParams->GetCyclotomicOrder();

			// stores automorphism indices needed for EvalSum
			std::vector<usint> indices;

			if (!(m & (m-1))){ // Check if m is a power of 2

                auto ccInst = privateKey->GetCryptoContext();
                // CKKS Packing
//					if (string(typeid(*this).name()).find("CKKS")!=std::string::npos)
                if (ccInst->getSchemeId() == "CKKS")
					indices = GenerateIndices2nComplex(batchSize, m);
				else
					indices = GenerateIndices_2n(batchSize, m);

			} else { // Arbitray cyclotomics

				usint g = encodingParams->GetPlaintextGenerator();
				for (int i = 0; i < floor(log2(batchSize)); i++)
				{
					indices.push_back(g);
					g = (g * g) % m;
				}
			}

			if (publicKey)
				// NTRU-based scheme
				return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
			else
				// Regular RLWE scheme
				return EvalAutomorphismKeyGen(privateKey, indices);

		}

		/**
		* Virtual function to generate the automorphism keys for EvalSumRows; works only for packed encoding
		*
		* @param privateKey private key.
		* @param publicKey public key.
		* @param rowSize size of rows in the matrix
		* @param colSize size of columns in the matrix
		* @return returns the evaluation keys
		*/
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey, usint rowSize) const
		{

			const auto cryptoParams = privateKey->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint m = elementParams->GetCyclotomicOrder();

			// stores automorphism indices needed for EvalSum
			std::vector<usint> indices;

			if (!(m & (m-1))){ // Check if m is a power of 2

                auto ccInst = privateKey->GetCryptoContext();
                // CKKS Packing
//					if (string(typeid(*this).name()).find("CKKS")!=std::string::npos)
                if (ccInst->getSchemeId() == "CKKS")
					indices = GenerateIndices2nComplexRows(rowSize, m);
				else
					PALISADE_THROW(config_error, "Matrix summation of row-vectors is only supported for CKKSPackedEncoding.");

			} else { // Arbitray cyclotomics

				PALISADE_THROW(config_error, "Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");
			}

			if (publicKey)
				// NTRU-based scheme
				return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
			else
				// Regular RLWE scheme
				return EvalAutomorphismKeyGen(privateKey, indices);

		}

		/**
		* Virtual function to generate the automorphism keys for EvalSumCols; works only for packed encoding
		*
		* @param privateKey private key.
		* @param publicKey public key.
		* @param rowSize size of rows in the matrix
		* @param colSize size of columns in the matrix
		* @return returns the evaluation keys
		*/
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const
		{

			const auto cryptoParams = privateKey->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint batchSize = encodingParams->GetBatchSize();
			usint m = elementParams->GetCyclotomicOrder();

            auto ccInst = privateKey->GetCryptoContext();
            // CKKS Packing
//					if (string(typeid(*this).name()).find("CKKS")!=std::string::npos)
            if (ccInst->getSchemeId() == "CKKS")
			{

				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				if (!(m & (m-1))){ // Check if m is a power of 2
						indices = GenerateIndices2nComplexCols(batchSize, m);
				} else { // Arbitray cyclotomics
					PALISADE_THROW(config_error, "Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");
				}

				if (publicKey)
					// NTRU-based scheme
					return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
				else
					// Regular RLWE scheme
					return EvalAutomorphismKeyGen(privateKey, indices);

			}
			else
				PALISADE_THROW(config_error, "Matrix summation of column-vectors is only supported for CKKSPackedEncoding.");

		}

		/**
		* Sums all elements in log (batch size) time - works only with packed encoding
		*
		* @param ciphertext the input ciphertext.
		* @param batchSize size of the batch to be summed up
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertext->GetCryptoParameters();
			Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint m = elementParams->GetCyclotomicOrder();

			if ((encodingParams->GetBatchSize() == 0))
				PALISADE_THROW(config_error, "EvalSum: Packed encoding parameters 'batch size' is not set; Please check the EncodingParams passed to the crypto context.");
			else
			{

				if (!(m & (m-1))){ // Check if m is a power of 2

					if (ciphertext->GetEncodingType() == CKKSPacked)
						newCiphertext = EvalSum2nComplex(batchSize, m, evalKeys,newCiphertext);
					else
						newCiphertext = EvalSum_2n(batchSize, m, evalKeys,newCiphertext);

				} else { // Arbitray cyclotomics

					if (encodingParams->GetPlaintextGenerator() == 0)
						PALISADE_THROW(config_error, "EvalSum: Packed encoding parameters 'plaintext generator' is not set; Please check the EncodingParams passed to the crypto context.");
					else
					{
						usint g = encodingParams->GetPlaintextGenerator();
						for (int i = 0; i < floor(log2(batchSize)); i++)
						{
							auto ea = EvalAutomorphism(newCiphertext, g, evalKeys);
							newCiphertext = EvalAdd(newCiphertext, ea);
							g = (g * g) % m;
						}
					}
				}
			}


			return newCiphertext;

		}

		/**
		* Sums all elements over row-vectors in a matrix - works only with packed encoding
		*
		* @param ciphertext the input ciphertext.
		* @param rowSize size of rows in the matrix
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertext->GetCryptoParameters();
			Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint m = elementParams->GetCyclotomicOrder();

			if ((encodingParams->GetBatchSize() == 0))
				PALISADE_THROW(config_error, "EvalSum: Packed encoding parameters 'batch size' is not set; Please check the EncodingParams passed to the crypto context.");
			else
			{

				if (!(m & (m-1))){ // Check if m is a power of 2

					if (ciphertext->GetEncodingType() == CKKSPacked)
						newCiphertext = EvalSum2nComplexRows(rowSize, m, evalKeys,newCiphertext);
					else
						PALISADE_THROW(config_error, "Matrix summation of row-vectors is only supported for CKKS packed encoding.");

				} else { // Arbitray cyclotomics
					PALISADE_THROW(config_error, "Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");
				}
			}


			return newCiphertext;

		}

		/**
		* Sums all elements over column-vectors in a matrix - works only with packed encoding
		*
		* @param ciphertext the input ciphertext.
		* @param rowSize size of rows in the matrixs
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys, const std::map<usint, LPEvalKey<Element>> &rightEvalKeys) const {

			const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertext->GetCryptoParameters();
			Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint m = elementParams->GetCyclotomicOrder();

			if ((encodingParams->GetBatchSize() == 0))
				PALISADE_THROW(config_error, "EvalSumCols: Packed encoding parameters 'batch size' is not set; Please check the EncodingParams passed to the crypto context.");
			else
			{

				if (ciphertext->GetEncodingType() == CKKSPacked) {

					if (!(m & (m-1))){ // Check if m is a power of 2

							newCiphertext = EvalSum2nComplex(batchSize, m, evalKeys,newCiphertext);

							std::vector<std::complex<double>> mask(m/4);
							for (size_t i = 0; i < mask.size(); i++)
							{
								if (i % batchSize == 0)
									mask[i] = 1;
								else
									mask[i] = 0;
							}

							auto cc = ciphertext->GetCryptoContext();

							Plaintext plaintext = cc->MakeCKKSPackedPlaintext(mask,1);

							newCiphertext = EvalMult(newCiphertext,plaintext);

							newCiphertext = EvalSum2nComplexCols(batchSize, m, rightEvalKeys,newCiphertext);


					} else { // Arbitray cyclotomics
						PALISADE_THROW(config_error, "Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");
					}

				}
				else
					PALISADE_THROW(config_error, "Matrix summation of column-vectors is only supported for CKKS packed encoding.");

			}

			return newCiphertext;

		}

		/**
		* Evaluates inner product in batched encoding
		*
		* @param ciphertext1 first vector.
		* @param ciphertext2 second vector.
		* @param batchSize size of the batch to be summed up
		* @param &evalSumKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @param &evalMultKey - reference to the evaluation key generated by EvalMultKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
			const LPEvalKey<Element> evalMultKey) const {

			Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2, evalMultKey);

			result = EvalSum(result, batchSize, evalSumKeys);

			// add a random number to all slots except for the first one so that no information is leaked
			//if (ciphertext1->GetEncodingType() != CKKSPacked)
			//	result = AddRandomNoise(result);

			return result;
		}

		/**
		* Evaluates inner product in batched encoding
		*
		* @param ciphertext1 first vector.
		* @param ciphertext2 plaintext.
		* @param batchSize size of the batch to be summed up
		* @param &evalSumKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @param &evalMultKey - reference to the evaluation key generated by EvalMultKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
			ConstPlaintext ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {

			Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2);

			result = EvalSum(result, batchSize, evalSumKeys);

			// add a random number to all slots except for the first one so that no information is leaked
			//if (ciphertext1->GetEncodingType() != CKKSPacked)
			//	result = AddRandomNoise(result);

			return result;

		}

		/**
		* Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext
		* The slot assignment is done based on the order of ciphertexts in the vector
		*
		* @param ciphertextVector vector of ciphertexts to be merged.
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalMerge(const vector<Ciphertext<Element>> &ciphertextVector,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (ciphertextVector.size() == 0)
				PALISADE_THROW(math_error, "EvalMerge: the vector of ciphertexts to be merged cannot be empty");

			const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVector[0]->GetCryptoParameters();
			Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*(ciphertextVector[0])));

			auto cc = ciphertextVector[0]->GetCryptoContext();

			Plaintext plaintext;
			if (ciphertextVector[0]->GetEncodingType() == CKKSPacked){
					std::vector<std::complex<double>> plaintextVector({{1,0}, {0,0}});
					plaintext = cc->MakeCKKSPackedPlaintext(plaintextVector);
			} else {
					std::vector<int64_t> plaintextVector = {1,0};
					plaintext = cc->MakePackedPlaintext(plaintextVector);
			}

			newCiphertext = EvalMult(newCiphertext,plaintext);

			for (size_t i = 1; i < ciphertextVector.size(); i++)
			{
				newCiphertext = EvalAdd(newCiphertext,EvalAtIndex(EvalMult(ciphertextVector[i],plaintext),-(int32_t)i,evalKeys));
			}

			return newCiphertext;

		}

		/**
		* EvalLinRegressBatched - Computes the parameter vector for linear regression using the least squares method
		* Currently supports only two regressors
		* @param x - matrix of regressors
		* @param y - vector of dependent variables
		* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
		*/
		virtual shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const
		{

			Matrix<RationalCiphertext<Element>> covarianceMatrix(x->GetAllocator(), 2, 2);

			Ciphertext<Element> x0 = (*x)(0, 0).GetNumerator();
			Ciphertext<Element> x1 = (*x)(0, 1).GetNumerator();
			Ciphertext<Element> y0 = (*y)(0, 0).GetNumerator();

			//Compute the covariance matrix for X
			covarianceMatrix(0, 0).SetNumerator(EvalInnerProduct(x0, x0, batchSize, evalSumKeys, evalMultKey));
			covarianceMatrix(0, 1).SetNumerator(EvalInnerProduct(x0, x1, batchSize, evalSumKeys, evalMultKey));
			covarianceMatrix(1, 0) = covarianceMatrix(0, 1);
			covarianceMatrix(1, 1).SetNumerator(EvalInnerProduct(x1, x1, batchSize, evalSumKeys, evalMultKey));

			Matrix<RationalCiphertext<Element>> cofactorMatrix = covarianceMatrix.CofactorMatrix();

			Matrix<RationalCiphertext<Element>> adjugateMatrix = cofactorMatrix.Transpose();

			shared_ptr<Matrix<RationalCiphertext<Element>>> result(new Matrix<RationalCiphertext<Element>>(x->GetAllocator(), 2, 1));

			(*result)(0, 0).SetNumerator(EvalInnerProduct(x0, y0, batchSize, evalSumKeys, evalMultKey));
			(*result)(1, 0).SetNumerator(EvalInnerProduct(x1, y0, batchSize, evalSumKeys, evalMultKey));

			*result = adjugateMatrix * (*result);

			RationalCiphertext<Element> determinant;
			covarianceMatrix.Determinant(&determinant);

			for (size_t row = 0; row < result->GetRows(); row++)
				for (size_t col = 0; col < result->GetCols(); col++)
					(*result)(row, col).SetDenominator(determinant.GetNumerator());

			return result;
		}


		/**
		* EvalCrossCorrelation - Computes the sliding sum of inner products (known as
		* as cross-correlation, sliding inner product, or sliding dot product in
		* image processing
		* @param x - first vector of row vectors
		* @param y - second vector of row vectors
		* @param batchSize - batch size for packed encoding
		* @param indexStart - starting index in the vectors of row vectors
		* @param length - length of the slice in the vectors of row vectors
		* @param evalSumKeys - evaluation keys used for the automorphism operation
		* @param evalMultKey - the evaluation key used for multiplication
		* @return sum(x_i*y_i), i.e., a sum of inner products
		*/
		virtual Ciphertext<Element>
			EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize, 
				usint indexStart, usint length,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const
		{

			if (length == 0)
				length = x->GetRows();
			
			if (length - indexStart > x->GetRows())
				PALISADE_THROW(math_error, "The number of rows exceeds the dimension of the vector");

			//additional error checking can be added here

			Ciphertext<Element> result;

			Ciphertext<Element> x0 = (*x)(indexStart, 0).GetNumerator();
			Ciphertext<Element> y0 = (*y)(indexStart, 0).GetNumerator();

			result = EvalInnerProduct(x0, y0, batchSize, evalSumKeys, evalMultKey);
			#pragma omp parallel for ordered schedule(dynamic)
			for (usint i = indexStart + 1; i < indexStart + length; i++)
			{
				Ciphertext<Element> xi = (*x)(i, 0).GetNumerator();
				Ciphertext<Element> yi = (*y)(i, 0).GetNumerator();

				auto product = EvalInnerProduct(xi, yi, batchSize, evalSumKeys, evalMultKey);
				#pragma omp ordered
				{
					result = EvalAdd(result,product);
				}
			}

			return result;

		}

		/* Maintenance procedure used in the exact RNS variant of CKKS
		* @param c1 input ciphertext.
		* @param targetLevel The number of the level we want to take this ciphertext
		*           to. Levels are numbered from 0 (all towers) to GetNumberOfTowers()-1
		*           (one remaining tower).
		* @return A ciphertext containing the same value as c1, but at level targetLevel.
		*/
		virtual Ciphertext<Element> AdjustLevelWithRescale(
					Ciphertext<Element> &c1,
					uint32_t targetLevel) const {
			std::string errMsg = "AdjustLevelWithoutRescale is not implemented for this scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		private:

			std::vector<usint> GenerateIndices_2n(usint batchSize, usint m) const {
				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				if (batchSize > 1)
				{
					usint g = 5;
					for (int i = 0; i < ceil(log2(batchSize)) - 1; i++)
					{
						indices.push_back(g);
						g = (g * g) % m;
					}
					if (2*batchSize<m)
						indices.push_back(g);
					else
						indices.push_back(m-1);
				}

				return indices;
			}

			std::vector<usint> GenerateIndices2nComplex(usint batchSize, usint m) const {
				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				// generator
				int32_t g = 5;
				usint gFinal = g;

				for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
					indices.push_back(gFinal);
					g = (g * g) % m;

					gFinal = g;

				}

				return indices;
			}

			std::vector<usint> GenerateIndices2nComplexRows(usint rowSize, usint m) const {
				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				usint colSize = m/(4*rowSize);

				// generator
				int32_t g0 = 5;
				usint g = 0;

				int32_t f = (NativeInteger(g0).ModExp(rowSize,m)).ConvertToInt();

				for (size_t j = 0; j < ceil(log2(colSize)); j++) {

					g = f;

					indices.push_back(g);

					f = (f * f)  % m;

				}

				return indices;

			}

			std::vector<usint> GenerateIndices2nComplexCols(usint batchSize, usint m) const {
				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				// generator
				int32_t g = NativeInteger(5).ModInverse(m).ConvertToInt();
				usint gFinal = g;

				for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
					indices.push_back(gFinal);
					g = (g * g) % m;

					gFinal = g;

				}

				return indices;
			}

			Ciphertext<Element> EvalSum_2n(usint batchSize, usint m, const std::map<usint, LPEvalKey<Element>> &evalKeys,
				ConstCiphertext<Element> ciphertext) const{

				Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

				if (batchSize > 1)
				{
					usint g = 5;
					for (int i = 0; i < ceil(log2(batchSize)) - 1; i++)
					{
						newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));
						g = (g * g) % m;
					}
					if (2*batchSize<m)
						newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));
					else
						newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, m - 1, evalKeys));
				}

				return newCiphertext;

			}

			Ciphertext<Element> EvalSum2nComplex(usint batchSize, usint m, const std::map<usint, LPEvalKey<Element>> &evalKeys,
				ConstCiphertext<Element> ciphertext) const{

				Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

				// generator
				int32_t g = 5;
				usint gFinal = g;

				for (int i = 0; i < ceil(log2(batchSize)); i++)
				{
					newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, gFinal, evalKeys));
					g = (g * g) % m;

					gFinal = g;

				}

				return newCiphertext;

			}

			Ciphertext<Element> EvalSum2nComplexRows(usint rowSize, usint m, const std::map<usint, LPEvalKey<Element>> &evalKeys,
				ConstCiphertext<Element> ciphertext) const{

				Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

				usint colSize = m/(4*rowSize);

				// generator
				int32_t g0 = 5;
				usint g = 0;
				int32_t f = (NativeInteger(g0).ModExp(rowSize,m)).ConvertToInt();

				for (size_t j = 0; j < ceil(log2(colSize)); j++) {

					g = f;

					newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));

					f = (f * f)  % m;

				}

				return newCiphertext;

			}

			Ciphertext<Element> EvalSum2nComplexCols(usint batchSize, usint m, const std::map<usint, LPEvalKey<Element>> &evalKeys,
				ConstCiphertext<Element> ciphertext) const{

				Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

				// generator
				int32_t g = NativeInteger(5).ModInverse(m).ConvertToInt();
				usint gFinal = g;

				for (int i = 0; i < ceil(log2(batchSize)); i++)
				{
					newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, gFinal, evalKeys));
					g = (g * g) % m;

					gFinal = g;

				}

				return newCiphertext;

			}

	};

	/**
	 * @brief main implementation class to capture essential cryptoparameters of any LBC system
	 * @tparam Element a ring element.
	 */
	template <typename Element>
	class LPCryptoParameters : public Serializable
	{		
	public:
		LPCryptoParameters() {}

		virtual ~LPCryptoParameters() {}

		/**
			* Returns the value of plaintext modulus p
			*
			* @return the plaintext modulus.
			*/
		virtual const PlaintextModulus &GetPlaintextModulus() const { return  m_encodingParams->GetPlaintextModulus(); }

		/**
			* Returns the reference to IL params
			*
			* @return the ring element parameters.
			*/
		virtual const shared_ptr<typename Element::Params> GetElementParams() const { return m_params; }

		/**
		* Returns the reference to encoding params
		*
		* @return the encoding parameters.
		*/
		virtual const EncodingParams GetEncodingParams() const { return m_encodingParams; }

		/**
		* Sets the value of plaintext modulus p
		*/
		virtual void SetPlaintextModulus(const PlaintextModulus &plaintextModulus) {
			m_encodingParams->SetPlaintextModulus(plaintextModulus);
		}

		virtual bool operator==(const LPCryptoParameters<Element>& cmp) const = 0;
		virtual bool operator!=(const LPCryptoParameters<Element>& cmp) const { return !(*this == cmp); }

		/**
		 * Overload to allow printing of parameters to an iostream
		 * NOTE that the implementation relies on calling the virtual PrintParameters method
		 * @param out - the stream to print to
		 * @param item - reference to the item to print
		 * @return the stream
		 */
		friend std::ostream& operator<<(std::ostream& out, const LPCryptoParameters& item) {
			item.PrintParameters(out);
			return out;
		}

		virtual usint GetRelinWindow() const { return 0; }

		virtual int GetDepth() const { return 0; }
		virtual size_t GetMaxDepth() const { return 0; }

		virtual const typename Element::DggType &GetDiscreteGaussianGenerator() const {
			PALISADE_THROW(config_error, "No DGG Available for this parameter set");
		}

		/**
		 * Sets the reference to element params
		 */
		virtual void SetElementParams(shared_ptr<typename Element::Params> params) {
			m_params = params;
		}

        /**
         * Sets the reference to encoding params
         */
		virtual void SetEncodingParams(EncodingParams encodingParams) {
			m_encodingParams = encodingParams;
		}

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
			ar( ::cereal::make_nvp("elp", m_params) );
			ar( ::cereal::make_nvp("enp", m_encodingParams) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}
			ar( ::cereal::make_nvp("elp", m_params) );
			ar( ::cereal::make_nvp("enp", m_encodingParams) );
		}

		std::string SerializedObjectName() const { return "CryptoParameters"; }
		static uint32_t	SerializedVersion() { return 1; }

	protected:
		LPCryptoParameters(const PlaintextModulus &plaintextModulus) {
			m_encodingParams.reset( new EncodingParamsImpl(plaintextModulus) );
		}

		LPCryptoParameters(shared_ptr<typename Element::Params> params, const PlaintextModulus &plaintextModulus) {
			m_params = params;
			m_encodingParams.reset( new EncodingParamsImpl(plaintextModulus) );
		}

		LPCryptoParameters(shared_ptr<typename Element::Params> params, EncodingParams encodingParams) {
			m_params = params;
			m_encodingParams = encodingParams;
		}

		LPCryptoParameters(LPCryptoParameters<Element> *from, shared_ptr<typename Element::Params> newElemParms) {
			*this = *from;
			m_params = newElemParms;
		}

		virtual void PrintParameters(std::ostream& out) const {
			out << "Element Parameters: " << *m_params << std::endl;
			out << "Encoding Parameters: " << *m_encodingParams << std::endl;
		}

	private:
		//element-specific parameters
		shared_ptr<typename Element::Params>		m_params;

		//encoding-specific parameters
		EncodingParams								m_encodingParams;
	};

	// forward decl so SchemeIdentifier works
	template<typename Element> class LPPublicKeyEncryptionScheme;

	template<typename Element>
	class PalisadeSchemeIdentifier {
		string									schemeName;
		LPPublicKeyEncryptionScheme<Element>	*(*schemeMaker)();
	public:
		PalisadeSchemeIdentifier(string n, LPPublicKeyEncryptionScheme<Element> (*f)())
			: schemeName(n), schemeMaker(f) {}

		const string& GetName() const { return schemeName; }
		LPPublicKeyEncryptionScheme<Element> *GetScheme() const { return (*schemeMaker)(); }
	};

	/**
	 * @brief Abstract interface for public key encryption schemes
	 * @tparam Element a ring element.
	 */
	template<typename Element>
	class LPPublicKeyEncryptionScheme {
	protected:
		//PalisadeSchemeIdentifier<Element> *SchemeId;

	public:
		LPPublicKeyEncryptionScheme() {}

		virtual ~LPPublicKeyEncryptionScheme() {}
		
		virtual bool operator==(const LPPublicKeyEncryptionScheme& sch) const = 0;

		virtual bool operator!=(const LPPublicKeyEncryptionScheme& sch) const {
			return !(*this == sch);
		}

		/**
		 * Enable features with a bit mast of PKESchemeFeature codes
		 * @param mask
		 */
		virtual void Enable(usint mask) {

			if (mask&ENCRYPTION) Enable(ENCRYPTION);

			if (mask&PRE) Enable(PRE);

			if (mask&SHE) Enable(SHE);

			if (mask&LEVELEDSHE) Enable(LEVELEDSHE);

			if (mask&MULTIPARTY) Enable(MULTIPARTY);

		}

		virtual usint GetEnabled() const {
			usint flag = 0;

			if (m_algorithmEncryption != NULL)
				flag |= ENCRYPTION;
			if (m_algorithmPRE != NULL)
				flag |= PRE;
			if (m_algorithmSHE != NULL)
				flag |= SHE;
			if (m_algorithmLeveledSHE != NULL)
				flag |= LEVELEDSHE;
			if (m_algorithmMultiparty != NULL)
				flag |= MULTIPARTY;

			return flag;
		}

		//instantiated in the scheme implementation class
		virtual void Enable(PKESchemeFeature feature) = 0;

		/////////////////////////////////////////
		// wrapper for LPParameterSelectionAlgorithm
		//

		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0, size_t dcrtBits = 0, uint32_t n = 0) const {
			if (this->m_algorithmParamsGen) {
				return this->m_algorithmParamsGen->ParamsGen(cryptoParams, evalAddCount, evalMultCount, keySwitchCount, dcrtBits, n);
			}
			else {
				PALISADE_THROW(not_implemented_error, "Parameter generation operation has not been implemented");
			}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPEncryptionAlgorithm (ENCRYPT)
		//

		virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
			const Element &plaintext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(publicKey,plaintext);
				}
				else {
					PALISADE_THROW(config_error, "Encrypt operation has not been enabled");
				}
		}

		virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
			const Element &plaintext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(privateKey,plaintext);
				}
				else {
					PALISADE_THROW(config_error, "Encrypt operation has not been enabled");
				}
		}

		virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey, ConstCiphertext<Element> ciphertext,
				NativePoly *plaintext) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					PALISADE_THROW(config_error, "Decrypt operation has not been enabled");
				}
		}

		virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey, ConstCiphertext<Element> ciphertext,
				Poly *plaintext) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					PALISADE_THROW(config_error, "Decrypt operation has not been enabled");
				}
		}

		virtual LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse) {
				if(this->m_algorithmEncryption) {
					auto kp = this->m_algorithmEncryption->KeyGen(cc, makeSparse);
					kp.publicKey->SetKeyTag( kp.secretKey->GetKeyTag() );
					return kp;
				}
				else {
					PALISADE_THROW(config_error, "KeyGen operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPPREAlgorithm (PRE)
		//

		virtual LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const {
			if(this->m_algorithmPRE) {
				auto rk = this->m_algorithmPRE->ReKeyGen(newKey,origPrivateKey);
				rk->SetKeyTag( newKey->GetKeyTag() );
				return rk;
			} else {
				PALISADE_THROW(config_error, "ReKeyGen operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
				ConstCiphertext<Element> ciphertext,
				const LPPublicKey<Element> publicKey) const {
			if(this->m_algorithmPRE) {
				auto ct = this->m_algorithmPRE->ReEncrypt(evalKey, ciphertext, publicKey);
				ct->SetKeyTag( evalKey->GetKeyTag() );
				return ct;
			} else {
				PALISADE_THROW(config_error, "ReEncrypt operation has not been enabled");
			}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPMultipartyAlgorithm (Multiparty)
		//

		// Wrapper for Multiparty Key Gen
		// FIXME check key ID for multiparty
		virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const LPPublicKey<Element> pk1,
				bool makeSparse, bool PRE) {
			if(this->m_algorithmMultiparty) {
				auto k = this->m_algorithmMultiparty->MultipartyKeyGen(cc, pk1, makeSparse, PRE);
				k.publicKey->SetKeyTag( k.secretKey->GetKeyTag() );
				return k;
			} else {
				PALISADE_THROW(config_error, "MultipartyKeyGen operation has not been enabled");
			}
		}

		// Wrapper for Multiparty Key Gen
		// FIXME key IDs for multiparty
		virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
			const vector<LPPrivateKey<Element>>& secretKeys,
			bool makeSparse) {
				if(this->m_algorithmMultiparty) {
					auto k = this->m_algorithmMultiparty->MultipartyKeyGen(cc, secretKeys, makeSparse);
					k.publicKey->SetKeyTag( k.secretKey->GetKeyTag() );
					return k;
				} else {
					PALISADE_THROW(config_error, "MultipartyKeyGen operation has not been enabled");
				}
		}

		// FIXME key IDs for multiparty
		virtual Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext) const {
				if(this->m_algorithmMultiparty) {
					auto ct = this->m_algorithmMultiparty->MultipartyDecryptMain(privateKey,ciphertext);
					ct->SetKeyTag( privateKey->GetKeyTag() );
					return ct;
				} else {
					PALISADE_THROW(config_error, "MultipartyDecryptMain operation has not been enabled");
				}
		}

		// FIXME key IDs for multiparty
		virtual Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
				ConstCiphertext<Element> ciphertext) const {
				if(this->m_algorithmMultiparty) {
					auto ct = this->m_algorithmMultiparty->MultipartyDecryptLead(privateKey,ciphertext);
					ct->SetKeyTag( privateKey->GetKeyTag() );
					return ct;
				} else {
					PALISADE_THROW(config_error, "MultipartyDecryptLead operation has not been enabled");
				}
		}

		virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				NativePoly *plaintext) const {
				if(this->m_algorithmMultiparty) {
					return this->m_algorithmMultiparty->MultipartyDecryptFusion(ciphertextVec,plaintext);
				} else {
					PALISADE_THROW(config_error, "MultipartyDecrypt operation has not been enabled");
				}
		}

		virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				Poly *plaintext) const {
				if(this->m_algorithmMultiparty) {
					return this->m_algorithmMultiparty->MultipartyDecryptFusion(ciphertextVec,plaintext);
				} else {
					PALISADE_THROW(config_error, "MultipartyDecrypt operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->AddRandomNoise(ciphertext);
			else {
				PALISADE_THROW(config_error, "AddRandomNoise operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
				ConstCiphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAdd(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext1,
				Ciphertext<Element> &ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAddMutable(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
				ConstPlaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAdd(ciphertext1, plaintext);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext1,
				Plaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAddMutable(ciphertext1, plaintext);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
				double constant) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAdd(ciphertext1, constant);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalLinearWSum(
				vector<Ciphertext<Element>> ciphertexts,
				vector<double> constants) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalLinearWSum(ciphertexts, constants);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalLinearWSum operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalLinearWSumMutable(
				vector<Ciphertext<Element>> ciphertexts,
				vector<double> constants) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalLinearWSumMutable(ciphertexts, constants);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalLinearWSum operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSub(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext1,
			Ciphertext<Element> &ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSubMutable(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
				ConstPlaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSub(ciphertext1, plaintext);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext1,
				Plaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSubMutable(ciphertext1, plaintext);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
				double constant) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSub(ciphertext1, constant);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
			Ciphertext<Element> &ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMultMutable(ciphertext1, ciphertext2);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
			ConstPlaintext plaintext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalMult(ciphertext, plaintext);
			else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
			ConstPlaintext plaintext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalMultMutable(ciphertext, plaintext);
			else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
				double constant) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMult(ciphertext1, constant);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
				double constant) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMultMutable(ciphertext1, constant);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
				ConstCiphertext<Element> ciphertext2,
				const LPEvalKey<Element> evalKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
				Ciphertext<Element> &ciphertext2,
				const LPEvalKey<Element> evalKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMultMutable(ciphertext1, ciphertext2, evalKey);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& ciphertext, const vector<LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE){
				return this->m_algorithmSHE->EvalMultMany(ciphertext, evalKeys);
			}
			else {
				PALISADE_THROW(config_error, "EvalMultMany operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAddMany(
				const vector<Ciphertext<Element>>& ciphertexts) const {

			if (this->m_algorithmSHE){
				return this->m_algorithmSHE->EvalAddMany(ciphertexts);
			}
			else {
				PALISADE_THROW(config_error, "EvalMultMany operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalAddManyInPlace(
				vector<Ciphertext<Element>>& ciphertexts) const {

			if (this->m_algorithmSHE){
				return this->m_algorithmSHE->EvalAddManyInPlace(ciphertexts);
			}
			else {
				PALISADE_THROW(config_error, "EvalAddManyInPlace operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalNegate(ciphertext);
				return ct;
			} else {
				PALISADE_THROW(config_error, "EvalNegate operation has not been enabled");
			}
		}

		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<usint> &indexList) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalAutomorphismKeyGen(publicKey,origPrivateKey,indexList);
				for( auto& k : *km )
					k.second->SetKeyTag( origPrivateKey->GetKeyTag() );
				return km;
			} else
				PALISADE_THROW(config_error, "EvalAutomorphismKeyGen operation has not been enabled");
		}

		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAtIndexKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<int32_t> &indexList) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalAtIndexKeyGen(publicKey,origPrivateKey,indexList);
				for( auto& k : *km )
					k.second->SetKeyTag( origPrivateKey->GetKeyTag() );
				return km;
			} else
				PALISADE_THROW(config_error, "EvalAtIndexKeyGen operation has not been enabled");
		}

		virtual Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAutomorphism(ciphertext, i, evalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalAutomorphism operation has not been enabled");
		}


		virtual Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAtIndex(ciphertext, i, evalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalAtIndex operation has not been enabled");
		}

		virtual shared_ptr<vector<Element>> EvalFastRotationPrecompute(
				ConstCiphertext<Element> ciphertext
				) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalFastRotationPrecompute(ciphertext);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalFastRotationPrecompute operation has not been enabled");
		}

		virtual Ciphertext<Element> EvalFastRotation(
				ConstCiphertext<Element> ciphertext,
				const usint index,
				const usint m,
				const shared_ptr<vector<Element>> digits
				) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalFastRotation(ciphertext, index, m, digits);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalFastRotation operation has not been enabled");
		}


		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalAutomorphismKeyGen(privateKey, indexList);
				for( auto& k : *km )
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				return km;
			} else
				PALISADE_THROW(config_error, "EvalAutomorphismKeyGen operation has not been enabled");
		}

		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(
			const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalSumKeyGen(privateKey,publicKey);
				for( auto& k : *km ) {
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				}
				return km;
			} else
				PALISADE_THROW(config_error, "EvalSumKeyGen operation has not been enabled");
		}

		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(
			const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey, usint rowSize) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalSumRowsKeyGen(privateKey,publicKey,rowSize);
				for( auto& k : *km ) {
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				}
				return km;
			} else
				PALISADE_THROW(config_error, "EvalSumRowsKeyGen operation has not been enabled");
		}

		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(
			const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalSumColsKeyGen(privateKey,publicKey);
				for( auto& k : *km ) {
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				}
				return km;
			} else
				PALISADE_THROW(config_error, "EvalSumColsKeyGen operation has not been enabled");
		}

		virtual Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSum(ciphertext, batchSize, evalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalSum operation has not been enabled");

		}

		virtual Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSumRows(ciphertext, rowSize, evalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalSumRow operation has not been enabled");

		}

		virtual Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys, const std::map<usint, LPEvalKey<Element>> &rightEvalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSumCols(ciphertext, batchSize, evalKeys, rightEvalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalSumCols operation has not been enabled");

		}

		virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
			const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeys, evalMultKey);
				ct->SetKeyTag( evalSumKeys.begin()->second->GetKeyTag() );
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalInnerProduct operation has not been enabled");

		}

		virtual Ciphertext<Element> EvalMerge(const vector<Ciphertext<Element>> &ciphertextVector,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMerge(ciphertextVector,evalKeys);
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalMerge operation has not been enabled");
		}


		virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
			ConstPlaintext ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeys);
			else
				PALISADE_THROW(config_error, "EvalInnerProduct operation has not been enabled");

		}

		virtual shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				string kID = evalMultKey->GetKeyTag();
				auto ctm = this->m_algorithmSHE->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, evalMultKey);
				for( size_t r = 0; r < ctm->GetRows(); r++ )
					for( size_t c = 0; c < ctm->GetCols(); c++ )
						(*ctm)(r,c).SetKeyTag(kID);
				return ctm;
			} else
				PALISADE_THROW(config_error, "EvalLinRegressionBatched operation has not been enabled");
		}


		virtual Ciphertext<Element>
			EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				usint indexStart, usint length,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, evalMultKey);
				// FIXME: mark with which key?
				return ct;
			} else
				PALISADE_THROW(config_error, "EvalCrossCorrelation operation has not been enabled");
		}


		/**
		* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
		* @param x - matrix of regressors
		* @param y - vector of dependent variables
		* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
		*/
		virtual shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
		{

			if (this->m_algorithmSHE) {
				auto ctm = this->m_algorithmSHE->EvalLinRegression(x, y);
				// FIXME mark with which key??
				return ctm;
			} else {
				PALISADE_THROW(config_error, "EvalLinRegression operation has not been enabled");
			}

		}

		virtual LPEvalKey<Element> KeySwitchGen(
			const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const {
			if (this->m_algorithmSHE) {
				auto kp = this->m_algorithmSHE->KeySwitchGen(originalPrivateKey, newPrivateKey);
				kp->SetKeyTag( newPrivateKey->GetKeyTag() );
				return kp;

			} else {
				PALISADE_THROW(config_error, "KeySwitchGen operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> KeySwitch(
			const LPEvalKey<Element> keySwitchHint,
			ConstCiphertext<Element> cipherText) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->KeySwitch(keySwitchHint, cipherText);
				return ct;

			}
			else {
				PALISADE_THROW(config_error, "KeySwitch operation has not been enabled");
			}
		}

		virtual LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newKey, const LPPrivateKey<Element> origPrivateKey) const {
			if (this->m_algorithmSHE) {
				auto kp = this->m_algorithmSHE->KeySwitchRelinGen(newKey, origPrivateKey);
				kp->SetKeyTag( newKey->GetKeyTag() );
				return kp;
			} else {
				PALISADE_THROW(config_error, "KeySwitchRelinGen operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			ConstCiphertext<Element> ciphertext) const {
			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->KeySwitchRelin(evalKey, ciphertext);
				ct->SetKeyTag( evalKey->GetKeyTag() );
				return ct;
			} else {
				PALISADE_THROW(config_error, "KeySwitchRelin operation has not been enabled");
			}
		}

		virtual LPEvalKey<Element> EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const {
				if(this->m_algorithmSHE) {
					auto ek = this->m_algorithmSHE->EvalMultKeyGen(originalPrivateKey);
					ek->SetKeyTag( originalPrivateKey->GetKeyTag() );
					return ek;
				} else {
					PALISADE_THROW(config_error, "EvalMultKeyGen operation has not been enabled");
				}
		}
		
		virtual vector<LPEvalKey<Element>> EvalMultKeysGen(const LPPrivateKey<Element> originalPrivateKey) const {
				if(this->m_algorithmSHE){
					auto ek = this->m_algorithmSHE->EvalMultKeysGen(originalPrivateKey);
					for(size_t i=0; i<ek.size(); i++)
						ek[i]->SetKeyTag( originalPrivateKey->GetKeyTag() );
					return ek;
				}
				else {
					PALISADE_THROW(config_error, "EvalMultKeysGen operation has not been enabled");
				}
		}

		virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct2, const vector<LPEvalKey<Element>> &ek) const {
				if(this->m_algorithmSHE)
					return this->m_algorithmSHE->EvalMultAndRelinearize(ct1, ct2, ek);
				else {
					PALISADE_THROW(config_error, "EvalMultAndRelinearize operation has not been enabled");
				}
		}

		virtual Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext, const vector<LPEvalKey<Element>> &ek) const {
				if(this->m_algorithmSHE)
					return this->m_algorithmSHE->Relinearize(ciphertext, ek);
				else {
					PALISADE_THROW(config_error, "Relinearize operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPFHEAlgorithm (FHE)
		//
		// TODO: Add Bootstrap and any other FHE methods

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> cipherText) const {
			if(this->m_algorithmLeveledSHE) {
				auto ct = this->m_algorithmLeveledSHE->ModReduce(cipherText);
				ct->SetKeyTag( cipherText->GetKeyTag() );
				return ct;
			}
			else{
				PALISADE_THROW(config_error, "ModReduce operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> ComposedEvalMult(
							ConstCiphertext<Element> cipherText1,
							ConstCiphertext<Element> cipherText2,
							const LPEvalKey<Element> quadKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				auto ct = this->m_algorithmLeveledSHE->ComposedEvalMult(cipherText1,cipherText2,quadKeySwitchHint);
				ct->SetKeyTag( quadKeySwitchHint->GetKeyTag() );
				return ct;
			}
			else{
				PALISADE_THROW(config_error, "ComposedEvalMult operation has not been enabled");
			}
		}

		virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element> cipherText1,
				const LPEvalKeyNTRU<Element> linearKeySwitchHint, size_t levels = 1) const {
			if(this->m_algorithmLeveledSHE){
				auto ct = this->m_algorithmLeveledSHE->LevelReduce(cipherText1,linearKeySwitchHint,levels);
				ct->SetKeyTag( cipherText1->GetKeyTag() );
				return ct;
			}
			else{
				PALISADE_THROW(config_error, "LevelReduce operation has not been enabled");
			}
		}

		/*
		 * This exposes CKKS's own ParamsGen through the LPPublicKeyEncryptionSchemeCKKS API.
		 * See LPAlgorithmParamsGenCKKS::ParamsGen for a description of the arguments.
		 *
		 */
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
				   usint cyclOrder,
				   usint numPrimes,
				   usint scaleExp,
				   usint relinWindow,
				   MODE mode,
				   enum KeySwitchTechnique ksTech,
				   usint firstModSize,
				   RescalingTechnique rsTech,
				   uint32_t numLargeDigits) const {

			if (this->m_algorithmParamsGen) {
				return m_algorithmParamsGen->ParamsGen(cryptoParams, cyclOrder, numPrimes, scaleExp,
											relinWindow, mode, ksTech, firstModSize, rsTech,
											numLargeDigits);
			}
			else {
				PALISADE_THROW(not_implemented_error, "Parameter generation operation has not been implemented for this scheme.");
			}
		}

		/*
		 * Internal method performing level reduce (drop towers).
		 * It's exposed here so methods in LPAlgorithmSHECKKS can access methods
		 * from LPLeveledSHEAlgorithmCKKS (so that automatic rescaling can work
		 * in EXACTRESCALE).
		 *
		 * @param cipherText1 input ciphertext
		 * @param linearKeySwitchHint not used in the CKKS scheme.
		 * @param levels the number of towers to drop from the input ciphertext
		 * @return a ciphertext of the same plaintext value as that of the input,
		 *         but with fewer towers.
		 *
		 */
		virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element> cipherText1,
				const LPEvalKey<Element> linearKeySwitchHint, size_t levels)  const {

			if (this->m_algorithmLeveledSHE) {
				return m_algorithmLeveledSHE->LevelReduceInternal(cipherText1, linearKeySwitchHint, levels);
			}
			else {
				PALISADE_THROW(not_implemented_error, "LevelReduceInternal has not been enabled for this scheme.");
			}
		}

		/*
		 * Internal method performing mod reduce (rescaling).
		 * It's exposed here so methods in LPAlgorithmSHECKKS can access the method
		 * from LPLeveledSHEAlgorithmCKKS (so that automatic rescaling can work
		 * in EXACTRESCALE).
		 *
		 * @param cipherText1 input ciphertext
		 * @return the rescaled ciphertext.
		 *
		 */
		virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> cipherText) const {
			if (this->m_algorithmLeveledSHE) {
				return m_algorithmLeveledSHE->ModReduceInternal(cipherText);
			}
			else {
				PALISADE_THROW(config_error, "ModReduceInternal has not been enabled for this scheme.");
			}
		}

		virtual Ciphertext<Element> AdjustLevelWithRescale(Ciphertext<Element> cipherText, uint32_t targetLevel) const {
			if (this->m_algorithmSHE) {
				return m_algorithmSHE->AdjustLevelWithRescale(cipherText, targetLevel);
			}
			else {
				PALISADE_THROW(config_error, "AdjustLevelWithRescale has not been enabled for this scheme.");
			}
		}

		const std::shared_ptr<LPEncryptionAlgorithm<Element>> getAlgorithm() const { return m_algorithmEncryption; }

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
			ar( ::cereal::make_nvp("enabled",GetEnabled()) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
			if( version > SerializedVersion() ) {
				PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
			}

			usint enabled;
			ar( ::cereal::make_nvp("enabled",enabled) );
			this->Enable(enabled);
		}

		virtual std::string SerializedObjectName() const { return "Scheme"; }
		static uint32_t	SerializedVersion() { return 1; }

		friend std::ostream& operator<<(std::ostream& out, const LPPublicKeyEncryptionScheme<Element>& s) {
			out << typeid(s).name() << ":" ;
			out <<  " ParameterGeneration " << (s.m_algorithmParamsGen == 0 ? "none" : typeid(*s.m_algorithmParamsGen).name());
			out <<  ", Encryption " << (s.m_algorithmEncryption == 0 ? "none" : typeid(*s.m_algorithmEncryption).name());
			out <<  ", PRE " << (s.m_algorithmPRE == 0 ? "none" : typeid(*s.m_algorithmPRE).name());
			out <<  ", Multiparty " << (s.m_algorithmMultiparty == 0 ? "none" : typeid(*s.m_algorithmMultiparty).name());
			out <<  ", SHE " << (s.m_algorithmSHE == 0 ? "none" : typeid(*s.m_algorithmSHE).name());
			out <<  ", LeveledSHE " << (s.m_algorithmLeveledSHE == 0 ? "none" : typeid(*s.m_algorithmLeveledSHE).name());
			return out;
		}

	protected:
		std::shared_ptr<LPParameterGenerationAlgorithm<Element>>	m_algorithmParamsGen;
		std::shared_ptr<LPEncryptionAlgorithm<Element>>				m_algorithmEncryption;
		std::shared_ptr<LPPREAlgorithm<Element>>					m_algorithmPRE;
		std::shared_ptr<LPMultipartyAlgorithm<Element>>				m_algorithmMultiparty;
		std::shared_ptr<LPSHEAlgorithm<Element>>					m_algorithmSHE;
		std::shared_ptr<LPLeveledSHEAlgorithm<Element>>				m_algorithmLeveledSHE;
	
	};


} // namespace lbcrypto ends

#endif
