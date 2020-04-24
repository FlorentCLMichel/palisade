/**
 * @file bfv.h -- Operations for the BFV cryptoscheme.
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
 /*
 *
 * This code implements the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme.  This scheme is also referred to as the FV scheme.
 * The BFV scheme is introduced here:
 *   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 *
 * Our implementation builds from the designs here:
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *
 */

#ifndef LBCRYPTO_CRYPTO_BFV_H
#define LBCRYPTO_CRYPTO_BFV_H

#include "palisade.h"

namespace lbcrypto {

	/**
 	* @brief This is the parameters class for the BFV encryption scheme.  This scheme is also referred to as the FV scheme.
 	*
 	* The BFV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
 	* @tparam Element a ring element type.
 	*/
	template <class Element>
	class LPCryptoParametersBFV : public LPCryptoParametersRLWE<Element> {

		public:
			/**
			 * Default constructor.
			 */
			LPCryptoParametersBFV();

			/**
		 	 * Copy constructor.
	 		 * @param rhs - source
			 */
			LPCryptoParametersBFV(const LPCryptoParametersBFV &rhs);

			/**
			 * Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
			 * infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
			 * chooses the basic noise, assurance and security parameters as the typical community-accepted values, 
			 * then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen 
			 * to provide correctness and security.  In some cases we would need to operate over already 
			 * encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
			 *
			 * @param &params Element parameters.  This will depend on the specific class of element being used.
			 * @param &plaintextModulus Plaintext modulus, typically denoted as p in most publications.
			 * @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
			 * @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
			 * @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes.
			 * @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
			 * @param delta BFV-specific factor that is multiplied by the plaintext polynomial.
			 * @param mode mode for secret polynomial, defaults to RLWE.
			 * @param bigModulus modulus used in polynomial multiplications in EvalMult
			 * @param bigRootOfUnity root of unity for bigModulus
			 * @param bigModulusArb modulus used in polynomial multiplications in EvalMult (for arbitrary cyclotomics)
			 * @param bigRootOfUnityArb root of unity for bigModulus (for arbitrary cyclotomics)
			 * @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			 * @param maxDepth the maximum power of secret key for which the relinearization key is generated
			 */
			LPCryptoParametersBFV(shared_ptr<typename Element::Params> params,
				const PlaintextModulus &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const typename Element::Integer &delta = typename Element::Integer(0),
				MODE mode = RLWE,
				const typename Element::Integer &bigModulus = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnity = typename Element::Integer(0),
				const typename Element::Integer &bigModulusArb = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnityArb = typename Element::Integer(0),
				int depth = 1,
				int maxDepth = 2);

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level. = BigInteger::ZERO
			* @param securityLevel security level (root Hermite factor).
			* @param relinWindow the size of the relinearization window.
			* @param delta BFV-specific factor that is multiplied by the plaintext polynomial.
			* @param mode mode for secret polynomial, defaults to RLWE.
			* @param bigModulus modulus used in polynomial multiplications in EvalMult
			* @param bigRootOfUnity root of unity for bigModulus
			* @param bigModulusArb modulus used in polynomial multiplications in EvalMult (arbitrary cyclotomics)
			* @param bigRootOfUnityArb root of unity for bigModulus (arbitrary cyclotomics)
			* @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			* @param maxDepth the maximum power of secret key for which the relinearization key is generated
			*/
			LPCryptoParametersBFV(shared_ptr<typename Element::Params> params,
				EncodingParams encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				float securityLevel,
				usint relinWindow,
				const typename Element::Integer &delta = typename Element::Integer(0),
				MODE mode = RLWE,
				const typename Element::Integer &bigModulus = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnity = typename Element::Integer(0),
				const typename Element::Integer &bigModulusArb = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnityArb = typename Element::Integer(0),
				int depth = 1,
				int maxDepth = 2);

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level. = BigInteger::ZERO
			* @param securityLevel standard security level.
			* @param relinWindow the size of the relinearization window.
			* @param delta BFV-specific factor that is multiplied by the plaintext polynomial.
			* @param mode mode for secret polynomial, defaults to RLWE.
			* @param bigModulus modulus used in polynomial multiplications in EvalMult
			* @param bigRootOfUnity root of unity for bigModulus
			* @param bigModulusArb modulus used in polynomial multiplications in EvalMult (arbitrary cyclotomics)
			* @param bigRootOfUnityArb root of unity for bigModulus (arbitrary cyclotomics)
			* @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			* @param maxDepth the maximum power of secret key for which the relinearization key is generated
			*/
			LPCryptoParametersBFV(shared_ptr<typename Element::Params> params,
				EncodingParams encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				SecurityLevel securityLevel,
				usint relinWindow,
				const typename Element::Integer &delta = typename Element::Integer(0),
				MODE mode = RLWE,
				const typename Element::Integer &bigModulus = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnity = typename Element::Integer(0),
				const typename Element::Integer &bigModulusArb = typename Element::Integer(0),
				const typename Element::Integer &bigRootOfUnityArb = typename Element::Integer(0),
				int depth = 1,
				int maxDepth = 2);

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersBFV() {}
			
			/**
			* Gets the value of the delta factor.
			*
			* @return the delta factor. It is an BFV-specific factor that is multiplied by the plaintext polynomial.
			*/
			const typename Element::Integer& GetDelta() const { return m_delta; }

			/**
			* Gets the modulus used for polynomial multiplications in EvalMult
			*
			* @return the modulus value.
			*/
			const typename Element::Integer& GetBigModulus() const { return m_bigModulus; }

			/**
			* Gets the primitive root of unity used for polynomial multiplications in EvalMult
			*
			* @return the primitive root of unity value.
			*/
			const typename Element::Integer& GetBigRootOfUnity() const { return m_bigRootOfUnity; }

			/**
			* Gets the modulus used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*
			* @return the modulus value.
			*/
			const typename Element::Integer& GetBigModulusArb() const { return m_bigModulusArb; }

			/**
			* Gets the primitive root of unity used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*
			* @return the primitive root of unity value.
			*/
			const typename Element::Integer& GetBigRootOfUnityArb() const { return m_bigRootOfUnityArb; }

			/**
			* Sets the value of the delta factor
			* @param &delta is the delta factor
			*/
			void SetDelta(const typename Element::Integer &delta) { m_delta = delta; }

			/**
			* Sets the modulus used for polynomial multiplications in EvalMult
			* 
			* @param &bigModulus the modulus value.
			*/
			void SetBigModulus(const typename Element::Integer &bigModulus) { m_bigModulus = bigModulus; }

			/**
			* Sets primitive root of unity used for polynomial multiplications in EvalMult
			* @param &bigRootOfUnity is the root of unity used for EvalMult operations.
			*/
			void SetBigRootOfUnity(const typename Element::Integer &bigRootOfUnity) { m_bigRootOfUnity = bigRootOfUnity; }

			/**
			* Sets the modulus used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*/
			void SetBigModulusArb(const typename Element::Integer &bigModulusArb) { m_bigModulusArb = bigModulusArb; }

			/**
			* Sets primitive root of unity used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*/
			void SetBigRootOfUnityArb(const typename Element::Integer &bigRootOfUnityArb) { m_bigRootOfUnityArb = bigRootOfUnityArb; }

			/**
			* == operator to compare to this instance of LPCryptoParametersBFV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBFV<Element> *el = dynamic_cast<const LPCryptoParametersBFV<Element> *>(&rhs);

				if( el == 0 ) return false;

				if (m_delta != el->m_delta) return false;
				if (m_bigModulus != el->m_bigModulus) return false;
				if (m_bigRootOfUnity != el->m_bigRootOfUnity) return false;
				if (m_bigModulusArb != el->m_bigModulusArb) return false;
				if (m_bigRootOfUnityArb != el->m_bigRootOfUnityArb) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

			void PrintParameters(std::ostream& os) const {
				LPCryptoParametersRLWE<Element>::PrintParameters(os);

				os << " delta: " << m_delta <<
						" bigmodulus: " << m_bigModulus <<
						" bigrootofunity: " << m_bigRootOfUnity <<
						" bigmodulusarb: " << m_bigModulusArb <<
						" bigrootofunityarb: " << m_bigRootOfUnityArb;
			}

			template <class Archive>
			void save ( Archive & ar, std::uint32_t const version ) const
			{
			    ar( ::cereal::base_class<LPCryptoParametersRLWE<Element>>( this ) );
				ar( ::cereal::make_nvp("d", m_delta) );
				ar( ::cereal::make_nvp("bm", m_bigModulus) );
				ar( ::cereal::make_nvp("br", m_bigRootOfUnity) );
				ar( ::cereal::make_nvp("bma", m_bigModulusArb) );
				ar( ::cereal::make_nvp("bra", m_bigRootOfUnityArb) );
			}

			template <class Archive>
			void load( Archive & ar, std::uint32_t const version )
			{
				if( version > SerializedVersion() ) {
					PALISADE_THROW(deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
				}
			    ar( ::cereal::base_class<LPCryptoParametersRLWE<Element>>( this ) );
				ar( ::cereal::make_nvp("d", m_delta) );
				ar( ::cereal::make_nvp("bm", m_bigModulus) );
				ar( ::cereal::make_nvp("br", m_bigRootOfUnity) );
				ar( ::cereal::make_nvp("bma", m_bigModulusArb) );
				ar( ::cereal::make_nvp("bra", m_bigRootOfUnityArb) );
			}

			std::string SerializedObjectName() const { return "BFVSchemeParameters"; }
			static uint32_t	SerializedVersion() { return 1; }

		private:
			// factor delta = floor(q/p) that is multipled by the plaintext polynomial 
			// in BFV (most significant bit ranges are used to represent the message)
			typename Element::Integer m_delta;
			
			// larger modulus that is used in polynomial multiplications within EvalMult (before rounding is done)
			typename Element::Integer m_bigModulus;
			
			// primitive root of unity for m_bigModulus
			typename Element::Integer m_bigRootOfUnity;

			// Large modulus used for CRT with m_bigModulus
			typename Element::Integer m_bigModulusArb;

			// Primitive root of unity for m_bigModulusArb
			typename Element::Integer m_bigRootOfUnityArb;
	};

	/**
	* @brief Parameter generation for BFV.  This scheme is also referred to as the FV scheme.
	*
 	* The BFV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenBFV : public LPParameterGenerationAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmParamsGenBFV() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		* @param dcrtBits number of bits in each CRT modulus - NOT USED IN BFV
		* @param n ring dimension in case the user wants to use a custom ring dimension
		*/
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0, size_t dcrtBits = 0, uint32_t n = 0) const;

		virtual ~LPAlgorithmParamsGenBFV() {}
	};

	/**
	* @brief Encryption algorithm implementation for BFV for the basic public key encrypt, decrypt and key generation methods for the BFV encryption scheme.  This scheme is also referred to as the FV scheme.
	*
 	* The BFV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBFV : public LPEncryptionAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmBFV() {}

		virtual ~LPAlgorithmBFV() {}

		/**
		* Method for encrypting plaintext using BFV.
		*
		* @param publicKey public key used for encryption.
		* @param plaintext the plaintext input.
		* @return ciphertext which results from encryption.
		*/
		virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
			Element plaintext) const;

		/**
		* Method for encrypting plaintext with private key using BFV.
		*
		* @param privateKey private key used for encryption.
		* @param plaintext the plaintext input.
		* @return ciphertext which results from encryption.
		*/
		virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
				Element plaintext) const;

		/**
		* Method for decrypting using BFV. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param privateKey private key used for decryption.
		* @param ciphertext ciphertext to be decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
			ConstCiphertext<Element> ciphertext,
			NativePoly *plaintext) const;

		/**
		* Function to generate public and private keys. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.  Generally this should always be false.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse=false);
	};

	/**
	* @brief SHE algorithms implementation for BFV.  This scheme is also referred to as the FV scheme.
	*
 	* The BFV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEBFV : public LPSHEAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmSHEBFV() {}

		virtual ~LPAlgorithmSHEBFV() {}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param ct1 fist input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ct1,
				ConstCiphertext<Element> ct2) const;

		/**
		* Function for homomorphic addition of ciphertext and plaintext.
		*
		* @param ct1 input ciphertext.
		* @param pt  input ciphertext.
		* @return new ciphertext.
		*/
		virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ct,
				ConstPlaintext pt) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct2) const;

		/**
		* Function for homomorphic subtraction of ciphertext ans plaintext.
		*
		* @param ct input ciphertext.
		* @param pt input ciphertext.
		* @return new ciphertext.
		*/
		virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct1,
				ConstPlaintext pt) const;

		/**
		* Function for homomorphic evaluation of ciphertexts.
		* The multiplication is supported for a fixed level without keyswitching requirement (default level=2).
		* If the total depth of the ciphertexts exceeds the supported level, it throws an error.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return resulting EvalMult ciphertext.
		*/
		virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct2) const;

		/**
		* Function for multiplying ciphertext by plaintext.
		*
		* @param ciphertext input ciphertext.
		* @param plaintext input plaintext embedded in the cryptocontext.
		* @return result of the multiplication.
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
			ConstPlaintext plaintext) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		* Currently it assumes that the input arguments are fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher depths will be added later.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext 
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @return new ciphertext
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct, const LPEvalKey<Element> ek) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by relinearization operation. It computes the
		* multiplication in a binary tree manner. Also, it reduces the number of elements in the ciphertext to two after each multiplication.
		* Currently it assumes that the consecutive two input arguments have total depth smaller than the supported depth. Otherwise, it throws an error.
		*
		* @param cipherTextList  is the ciphertext list.
		* @param evalKeys is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext list.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& cipherTextList, const vector<LPEvalKey<Element>> &evalKeys) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by relinearization operation.
		* Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @return new ciphertext
		*/
		virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct, const vector<LPEvalKey<Element>> &ek) const;

		/**
		* Function for homomorphic negation of ciphertexts.
		*
		* @param ct first input ciphertext.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ct) const;

		/**
		* Method for generating a KeySwitchHint using RLWE relinearization
		*
		* @param originalPrivateKey Original private key used for encryption.
		* @param newPrivateKey New private key to generate the keyswitch hint.
		* @return resulting keySwitchHint.
		*/
		virtual LPEvalKey<Element> KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const;

		/**
		* Method for key switching based on a KeySwitchHint using RLWE relinearization
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		* @return new ciphertext
		*/
		virtual Ciphertext<Element> KeySwitch(const LPEvalKey<Element> keySwitchHint,
			ConstCiphertext<Element> cipherText) const;

		/**
		* Method for KeySwitching based on RLWE relinearization and NTRU key generation.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		* Not implemented for BFV.
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
			const LPPrivateKey<Element> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmSHEBFV:KeySwitchRelinGen is not needed for this scheme as relinearization is the default technique and no NTRU key generation is used.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Method for KeySwitching based on RLWE relinearization and NTRU key generation
		* Not implemented for BFV.
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			ConstCiphertext<Element> ciphertext) const {
			std::string errMsg = "LPAlgorithmSHEBFV:KeySwitchRelin is not needed for this scheme as relinearization is the default technique and no NTRU key generation is used.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Function to generate 1..log(q) encryptions for each bit of the square of the original private key
		*
		* @param k1 private key.
		* @return evaluation key.
		*/
		LPEvalKey<Element> EvalMultKeyGen(
					const LPPrivateKey<Element> k1) const;

		/**
		* Function to generate 1..log(q) encryptions for each bit of the powers of the original private key.
		* The number of the powers is determined by the depth. If we choose depth 4, it means we can decrypt
		* ciphertexts with 5 elements. For c[i] being the ciphertext elements, we compute \sum_{i=0}^{i<5} c[i]*s^i.
		*
		* @param k1 private key.
		* @return evaluation key.
		*/
		vector<LPEvalKey<Element>> EvalMultKeysGen(
					const LPPrivateKey<Element> k1) const;

		/**
		* Function for evaluating automorphism of ciphertext at index i.
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const;

		/**
		* Generate automophism keys for a given private key; Uses the private key for encryption
		*
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const;

		/**
		* Generate automophism keys for a given private key; Uses the public key for encryption
		*
		* @param publicKey public key.
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> privateKey, const std::vector<usint> &indexList) const {
			std::string errMsg = "LPAlgorithmSHEBFV::EvalAutomorphismKeyGen is not implemented for BFV SHE Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}
	};

	/**
	* @brief PRE scheme based on BFV. This functionality is currently DISABLED in LPPublicKeyEncryptionSchemeBFV because
	* it needs more testing
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREBFV : public LPPREAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmPREBFV() {}

		/*
		* DISABLED. Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the new secret key directly.
		*
		* @param newKey new private key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
			const LPPrivateKey<Element> origPrivateKey) const;

		/**
		* The generation of re-encryption keys is based on the BG-PRE scheme described in
		* Polyakov, et. al., "Fast proxy re-encryption for publish/subscribe systems".
		*
		* The above scheme was found to have a weakness in Cohen, "What about Bob? The
		* inadequacy of CPA Security for proxy re-encryption". Section 5.1 shows an attack
		* where given an original ciphertext c=(c0,c1) and a re-encrypted ciphertext
		* c'=(c'0, c'1), the subscriber (Bob) can compute the secret key of the publisher
		* (Alice).
		*
		* We fix this vulnerability by making re-encryption keys be encryptions of the
		* s*(2^{i*r}) terms, instead of simple addition as previously defined. This makes
		* retrieving the secret key using the above attack as hard as breaking the RLWE
		* assumption.
		*
		* Our modification makes the scheme CPA-secure, but does not achieve HRA-security
		* as it was defined in the Cohen paper above. Please look at the ReEncrypt method
		* for an explanation of the two security definitions and how to achieve each in
		* Palisade.
		*
		* @param newKey public key for the new private key.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
			const LPPrivateKey<Element> origPrivateKey) const;

		/**
		* This method implements re-encryption using the evaluation key generated by ReKeyGen.
		*
		* The PRE scheme used can achieve two different levels of security, based on the value
		* supplied in the publicKey argument:
		*
		* If publicKey is nullptr, the PRE scheme is CPA-secure. If the publicKey of the
		* recipient of the re-encrypted ciphertext is supplied, then the scheme is HRA-
		* secure. Please refer to Cohen, "What about Bob? The inadequacy of CPA Security for
		* proxy re-encryption", for more information on HRA security.
		*
		* The tradeoff of going for HRA is twofold: (1) performance is a little worst because
		* we add one additional encryption and homomorphic addition to the result, and (2) more
		* noise is added to the result because of the additional operations - in particular,
		* the extra encryption draws noise from a distribution whose standard deviation is
		* scaled by K, the number of digits in the PRE decomposition.
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @param publicKey the public key of the recipient of the re-encrypted ciphertext.
		* @return resulting ciphertext after the re-encryption operation.
		*/
		Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
			ConstCiphertext<Element> ciphertext,
			const LPPublicKey<Element> publicKey = nullptr) const;
	};


	/**
	 * @brief Concrete class for the FHE Multiparty algorithms on BFV.  A version of this multiparty scheme built on the BGV scheme is seen here:
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
	class LPAlgorithmMultipartyBFV : public LPMultipartyAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmMultipartyBFV() {}

		virtual ~LPAlgorithmMultipartyBFV() {}

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param pk1 private key used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @param pre set to true if proxy re-encryption is used in multi-party protocol
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
			const LPPublicKey<Element> pk1,
			bool makeSparse=false,
			bool pre=false);

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption server key pair in coordination with secret keys of clients.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param secretkeys private keys used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const vector<LPPrivateKey<Element>>& secretKeys,
				bool makeSparse=false);

		/**
		 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
		Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
			ConstCiphertext<Element> ciphertext) const;

		/**
		 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
		Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
			ConstCiphertext<Element> ciphertext) const;

		/**
		 * Method for fusing the partially decrypted ciphertext.
		 *
		 * @param &ciphertextVec ciphertext id decrypted.
		 * @param *plaintext the plaintext output.
		 * @return the decoding result.
		 */
		virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
			NativePoly *plaintext) const;

		LPEvalKey<Element> MultiKeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey,
			const LPEvalKey<Element> ek) const;

		shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
			const std::vector<usint> &indexList) const;

		shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(const LPPrivateKey<Element> privateKey,
			const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const;

		LPEvalKey<Element> MultiAddEvalKeys(LPEvalKey<Element> a, LPEvalKey<Element> b) const;

		LPEvalKey<Element> MultiMultEvalKey(LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk) const;

		shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiAddEvalSumKeys(const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
			const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2) const;

		LPEvalKey<Element> MultiAddEvalMultKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const;


		template <class Archive>
		void save ( Archive & ar ) const
		{
		    ar( cereal::base_class<LPMultipartyAlgorithm<Element>>( this ) );
		}

		template <class Archive>
		void load ( Archive & ar )
		{
		    ar( cereal::base_class<LPMultipartyAlgorithm<Element>>( this ) );
		}

		std::string SerializedObjectName() const { return "BFVMultiparty"; }

	};


	/**
	* @brief Main public key encryption scheme for BFV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBFV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBFV();

		bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
			if( dynamic_cast<const LPPublicKeyEncryptionSchemeBFV<Element> *>(&sch) == 0 )
				return false;
			return true;
		}

		void Enable(PKESchemeFeature feature);

		template <class Archive>
		void save( Archive & ar, std::uint32_t const version ) const
		{
		    ar( ::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>( this ) );
		}

		template <class Archive>
		void load( Archive & ar, std::uint32_t const version )
		{
		    ar( ::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>( this ) );
		}

		std::string SerializedObjectName() const { return "BFVScheme"; }
	};

} // namespace lbcrypto ends

#endif
