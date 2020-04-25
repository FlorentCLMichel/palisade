/**
 * @file stst.h -- definitions for StehleSteinfeld Crypto Params
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
 * This code provides support for the Stehle-Steinfeld cryptoscheme.
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *
 */

#ifndef LBCRYPTO_CRYPTO_STST_H
#define LBCRYPTO_CRYPTO_STST_H

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief This is the parameters class for the Stehle-Stenfeld encryption scheme.
 *
 *  Parameters for this scheme are defined here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * @tparam Element a ring element type.
 */
template <class Element>
class LPCryptoParametersStehleSteinfeld : public LPCryptoParametersRLWE<Element> {
public:
	/**
	 * Default constructor.  This constructor initializes all values to 0.
	 */
	LPCryptoParametersStehleSteinfeld() : LPCryptoParametersRLWE<Element>() {
		m_distributionParameterStSt = 0.0f;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Copy constructor.
	 *
	 * @param rhs - source
	 */
	LPCryptoParametersStehleSteinfeld(const LPCryptoParametersStehleSteinfeld &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
		m_distributionParameterStSt = rhs.m_distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

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
	 * @param depth of supported computation circuit (not used; for future use)
	 */
	LPCryptoParametersStehleSteinfeld(
			shared_ptr<typename Element::Params> params,
			const PlaintextModulus &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			float distributionParmStst,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(params,
			EncodingParams( new EncodingParamsImpl(plaintextModulus) ),
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	* Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
	* infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
	* chooses the basic noise, assurance and security parameters as the typical community-accepted values,
	* then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen
	* to provide correctness and security.  In some cases we would need to operate over already
	* encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
	*
	* @param &params Element parameters.  This will depend on the specific class of element being used.
	* @param &encodingParams Plaintext space parameters.
	* @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
	* @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
	* @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes.
	* @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
	* @param depth of supported computation circuit (not used; for future use)
	*/
	LPCryptoParametersStehleSteinfeld(
		shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		float distributionParmStst,
		int depth = 1)
		: LPCryptoParametersRLWE<Element>(params,
			encodingParams,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Returns the value of standard deviation r for discrete Gaussian distribution used in Key Generation
	 *
	 * @return the standard deviation r.
	 */
	float GetDistributionParameterStSt() const {return m_distributionParameterStSt;}

	/**
	 * Returns reference to Discrete Gaussian Generator for keys
	 *
	 * @return reference to Discrete Gaussian Generaror.
	 */
	const typename Element::DggType &GetDiscreteGaussianGeneratorStSt() const {return m_dggStSt;}

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 *
	 * @param distributionParameterStSt distribution parameter r.
	 */
	void SetDistributionParameterStSt(float distributionParameterStSt) {
		m_distributionParameterStSt = distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * == operator to compare to this instance of LPCryptoParametersStehleSteinfeld object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element>& cmp) const {
		const LPCryptoParametersStehleSteinfeld<Element> *el = dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element> *>(&cmp);

		if( el == 0 ) return false;

		return  LPCryptoParametersRLWE<Element>::operator==( cmp ) &&
				m_distributionParameterStSt == el->GetDistributionParameterStSt();
	}

	void PrintParameters(std::ostream& os) const {
		LPCryptoParametersRLWE<Element>::PrintParameters(os);

		os << " StSt distribution parm: " << m_distributionParameterStSt;
	}

	template <class Archive>
	void save ( Archive & ar ) const
	{
	    ar( ::cereal::base_class<LPCryptoParametersRLWE<Element>>( this ) );
	    ar( ::cereal::make_nvp("dp", m_distributionParameterStSt) );
	}

	template <class Archive>
	void load ( Archive & ar )
	{
	    ar( ::cereal::base_class<LPCryptoParametersRLWE<Element>>( this ) );
	    ar( ::cereal::make_nvp("dp", m_distributionParameterStSt) );
		this->SetDistributionParameterStSt(m_distributionParameterStSt);
	}

	std::string SerializedObjectName() const { return "StStSchemeParameters"; }

private:
	//standard deviation in Discrete Gaussian Distribution used for Key Generation
	float m_distributionParameterStSt;
	//Discrete Gaussian Generator for Key Generation
	typename Element::DggType m_dggStSt;
};

/**
 * @brief This is the algorithms class for the basic public key encrypt, decrypt and key generation methods for the Stehle-Stenfeld scheme encryption scheme.  
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmStSt : public LPEncryptionAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmStSt() {};

	/**
	 * Encrypt method for the StSt Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param publicKey The encryption key.
	 * @param plaintext copy of Plaintext to be encrypted.
	 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	 * @return A shared pointer to the encrypted Ciphertext.
	 */
	Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey, Element plaintext) const;

	/**
	 * Encrypt method for the StSt Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param privateKey The encryption key.
	 * @param plaintext Plaintext to be encrypted.
	 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	 * @return A shared pointer to the encrypted Ciphertext.
	 */
	Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey, Element plaintext) const;

	/**
	 * Decrypt method for the StSt Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param privateKey Decryption key.
	 * @param ciphertext Diphertext to be decrypted.
	 * @param plaintext Plaintext result of Decrypt operation.
	 * @return DecryptResult indicating success or failure and number of bytes decrypted.
	 */
	DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext,
		NativePoly *plaintext) const;

	/**
	 * Key Generation method for the StehleSteinfeld scheme.
	 *
	 * @param cc Drypto context in which to generate a key pair.
	 * @param makeSparse set to true if ring reduce by a factor of 2 is to be used.  Generally this should always be false.
	 * @return Public and private key pair.
	 */
	LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse=false);

};

template <class Element>
class LPAlgorithmSHEStSt : public LPSHEAlgorithm<Element> {
public:

		/**
		* Default constructor
		*/
		LPAlgorithmSHEStSt() {};

		/**
		* Function for evaluation addition on ciphertext.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext1 The first input ciphertext.
		* @param ciphertext2 The second input ciphertext.
		* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
		*/
		Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
				ConstCiphertext<Element> ciphertext2) const;

		/**
		* Function for evaluation addition on ciphertext.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext The input ciphertext.
		* @param plaintext The input plaintext.
		* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
		*/
		Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
				ConstPlaintext plaintext) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext1 The first input ciphertext.
		* @param ciphertext2 The second input ciphertext.
		* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
		*/
		Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext The input ciphertext.
		* @param plaintext The input plaintext.
		* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
		*/
		Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
				ConstPlaintext plaintext) const;

		/**
		* Function for evaluating multiplication on ciphertext.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext1 The first input ciphertext.
		* @param ciphertext2 The second input ciphertext.
		* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2) const {
			std::string errMsg = "LPAlgorithmSHEStSt::EvalMult is not implemented for StSt SHE Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Function for multiplying a ciphertext by plaintext.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext Input ciphertext.
		* @param plaintext input plaintext.
		* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
			ConstPlaintext plaintext) const;


		/**
		* Function for evaluating multiplication on ciphertext, but with a key switch performed after the
		* EvalMult using the Evaluation Key input.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ciphertext1 The first input ciphertext.
		* @param ciphertext2 The second input ciphertext.
		* @param evalKey The evaluation key input.
		* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2,
			const LPEvalKey<Element> evalKey) const {
			std::string errMsg = "LPAlgorithmSHEStSt::EvalMult is not implemented for StSt SHE Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Unimplemented function to support  a multiplication with depth larger than 2 for the Stehle-Steinfeld scheme.
		*
		* @param ciphertext1 The first input ciphertext.
		* @param ciphertext2 The second input ciphertext.
		* @param evalKey The evaluation key input.
		* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
		*/
		Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2,
			const vector<LPEvalKey<Element>> &ek) const {
			std::string errMsg = "LPAlgorithmStSt::EvalMultAndRelinearize is not implemented for the Stehle-Steinfeld Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Function for homomorphic negation of ciphertexts.
		* At a high level, this operation substracts the plaintext value encrypted in the ciphertext from the
		* plaintext modulus p.
		* See the class description for citations on where the algorithms were taken from.
		*
		* @param ct The input ciphertext.
		* @return A shared pointer to a new ciphertext which is the negation of the input.
		*/
		Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ct) const;

		/**
		* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme.
		* EvalMult is currently unsopported in the Stehle-Steinfeld scheme and there is no currently known method to
		* support EvalMult in the Stehle-Steinfeld scheme.
		*
		* @param &k1 Original private key used for encryption.
		* @param &k2 New private key to generate the keyswitch hint.
		* @result A shared point to the resulting key switch hint.
		*/
		LPEvalKey<Element> KeySwitchGen(
			const LPPrivateKey<Element> k1,
			const LPPrivateKey<Element> k2) const {
			std::string errMsg = "LPAlgorithmStSt::KeySwitchGen is not implemented for the Stehle-Steinfeld Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Method for KeySwitching based on a KeySwitchHint.
		* See the class description for citations on where the algorithms were taken from.
		* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
		* We recommend that one uses key switch hints only for scenarios where security is not of critical
		* importance.
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param cipherText Original ciphertext to perform switching on.
		* @result A shared pointer to the resulting ciphertext.
		*/
		Ciphertext<Element> KeySwitch(
			const LPEvalKey<Element> keySwitchHint,
			ConstCiphertext<Element> cipherText) const {
			std::string errMsg = "LPAlgorithmStSt::KeySwitch is not implemented for the Stehle-Steinfeld Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Method for KeySwitching based on RLWE relinearization.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
			const LPPrivateKey<Element> origPrivateKey) const;

		/**
		* Method for KeySwitching based on RLWE relinearization
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			ConstCiphertext<Element> ciphertext) const;

		/**
		* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme.
		* EvalMult is currently unsopported in the Stehle-Steinfeld scheme and there is no currently known method to
		* support EvalMult in the Stehle-Steinfeld scheme.
		*
		* @param originalPrivateKey private key to start from when key switching.
		* @return resulting evalkeyswitch hint
		*/
		LPEvalKey<Element> EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const {
			std::string errMsg = "LPAlgorithmStSt::EvalMultKeyGen is not implemented for the Stehle-Steinfeld Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme.
		*
		* @param originalPrivateKey private key to start from when key switching.
		* @return resulting evalkeyswitch hint
		*/
		vector<LPEvalKey<Element>> EvalMultKeysGen(const LPPrivateKey<Element> originalPrivateKey) const {
			std::string errMsg = "LPAlgorithmStSt::EvalMultKeysGen is not implemented for the Stehle-Steinfeld Scheme.";
			PALISADE_THROW(not_implemented_error, errMsg);
		}

		/**
		* Function for evaluating automorphism of ciphertext at index i
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
			PALISADE_THROW(not_implemented_error, "LPAlgorithmSHEStSt::EvalAutomorphism is not implemented for Stehle-Steinfeld SHE Scheme.");
		}

		/**
		* Generate automophism keys for a given private key.  Thess methods are not currently supported.
		*/
		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey, const std::vector<usint> &indexList) const {
			PALISADE_THROW(not_implemented_error, "LPAlgorithmSHEStSt::EvalAutomorphismKeyGen is not implemented for Stehle-Steinfeld SHE Scheme.");
		}

		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const {
			PALISADE_THROW(not_implemented_error, "LPAlgorithmSHEStSt::EvalAutomorphismKeyGen is not implemented for Stehle-Steinfeld SHE Scheme.");
		}


};

/**
 * @brief This is the algorithms class for the Proxy Re-Encryption methods Re-Encryption Key Generation (ReKeyGen) and Re-Encryption (ReEncrypt) for the StSt encryption scheme.
 *
 * This basic public key scheme is defined here:
 *   - L�pez-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our PRE design and algorithms are informed by the design here:
 *   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan. Fast Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM Transactions on Privacy and Security (ACM TOPS).
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPREStSt : public LPPREAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmPREStSt() {}

	/**
	* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
	* This variant that uses the new public key with the original secret key.
	*
	* @param newKey new private key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
		const LPPrivateKey<Element> origPrivateKey) const;

	/**
	* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @param publicKey the public key of the recipient of the re-encrypted ciphertext.
	* @return A shared pointer to the resulting ciphertext.
	*/
	Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
		ConstCiphertext<Element> ciphertext,
		const LPPublicKey<Element> publicKey = nullptr) const;
};


/**
* @brief Main public key encryption scheme for Stehle-Stenfeld scheme implementation,
* @tparam Element a ring element.
*/
/**
* @brief This is the algorithms class for to enable deatures for the Stehle-Stenfeld scheme encryption scheme.  
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeStehleSteinfeld : public LPPublicKeyEncryptionScheme<Element> {
public:
	/**
	* Inherited constructor
	*/
	LPPublicKeyEncryptionSchemeStehleSteinfeld() : LPPublicKeyEncryptionScheme<Element>() {}

	bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
		if( dynamic_cast<const LPPublicKeyEncryptionSchemeStehleSteinfeld<Element> *>(&sch) == 0 )
			return false;
		return true;
	}

	/**
	* Function to enable a scheme.
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmStSt<Element>() );
			break;
		case PRE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmStSt<Element>() );
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE.reset( new LPAlgorithmPREStSt<Element>() );
			break;
		case SHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmStSt<Element>() );
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE.reset( new LPAlgorithmSHEStSt<Element>() );
			break;
		case MULTIPARTY:
			PALISADE_THROW(not_implemented_error, "MULTIPARTY feature not supported for StehleSteinfeld scheme");
		case LEVELEDSHE:
			PALISADE_THROW(not_implemented_error, "LEVELEDSHE feature not supported for StehleSteinfeld scheme");
		case FHE:
			PALISADE_THROW(not_implemented_error, "FHE feature not supported for StehleSteinfeld scheme");
		case ADVANCEDSHE:
			PALISADE_THROW(not_implemented_error, "ADVANCEDSHE feature not supported for StehleSteinfeld scheme");
		case ADVANCEDMP:
			PALISADE_THROW(not_implemented_error, "ADVANCEDMP feature not supported for StehleSteinfeld scheme");
		}
	}

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

	std::string SerializedObjectName() const { return "StStScheme"; }
};


}

#endif
