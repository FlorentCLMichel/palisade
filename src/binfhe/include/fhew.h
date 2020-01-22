/*
 * @file fhew.h - FHEW scheme header file
 * The scheme is described in https://eprint.iacr.org/2014/816
 * Full reference:
 * @misc{cryptoeprint:2014:816,
 *   author = {Léo Ducas and Daniele Micciancio},
 *   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
 *   howpublished = {Cryptology ePrint Archive, Report 2014/816},
 *   year = {2014},
 *   note = {\url{https://eprint.iacr.org/2014/816}},
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, Duality Technologies Inc.
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

#ifndef BINFHE_FHEW_H
#define BINFHE_FHEW_H

#include "ringcore.h"
#include "lwe.h"

namespace lbcrypto{

/**
 * @brief Ring GSW accumulator scheme described in https://eprint.iacr.org/2014/816
 */
class RingGSWAccumulatorScheme {

public:

	/**
	* Generates a refreshing key
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param lwescheme a shared pointer to additive LWE scheme
	* @param LWEsk a shared pointer to the secret key of the underlying additive LWE scheme
	* @return a shared pointer to the secret key
	*/
	RingGSWEvalKey KeyGen(const std::shared_ptr<RingGSWCryptoParams> params,
			const std::shared_ptr<LWEEncryptionScheme> lwescheme, const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

	/**
	* Evaluates a binary gate (calls bootstrapping as a subroutine)
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param gate the gate; can be AND, OR, NAND, or NOR
	* @param &EK a shared pointer to the bootstrapping keys
	* @param ct1 first ciphertext
	* @param ct2 second ciphertext
	* @param lwescheme a shared pointer to additive LWE scheme
	* @return a shared pointer to the resulting ciphertext
	*/
	std::shared_ptr<LWECiphertextImpl> EvalBinGate(const std::shared_ptr<RingGSWCryptoParams> params,
			const BINGATE gate, const RingGSWEvalKey& EK, const std::shared_ptr<const LWECiphertextImpl> ct1,
			const std::shared_ptr<const LWECiphertextImpl> ct2, const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const;

	/**
	* Evaluates NOT gate
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param ct1 the input ciphertext
	* @return a shared pointer to the resulting ciphertext
	*/
	std::shared_ptr<LWECiphertextImpl> EvalNOT(const std::shared_ptr<RingGSWCryptoParams> params,
			const std::shared_ptr<const LWECiphertextImpl> ct1) const;

private:

	/**
	* Internal RingGSW encryption used in generating the refreshing key
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param skFFT secret key polynomial in the EVALUATION representation
	* @param m plaintext (corresponds to a lookup entry for the LWE scheme secret key)
	* @return a shared pointer to the resulting ciphertext
	*/
	std::shared_ptr<RingGSWCiphertext> Encrypt(const std::shared_ptr<RingGSWCryptoParams> params,
			const NativePoly &skFFT, const LWEPlaintext &m) const;

	/**
	* Main accumulator function used in bootstrapping
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param &input input ciphertext
	* @param acc previous value of the accumulator
	*/
	void AddToACC(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWCiphertext &input,
			std::shared_ptr<RingGSWCiphertext> acc) const;

	/**
	* Initialization of the accumulator
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param &m some initial value used by the accumulator
	* @return the initial RingGSW ciphertext
	*/
	std::shared_ptr<RingGSWCiphertext> InitializeACC(const std::shared_ptr<RingGSWCryptoParams> params,
			const LWEPlaintext &m) const;

	/*
	* MSB extraction operation using a test vector
	*
	* @param params a shared pointer to RingGSW scheme parameters
	* @param &acc RingGSW ciphertext representing the result of accumulation
	* @return the ciphertext for MSB
	*/
	std::shared_ptr<LWECiphertextImpl> MemberTest(const std::shared_ptr<RingGSWCryptoParams> params,
			const std::shared_ptr<RingGSWCiphertext>& acc) const;

};

}

#endif
