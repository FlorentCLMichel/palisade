/*
 * @file fhew.cpp - FHEW scheme (RingGSW accumulator) implementation
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
 * We also applied two other optimizations.
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

#include "fhew.h"

namespace lbcrypto {

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::Encrypt(const std::shared_ptr<RingGSWCryptoParams> params,
		const NativePoly &skNTT, const LWEPlaintext &m) const {

	    NativeInteger Q = params->GetLWEParams()->GetQ();
	    int64_t q = params->GetLWEParams()->Getq().ConvertToInt();
	    uint32_t N = params->GetLWEParams()->GetN();
	    uint32_t digitsG = params->GetDigitsG();
	    uint32_t digitsG2 = params->GetDigitsG2();
	    const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

	    std::shared_ptr<RingGSWCiphertext> result = std::make_shared<RingGSWCiphertext>(digitsG2,2);

		DiscreteUniformGeneratorImpl<NativeVector> dug;
		dug.SetModulus(Q);

	    int64_t mm = (((m % q) + q) % q) * (2*N/q);   	// Reduce mod q (dealing with negative number as well)
	    int64_t sign = 1;
	    if (mm >= N) { mm -= N; sign = -1; }

	    // tempA is introduced to minimize the number of NTTs
	    std::vector<NativePoly> tempA(digitsG2);

	    for (uint32_t i = 0; i < digitsG2; ++i) {

	    	(*result)[i][0] = NativePoly(dug,polyParams,COEFFICIENT);
	    	tempA[i] = (*result)[i][0];
	    	(*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(),polyParams,COEFFICIENT);
	    }

	    for (uint32_t i = 0; i < digitsG; ++i) {
	    	if (sign > 0) {
	  	      (*result)[2*i  ][0][mm].ModAddEq(params->GetVGPrime()[i],Q); // Add G Multiple
	  	      (*result)[2*i+1][1][mm].ModAddEq(params->GetVGPrime()[i],Q); // [a,as+e] + X^m *G
	    	}
	    	else
	    	{
			  (*result)[2*i  ][0][mm].ModSubEq(params->GetVGPrime()[i],Q); // Subtract G Multiple
			  (*result)[2*i+1][1][mm].ModSubEq(params->GetVGPrime()[i],Q); // [a,as+e] - X^m *G
	    	}
	    }

	    // 3*digitsG2 NTTs are called
	    for (uint32_t i = 0; i < digitsG2; ++i) {
	    	result->SetFormat(EVALUATION);
	    	tempA[i].SetFormat(EVALUATION);
	    	(*result)[i][1] += tempA[i]*skNTT;
	    }

	    return result;

}

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGen(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::shared_ptr<LWEEncryptionScheme> lwescheme, const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {

	RingGSWEvalKey ek;
    const std::shared_ptr<const LWEPrivateKeyImpl> skN = lwescheme->KeyGenN(params->GetLWEParams());

    ek.KSkey = lwescheme->KeySwitchGen(params->GetLWEParams(),LWEsk,skN);

    NativePoly skNPoly = NativePoly(params->GetPolyParams());
    skNPoly.SetValues(skN->GetElement(),COEFFICIENT);

    skNPoly.SetFormat(EVALUATION);

    NativeInteger q = params->GetLWEParams()->Getq();
    int32_t qInt = params->GetLWEParams()->Getq().ConvertToInt();
    uint32_t n = params->GetLWEParams()->Getn();
    uint32_t baseR = params->GetBaseR();
    std::vector<NativeInteger> digitsR = params->GetDigitsR();

    ek.BSkey = std::make_shared<RingGSWBTKey>(n,baseR,digitsR.size());

    NativeInteger qHalf = q >> 1;

#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i)
      for (uint32_t j = 1; j < baseR; ++j)
        for (uint32_t k = 0; k < digitsR.size(); ++k)
        {
        	int32_t signedSK;
        	if (LWEsk->GetElement()[i] < qHalf)
        		signedSK = LWEsk->GetElement()[i].ConvertToInt();
        	else
        		signedSK = (int32_t)LWEsk->GetElement()[i].ConvertToInt() - qInt;
        	(*ek.BSkey)[i][j][k] = *(Encrypt(params, skNPoly, signedSK * (int32_t)j * (int32_t)digitsR[k].ConvertToInt()));
        }

    return ek;
}

// Accumulation as described in Algorithm 1 of https://eprint.iacr.org/2014/816 (with further optimizations)
void RingGSWAccumulatorScheme::AddToACC(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWCiphertext &input,
		std::shared_ptr<RingGSWCiphertext> acc) const {

	uint32_t N = params->GetLWEParams()->GetN();
	uint32_t digitsG = params->GetDigitsG();
	uint32_t digitsG2 = params->GetDigitsG2();
	NativeInteger Q = params->GetLWEParams()->GetQ();
	int64_t baseG = NativeInteger(params->GetBaseG()).ConvertToInt();
	NativeInteger vInverse = params->GetVInverse();
	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();
	NativeInteger mu = Q.ComputeMu();

	std::vector<NativePoly> ct = acc->GetElements()[0];
	std::vector<NativePoly> dct(digitsG2);

	// initialize dct to zeros
	for(uint32_t i = 0; i < digitsG2; i++)
		dct[i] = NativePoly(polyParams,COEFFICIENT,true);

	for (uint32_t i = 0; i < 2; i++)
		ct[i].SetFormat(COEFFICIENT);

	NativeInteger QHalf = Q>>1;
	int64_t d;

	int64_t gBits = (int64_t)std::log2(baseG);
	int64_t gBits64 = 64 - gBits;

	// Signed digit decomposition
	for (uint32_t j = 0; j < 2; j++) {
		for (uint32_t k = 0; k < N; k++) {
			NativeInteger t = ct[j][k].ModMulFastOptimized(vInverse,Q,mu);
			if (t < QHalf)
				d = t.ConvertToInt();
			else
				d = (int64_t)t.ConvertToInt() - (int64_t)Q.ConvertToInt();

			for (uint32_t l = 0; l < digitsG; l++) {

				// remainder is signed
				int64_t r = (d << gBits64) >> gBits64;

				d = (d-r)>>gBits;

				if (r >= 0)
					dct[j+2*l][k] = NativeInteger(r);
				else
					dct[j+2*l][k] = NativeInteger((int64_t)r + (int64_t)Q.ConvertToInt());

			}
		}
	}

	for (uint32_t j = 0; j < digitsG2; j++)
		dct[j].SetFormat(EVALUATION);

	// acc = dct * input (matrix product);
	for (uint32_t j = 0; j < 2; j++) {
		(*acc)[0][j].SetValuesToZero();
		for (uint32_t l = 0; l < digitsG2; l++) {
			(*acc)[0][j] += dct[l]*input[l][j];
		}
	}

}

// Set a ciphertext to X^m * G (encryption of m without errors) as described in Algorithm 1 of https://eprint.iacr.org/2014/816 (with further optimizations)
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::InitializeACC(const std::shared_ptr<RingGSWCryptoParams> params,
		const LWEPlaintext &m) const {

	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();
	uint32_t N = params->GetLWEParams()->GetN();
	int64_t q = params->GetLWEParams()->Getq().ConvertToInt();
	NativeInteger Q = params->GetLWEParams()->GetQ();

	std::vector<NativePoly> res(2);
	res[0] = NativePoly(polyParams,EVALUATION,true); // no need to do NTT as all coefficients of this poly are zero
	res[1] = NativePoly(polyParams,COEFFICIENT,true);

	int64_t mm = (((m % q) + q) % q) * (2*N/q);   	// Reduce mod q (dealing with negative number as well)
	int64_t sign = 1;
	if (mm >= N) { mm -= N; sign = -1; }

	// different from the FHEW paper
	if (sign > 0)
		res[1][mm].ModAddEq(params->GetVGPrime()[0],Q); // [a,as+e] + X^m *G
	else
		res[1][mm].ModSubEq(params->GetVGPrime()[0],Q); // [a,as+e] - X^m *G

	std::shared_ptr<RingGSWCiphertext> acc = std::make_shared<RingGSWCiphertext>(1,2);

	res[1].SetFormat(EVALUATION);

	(*acc)[0] = std::move(res);

	return acc;

}

// MSB extraction operation as described in Algorithm 2 of https://eprint.iacr.org/2014/816 (with further optimizations)
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::MemberTest(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::shared_ptr<RingGSWCiphertext> &acc) const {

	uint32_t N = params->GetLWEParams()->GetN();
	NativeInteger Q = params->GetLWEParams()->GetQ();

	NativeInteger b;
	NativeVector a(N,Q);

	NativePoly temp = (*acc)[0][0] * params->GetTestPoly();
	temp = temp.Transpose();
	temp.SetFormat(COEFFICIENT);
	a = temp.GetValues();

	temp = (*acc)[0][1] * params->GetTestPoly();
	temp.SetFormat(COEFFICIENT);
	b = params->GetV().ModAddFastOptimized(temp[0],Q);

	return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(a),std::move(b)));

}

// Full evaluation as described in Algorithms 1 and 2 of https://eprint.iacr.org/2014/816 (with further optimizations)
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::EvalBinGate(const std::shared_ptr<RingGSWCryptoParams> params,
			const BINGATE gate, const RingGSWEvalKey& EK, const std::shared_ptr<const LWECiphertextImpl> ct1,
			const std::shared_ptr<const LWECiphertextImpl> ct2, const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {

	NativeInteger q = params->GetLWEParams()->Getq();
	uint32_t n = params->GetLWEParams()->Getn();
	uint32_t baseR = params->GetBaseR();
	std::vector<NativeInteger> digitsR = params->GetDigitsR();

	if (ct1 == ct2)
	{
		std::string errMsg = "ERROR: Please only use independent ciphertexts as inputs."; \
		throw std::runtime_error(errMsg);
	}

	NativeVector a = -(ct1->GetA() + ct2->GetA());
	NativeInteger b = params->GetGateConst()[gate].ModSub(ct1->GetB() + ct2->GetB(),q);

	std::shared_ptr<RingGSWCiphertext> acc = this->InitializeACC(params,(b.ModAddFastOptimized(q>>2,q)).ConvertToInt());

	for (uint32_t i = 0; i < n; i++) {
		NativeInteger aI = q.ModSub(a[i],q);
		for (uint32_t k = 0; k < digitsR.size(); k++, aI /= NativeInteger(baseR)) {
			uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
			if (a0)
				this->AddToACC(params,(*EK.BSkey)[i][a0][k],acc);
		}
	}

	const std::shared_ptr<const LWECiphertextImpl> eQN = this->MemberTest(params,acc);

	const std::shared_ptr<const LWECiphertextImpl> eQ = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

	return  LWEscheme->ModSwitch(params->GetLWEParams(), eQ);

}

// Evaluation of the NOT operation; no key material is needed
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::EvalNOT(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::shared_ptr<const LWECiphertextImpl> ct) const {

	NativeInteger q = params->GetLWEParams()->Getq();
	uint32_t n = params->GetLWEParams()->Getn();

	NativeInteger b;
	NativeVector a(n,q);

	for (uint32_t i = 0; i < n; i++)
		a[i] = q - ct->GetA()[i];
	b =  (q>>2).ModSubFast(ct->GetB(),q);

	return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(a),std::move(b)));
}

};


