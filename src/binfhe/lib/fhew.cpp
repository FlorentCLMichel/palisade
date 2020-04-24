/*
 * @file fhew.cpp - FHEW scheme (RingGSW accumulator) implementation
 * The scheme is described in https://eprint.iacr.org/2014/816 and in
 * Daniele Micciancio and Yuriy Polyakov, "Bootstrapping in FHEW-like Cryptosystems",
 * Cryptology ePrint Archive, Report 2020/086, https://eprint.iacr.org/2020/086.
 *
 * Full reference to https://eprint.iacr.org/2014/816:
 * @misc{cryptoeprint:2014:816,
 *   author = {L�o Ducas and Daniele Micciancio},
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

#include "fhew.h"

namespace lbcrypto {

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::EncryptAP(const std::shared_ptr<RingGSWCryptoParams> params,
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
	  	      (*result)[2*i  ][0][mm].ModAddEq(params->GetGPower()[i],Q); // Add G Multiple
	  	      (*result)[2*i+1][1][mm].ModAddEq(params->GetGPower()[i],Q); // [a,as+e] + X^m*G
	    	}
	    	else
	    	{
			  (*result)[2*i  ][0][mm].ModSubEq(params->GetGPower()[i],Q); // Subtract G Multiple
			  (*result)[2*i+1][1][mm].ModSubEq(params->GetGPower()[i],Q); // [a,as+e] - X^m*G
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

// Encryption for the GINX variant, as described in "Bootstrapping in FHEW-like Cryptosystems"
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::EncryptGINX(const std::shared_ptr<RingGSWCryptoParams> params,
		const NativePoly &skNTT, const LWEPlaintext &m) const {

	NativeInteger Q = params->GetLWEParams()->GetQ();
	uint32_t digitsG = params->GetDigitsG();
	uint32_t digitsG2 = params->GetDigitsG2();
	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

	std::shared_ptr<RingGSWCiphertext> result = std::make_shared<RingGSWCiphertext>(digitsG2,2);

	DiscreteUniformGeneratorImpl<NativeVector> dug;
	dug.SetModulus(Q);

	// tempA is introduced to minimize the number of NTTs
	std::vector<NativePoly> tempA(digitsG2);

	for (uint32_t i = 0; i < digitsG2; ++i) {

		(*result)[i][0] = NativePoly(dug,polyParams,COEFFICIENT);
		tempA[i] = (*result)[i][0];
		(*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(),polyParams,COEFFICIENT);
	}

	for (uint32_t i = 0; i < digitsG; ++i) {
		if (m > 0) {
		  (*result)[2*i  ][0][0].ModAddEq(params->GetGPower()[i],Q); // Add G Multiple
		  (*result)[2*i+1][1][0].ModAddEq(params->GetGPower()[i],Q); // [a,as+e] + G
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

// wrapper for KeyGen methods
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGen(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::shared_ptr<LWEEncryptionScheme> lwescheme, const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {

	if (params->GetMethod() == AP)
		return KeyGenAP(params,lwescheme,LWEsk);
	else // GINX
		return KeyGenGINX(params,lwescheme,LWEsk);

}

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGenAP(const std::shared_ptr<RingGSWCryptoParams> params,
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
        	(*ek.BSkey)[i][j][k] = *(EncryptAP(params, skNPoly, signedSK * (int32_t)j * (int32_t)digitsR[k].ConvertToInt()));
        }

    return ek;
}

// Bootstrapping keys generation for the GINX variant, as described in "Bootstrapping in FHEW-like Cryptosystems"
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGenGINX(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::shared_ptr<LWEEncryptionScheme> lwescheme, const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {

	RingGSWEvalKey ek;
	const std::shared_ptr<const LWEPrivateKeyImpl> skN = lwescheme->KeyGenN(params->GetLWEParams());

    ek.KSkey = lwescheme->KeySwitchGen(params->GetLWEParams(),LWEsk,skN);

    NativePoly skNPoly = NativePoly(params->GetPolyParams());
    skNPoly.SetValues(skN->GetElement(),COEFFICIENT);

    skNPoly.SetFormat(EVALUATION);

    uint64_t q = params->GetLWEParams()->Getq().ConvertToInt();
    uint32_t n = params->GetLWEParams()->Getn();

    ek.BSkey = std::make_shared<RingGSWBTKey>(1,2,n);

    uint64_t qHalf = (q >> 1);

    // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 -> {1,0}, -1 -> {0,1}
#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i){
    	int64_t s = LWEsk->GetElement()[i].ConvertToInt();
    	if (s > (int64_t)qHalf)
    		s = s - q;
    	switch(s)
    	{
    	case 0:
        	(*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        	(*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        	break;
    	case 1:
        	(*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 1));
        	(*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        	break;
    	case -1:
         	(*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        	(*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 1));
        	break;
    	default:
    		std::string errMsg = "ERROR: only ternary secret key distributions are supported."; \
    		PALISADE_THROW(not_implemented_error, errMsg);
    	}
    }

    return ek;

}

void RingGSWAccumulatorScheme::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params,
		const std::vector<NativePoly> &input, std::vector<NativePoly> *output) const {

	uint32_t N = params->GetLWEParams()->GetN();
	uint32_t digitsG = params->GetDigitsG();
	NativeInteger Q = params->GetLWEParams()->GetQ();
	int64_t baseG = NativeInteger(params->GetBaseG()).ConvertToInt();

	NativeInteger QHalf = Q>>1;
	int64_t d = 0;

	int64_t gBits = (int64_t)std::log2(baseG);
	int64_t gBits64 = 64 - gBits;

	// Signed digit decomposition
	for (uint32_t j = 0; j < 2; j++) {
		for (uint32_t k = 0; k < N; k++) {
			NativeInteger t = input[j][k];
			if (t < QHalf)
				d += t.ConvertToInt();
			else
				d += (int64_t)t.ConvertToInt() - (int64_t)Q.ConvertToInt();

			for (uint32_t l = 0; l < digitsG; l++) {

				// remainder is signed
				int64_t r = d << gBits64;
				r>>= gBits64;

				d -= r;
				d >>= gBits;

				if (r >= 0)
					(*output)[j+2*l][k] += NativeInteger(r);
				else
					(*output)[j+2*l][k] += NativeInteger((int64_t)r + (int64_t)Q.ConvertToInt());

			}
		}
	}
}

// AP Accumulation as described in "Bootstrapping in FHEW-like Cryptosystems"
void RingGSWAccumulatorScheme::AddToACCAP(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWCiphertext &input,
		std::shared_ptr<RingGSWCiphertext> acc) const {

	uint32_t digitsG2 = params->GetDigitsG2();
	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

	std::vector<NativePoly> ct = acc->GetElements()[0];
	std::vector<NativePoly> dct(digitsG2);

	// initialize dct to zeros
	for(uint32_t i = 0; i < digitsG2; i++)
		dct[i] = NativePoly(polyParams,COEFFICIENT,true);

	// calls 2 NTTs
	for (uint32_t i = 0; i < 2; i++)
		ct[i].SetFormat(COEFFICIENT);

	SignedDigitDecompose(params,ct,&dct);

	// calls digitsG2 NTTs
	for (uint32_t j = 0; j < digitsG2; j++)
		dct[j].SetFormat(EVALUATION);

	// acc = dct * input (matrix product);
	// uses in-place * operators for the last call to dct[i] to gain performance improvement
	for (uint32_t j = 0; j < 2; j++) {
		(*acc)[0][j].SetValuesToZero();
		for (uint32_t l = 0; l < digitsG2; l++) {
			if (j < 1)
				(*acc)[0][j] += dct[l]*input[l][j];
			else
				(*acc)[0][j] += (dct[l]*=input[l][j]);
		}
	}

}

// GINX Accumulation as described in "Bootstrapping in FHEW-like Cryptosystems"
void RingGSWAccumulatorScheme::AddToACCGINX(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWCiphertext &input, const NativeInteger& a,
		std::shared_ptr<RingGSWCiphertext> acc) const {

	uint32_t N = params->GetLWEParams()->GetN();
	uint32_t digitsG2 = params->GetDigitsG2();
	int64_t q = params->GetLWEParams()->Getq().ConvertToInt();
	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

	std::vector<NativePoly> ct = acc->GetElements()[0];
	std::vector<NativePoly> dct(digitsG2);

	// initialize dct to zeros
	for(uint32_t i = 0; i < digitsG2; i++)
		dct[i] = NativePoly(polyParams,COEFFICIENT,true);

	// calls 2 NTTs
	for (uint32_t i = 0; i < 2; i++)
		ct[i].SetFormat(COEFFICIENT);

	SignedDigitDecompose(params,ct,&dct);

	for (uint32_t j = 0; j < digitsG2; j++)
		dct[j].SetFormat(EVALUATION);

	uint64_t mm = a.ConvertToInt() * (2*N/q);
	const NativePoly& monomial = params->GetMonomial(mm);

	// acc = dct * input (matrix product);
	// uses in-place * operators for the last call to dct[i] to gain performance improvement
	for (uint32_t j = 0; j < 2; j++) {
		NativePoly temp1 = (j < 1) ? dct[0]*input[0][j] : (dct[0]*=input[0][j]);
		for (uint32_t l = 1; l < digitsG2; l++) {
			if (j < 1)
				temp1 += dct[l]*input[l][j];
			else
				temp1 += (dct[l]*=input[l][j]);
		}
		(*acc)[0][j] += (temp1*=monomial);
	}

}

// Full evaluation as described in "Bootstrapping in FHEW-like Cryptosystems"
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::EvalBinGate(const std::shared_ptr<RingGSWCryptoParams> params,
			const BINGATE gate, const RingGSWEvalKey& EK, const std::shared_ptr<const LWECiphertextImpl> ct1,
			const std::shared_ptr<const LWECiphertextImpl> ct2, const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {

	NativeInteger q = params->GetLWEParams()->Getq();
	NativeInteger Q = params->GetLWEParams()->GetQ();
	uint32_t n = params->GetLWEParams()->Getn();
	uint32_t N = params->GetLWEParams()->GetN();
	uint32_t baseR = params->GetBaseR();
	std::vector<NativeInteger> digitsR = params->GetDigitsR();
	const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

	if (ct1 == ct2)	{
		std::string errMsg = "ERROR: Please only use independent ciphertexts as inputs."; \
		PALISADE_THROW(config_error, errMsg);
	}

	NativeVector a(n,q);
	NativeInteger b;

	// the additive homomorphic operation for XOR/NXOR is different from the other gates
	// we compute 2*(ct1 - ct2) mod 4
	// for XOR, me map 1,2 -> 1 and 3,0 -> 0
	if ((gate == XOR) || (gate == XNOR)) {
		a = ct1->GetA() - ct2->GetA();
		a += a;
		b = ct1->GetB().ModSubFast(ct2->GetB(),q);
		b.ModAddFastEq(b,q);
	} // for all other gates, we simply compute (ct1 + ct2) mod 4
	// for AND: 0,1 -> 0 and 2,3 -> 1
	// for OR: 1,2 -> 1 and 3,0 -> 0
	else {
		a = ct1->GetA() + ct2->GetA();
		b = ct1->GetB().ModAddFast(ct2->GetB(),q);
	}

	// Specifies the range [q1,q2) that will be used for mapping
	uint32_t qHalf = q.ConvertToInt()>>1;
	NativeInteger q1 = params->GetGateConst()[gate];
	NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf),q);

	// depending on whether the value is the range, it will be set
	// to either Q/8 or -Q/8 to match binary arithmetic
	NativeInteger Q8 = Q/NativeInteger(8)+1;
	NativeInteger Q8Neg = Q - Q8;

	NativeVector m(params->GetLWEParams()->GetN(),params->GetLWEParams()->GetQ());
	// Since 2*N * q, we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to Z_Q[x]/(X^N+1)
	uint32_t factor = (2*N/q.ConvertToInt());

	for(uint32_t j = 0; j < qHalf; j++ ) {
		NativeInteger temp = b.ModSub(j,q);
		if (q1 < q2)
			m[j*factor] = ((temp >= q1) && (temp < q2)) ? Q8Neg : Q8;
		else
			m[j*factor] = ((temp >= q2) && (temp < q1)) ? Q8 : Q8Neg;
	}

	std::vector<NativePoly> res(2);
	res[0] = NativePoly(polyParams,EVALUATION,true); // no need to do NTT as all coefficients of this poly are zero
	res[1] = NativePoly(polyParams,COEFFICIENT,false);
	res[1].SetValues(m,COEFFICIENT);
	res[1].SetFormat(EVALUATION);

	// main accumulation computation
	// the following loop is the bottleneck of bootstrapping/binary gate evaluation
	std::shared_ptr<RingGSWCiphertext> acc = std::make_shared<RingGSWCiphertext>(1,2);
	(*acc)[0] = std::move(res);

	if (params->GetMethod() == AP) {
		for (uint32_t i = 0; i < n; i++) {
			NativeInteger aI = q.ModSub(a[i],q);
			for (uint32_t k = 0; k < digitsR.size(); k++, aI /= NativeInteger(baseR)) {
				uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
				if (a0)
					this->AddToACCAP(params,(*EK.BSkey)[i][a0][k],acc);
			}
		}
	}
	else { // if GINX
		for (uint32_t i = 0; i < n; i++) {
			this->AddToACCGINX(params,(*EK.BSkey)[0][0][i],q.ModSub(a[i],q),acc); // handles -a*E(1)
			this->AddToACCGINX(params,(*EK.BSkey)[0][1][i],a[i],acc); // handles -a*E(-1) = a*E(1)
		}
	}

	NativeInteger bNew;
	NativeVector aNew(N,Q);

	// the accumulator result is encrypted w.r.t. the transposed secret key
	// we can transpose "a" to get an encryption under the original secret key
	NativePoly temp = (*acc)[0][0];
	temp = temp.Transpose();
	temp.SetFormat(COEFFICIENT);
	aNew = temp.GetValues();

	temp = (*acc)[0][1];
	temp.SetFormat(COEFFICIENT);
	// we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
	bNew = Q8.ModAddFast(temp[0],Q);

	std::shared_ptr<const LWECiphertextImpl> eQN = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(aNew),std::move(bNew)));

	// Key switching
	const std::shared_ptr<const LWECiphertextImpl> eQ = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

	// Modulus switching
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


