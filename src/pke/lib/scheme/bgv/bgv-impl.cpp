/*
 * @file bgv-impl.cpp - template instantiations and methods for the BGV scheme
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

#include "cryptocontext.h"
#include "bgv.cpp"

namespace lbcrypto {

template class LPCryptoParametersBGV<Poly>;
template class LPPublicKeyEncryptionSchemeBGV<Poly>;
template class LPAlgorithmBGV<Poly>;
template class LPAlgorithmMultipartyBGV<Poly>;
template class LPAlgorithmSHEBGV<Poly>;

template class LPCryptoParametersBGV<NativePoly>;
template class LPPublicKeyEncryptionSchemeBGV<NativePoly>;
template class LPAlgorithmBGV<NativePoly>;
template class LPAlgorithmMultipartyBGV<NativePoly>;
template class LPAlgorithmSHEBGV<NativePoly>;

template class LPCryptoParametersBGV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBGV<DCRTPoly>;
template class LPAlgorithmBGV<DCRTPoly>;
template class LPAlgorithmMultipartyBGV<DCRTPoly>;
template class LPAlgorithmSHEBGV<DCRTPoly>;

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBGV<DCRTPoly>::ReKeyGen(const LPPublicKey<DCRTPoly> newPK,
	const LPPrivateKey<DCRTPoly> origPrivateKey) const
{
	// Get crypto context of new public key.
	auto cc = newPK->GetCryptoContext();

	// Create an evaluation key that will contain all the re-encryption key elements.
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	// Get crypto and elements parameters
	const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(newPK->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

	// Get parameters needed for PRE key gen
	// r = relinWindow
	usint relinWin = cryptoParamsLWE->GetRelinWindow();
	// nBits = log2(q), where q: ciphertext modulus
	usint nBits = elementParams->GetModulus().GetLengthForBase(2);

	// K = log2(q)/r, i.e., number of digits in PRE decomposition
	usint K = 1;
	if (relinWin > 0) {
		K = nBits / relinWin;
		if (nBits % relinWin > 0)
			K++;
	}

	DCRTPoly s = origPrivateKey->GetPrivateElement();

	std::vector<DCRTPoly> evalKeyElementsA(K);
	std::vector<DCRTPoly> evalKeyElementsB(K);

	// The re-encryption key is K ciphertexts, one for each -s(2^r)^i
	for (usint i=0; i<K; i++) {
		int numTowers = s.GetAllElements().size();
		BigInteger bb = BigInteger(1) << i*relinWin;
		vector<NativeInteger> b(numTowers);

		for (int j=0; j<numTowers; j++) {
			auto mod = s.ElementAtIndex(j).GetModulus();
			auto bbmod = bb.Mod(mod);
			b[j] = bbmod.ConvertToInt();
		}

		const auto p = cryptoParamsLWE->GetPlaintextModulus();
		const DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

		DCRTPoly::TugType tug;

		s.SetFormat(Format::EVALUATION);

		std::vector<DCRTPoly> cVector;

		const DCRTPoly &pk1 = newPK->GetPublicElements().at(0);
		const DCRTPoly &pk0 = newPK->GetPublicElements().at(1);

		DCRTPoly v;

		if (cryptoParamsLWE->GetMode() == RLWE)
			v = DCRTPoly(dgg, elementParams, Format::EVALUATION);
		else
			v = DCRTPoly(tug, elementParams, Format::EVALUATION);

		DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
		DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

		DCRTPoly c0(pk0*v + p*e0 - s.Times(b));

		DCRTPoly c1(pk1*v + p*e1);

		evalKeyElementsA[i] = c1;
		evalKeyElementsB[i] = c0;
	}

	ek->SetAVector(std::move(evalKeyElementsA));
	ek->SetBVector(std::move(evalKeyElementsB));

	return std::move(ek);
}

}
