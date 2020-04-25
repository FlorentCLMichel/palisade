/*
* @file ckks.cpp - CKKS scheme implementation.
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

#ifndef LBCRYPTO_CRYPTO_CKKS_C
#define LBCRYPTO_CRYPTO_CKKS_C

#include "scheme/ckks/ckks.h"

namespace lbcrypto {

	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmCKKS<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
	{

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(cc->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::DugType dug;

		typename Element::TugType tug;

		//Generate the element "a" of the public key
		Element a(dug, elementParams, Format::EVALUATION);

		//Generate the secret key
		Element s;

		//Done in two steps not to use a random polynomial from a pre-computed pool
		//Supports discrete Gaussian (RLWE), ternary uniform distribution (OPTIMIZED), and sparse distribution (SPARSE) cases
		switch(cryptoParams->GetMode()){
		case RLWE:
			s = Element(dgg, elementParams, Format::COEFFICIENT);
			break;
		case OPTIMIZED:
			s = Element(tug, elementParams, Format::COEFFICIENT);
			break;
		case SPARSE:
			s = Element(tug, elementParams, Format::COEFFICIENT,64);
			break;
		default:
			break;
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = e - a*s;

		kp.secretKey->SetPrivateElement(std::move(s));

		kp.publicKey->SetPublicElementAtIndex(0, std::move(b));

		kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

		return kp;
	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::KeySwitchGHSGen(const LPPrivateKey<DCRTPoly> oldKey,
			const LPPrivateKey<DCRTPoly> newPrivateKey) const  {

		std::string errMsg = "LPAlgorithmSHECKKS::KeySwitchGHSGen is only supported for DCRTPoly.";
		PALISADE_THROW(not_implemented_error, errMsg);
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::KeySwitchGHS(const LPEvalKey<Element> keySwitchHint,
		ConstCiphertext<Element> cipherText) const  {

		std::string errMsg = "LPAlgorithmSHECKKS::KeySwitchGHS is only supported for DCRTPoly.";
		PALISADE_THROW(not_implemented_error, errMsg);
	}

	template <class Element>
	vector<shared_ptr<ConstCiphertext<Element>>> LPAlgorithmSHECKKS<Element>::AutomaticLevelReduce(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const {

		std::string errMsg = "LPAlgorithmSHECKKS::AutomaticLevelReduce is only supported for DCRTPoly.";
		PALISADE_THROW(not_implemented_error, errMsg);
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAddCore(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{
		if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
			PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
		}


		if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
			PALISADE_THROW(config_error, "EvalAddCore cannot add ciphertexts with different number of CRT components.");
		}

		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		size_t c1Size = c1.size();
		size_t c2Size = c2.size();
		size_t cSmallSize, cLargeSize;
		if (c1Size < c2Size)
		{
			cSmallSize = c1Size;
			cLargeSize = c2Size;
		}
		else
		{
			cSmallSize = c2Size;
			cLargeSize = c1Size;
		}

		std::vector<Element> cNew;

		for(size_t i = 0; i < cSmallSize; i++) {
			cNew.push_back(std::move(c1[i] + c2[i]));
		}
		for(size_t i = cSmallSize; i < cLargeSize; i++) {
			if (c1Size < c2Size)
				cNew.push_back(std::move(c2[i]));
			else
				cNew.push_back(std::move(c1[i]));
		}

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext1->GetDepth());
		newCiphertext->SetScalingFactor(ciphertext1->GetScalingFactor());
		newCiphertext->SetLevel(ciphertext1->GetLevel());

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSubCore(ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const {

		if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
			PALISADE_THROW(config_error, "LPAlgorithmSHECKKS<Element>::EvalSubCore - Depths of two ciphertexts do not match.");
		}

		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		size_t c1Size = c1.size();
		size_t c2Size = c2.size();
		size_t cSmallSize, cLargeSize;
		if (c1Size < c2Size)
		{
			cSmallSize = c1Size;
			cLargeSize = c2Size;
		}
		else
		{
			cSmallSize = c2Size;
			cLargeSize = c1Size;
		}

		std::vector<Element> cNew;

		for(size_t i = 0; i < cSmallSize; i++) {
			cNew.push_back(std::move(c1[i] - c2[i]));
		}
		for(size_t i = cSmallSize; i < cLargeSize; i++) {
			if (c1Size < c2Size)
				cNew.push_back(std::move(c2[i].Negate()));
			else
				cNew.push_back(std::move(c1[i]));
		}

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext1->GetDepth());
		newCiphertext->SetScalingFactor(ciphertext1->GetScalingFactor());
		newCiphertext->SetLevel(ciphertext1->GetLevel());

		return newCiphertext;
	}


	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMultCore(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			PALISADE_THROW(not_available_error, "EvalMult cannot multiply in COEFFICIENT domain.");
		}

		if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
			PALISADE_THROW(config_error, "EvalMultCore cannot multiply ciphertexts with different number of CRT components.");
		}

		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		size_t cResultSize = c1.size() + c2.size() - 1;

		std::vector<Element> c(cResultSize);

		bool *isFirstAdd = new bool[cResultSize];
		std::fill_n(isFirstAdd, cResultSize, true);

		for(size_t i=0; i<c1.size(); i++){
			for(size_t j=0; j<c2.size(); j++){

				if(isFirstAdd[i+j] == true){
					c[i+j] = c1[i] * c2[j];
					isFirstAdd[i+j] = false;
				}
				else{
					c[i+j] += c1[i] * c2[j];
				}
			}
		}

		delete []isFirstAdd;

		newCiphertext->SetElements(std::move(c));

		newCiphertext->SetDepth(ciphertext1->GetDepth() + ciphertext2->GetDepth());
		newCiphertext->SetScalingFactor(ciphertext1->GetScalingFactor() * ciphertext2->GetScalingFactor());
		newCiphertext->SetLevel(ciphertext1->GetLevel());

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAdd(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{
		return LPAlgorithmSHECKKS<Element>::EvalAddCore(ciphertext1, ciphertext2);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAdd(
		ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		plaintext->SetFormat(EVALUATION);
		const Element& c2 = plaintext->GetElement<Element>();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + c2));

		for (size_t i = 1; i < c1.size(); i++)
			cNew.push_back(std::move(c1[i]));

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext->GetDepth());

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAdd(
		ConstCiphertext<Element> ciphertext,
		double constant) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(ciphertext->GetCryptoParameters());
		const auto p = cryptoParams->GetPlaintextModulus();

		int32_t depth = ciphertext->GetDepth();

		// FIXME EvalAdd does not work for depth > 1 because of
		// overflow. We need BigIntegers to handle this case.
		// For now, we address this issue in the DCRTPoly
		// implementation of EvalAdd, by doing the operation
		// in CRT.
		if (depth > 2)
			PALISADE_THROW(not_implemented_error, "LPAlgorithmSHECKKS<Element>::EvalAdd is supported only for DCRTPoly.");

		double powP = pow(2,p*depth);

		typename Element::Integer scaledConstant = std::llround(constant*powP);

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + scaledConstant));

		for (size_t i = 1; i < c1.size(); i++)
			cNew.push_back(std::move(c1[i]));

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext->GetDepth());

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const {

		return LPAlgorithmSHECKKS<Element>::EvalSubCore(ciphertext1, ciphertext2);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const {

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		plaintext->SetFormat(EVALUATION);
		const Element& c2 = plaintext->GetElement<Element>();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - c2));

		for (size_t i = 1; i < c1.size(); i++)
			cNew.push_back(std::move(c1[i]));

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext->GetDepth());

		return newCiphertext;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(
		ConstCiphertext<Element> ciphertext,
		double constant) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(ciphertext->GetCryptoParameters());
		const auto p = cryptoParams->GetPlaintextModulus();

		int32_t depth = ciphertext->GetDepth();

		// FIXME EvalSub does not work for depth > 1 because of
		// overflow. We need BigIntegers to handle this case.
		// For now, we address this issue in the DCRTPoly
		// implementation of EvalSub, by doing the operation
		// in CRT.
		if (depth > 2)
			PALISADE_THROW(not_implemented_error, "LPAlgorithmSHECKKS<Element>::EvalSub is supported only for DCRTPoly.");

		double powP = pow(2,p*depth);

		typename Element::Integer scaledConstant = std::llround(constant*powP);

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - scaledConstant));

		for (size_t i = 1; i < c1.size(); i++)
			cNew.push_back(std::move(c1[i]));

		newCiphertext->SetElements(std::move(cNew));

		newCiphertext->SetDepth(ciphertext->GetDepth());

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{
		return LPAlgorithmSHECKKS<Element>::EvalMultCore(ciphertext1, ciphertext2);
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
		ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const
	{
		PALISADE_THROW(not_implemented_error, "EvalMult is onlly implemented in DCRTPoly.");
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
		ConstCiphertext<Element> ciphertext,
		double constant) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(ciphertext->GetCryptoParameters());

		if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
			const auto p = cryptoParams->GetPlaintextModulus();
			const std::vector<Element> &c1 = ciphertext->GetElements();

			double powP = pow(2,p);

			int64_t scaledConstant = std::llround(constant*powP);

			std::vector<Element> cNew;

			for (size_t i = 0; i < c1.size(); i++)
				cNew.push_back(std::move(c1[i] * scaledConstant));

			newCiphertext->SetElements(std::move(cNew));

			newCiphertext->SetDepth(ciphertext->GetDepth()+ciphertext->GetDepth());
			newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor() * powP);
			newCiphertext->SetLevel(ciphertext->GetLevel());

			return newCiphertext;
		} else { // EXACTRESCALING
			Ciphertext<Element> c;
			// First, rescale to bring ciphertext to depth 1
			if (ciphertext->GetDepth() > 2) {
				PALISADE_THROW(not_available_error, "Exact rescaling works for ciphertexts of depth 1 and 2 only.");
			}

			double powP = ciphertext->GetScalingFactor();
			uint32_t depth = ciphertext->GetDepth();
			uint32_t level = ciphertext->GetLevel();
			double scalingFactor = ciphertext->GetScalingFactor();

			if (ciphertext->GetDepth() == 2) {
				CryptoContext<Element> cc = ciphertext->GetCryptoContext();
				c = cc->ModReduce(ciphertext);

				powP = c->GetScalingFactor();
				depth = c->GetDepth();
				level = c->GetLevel();
				scalingFactor = c->GetScalingFactor();
			}

			const std::vector<Element> &c1 =
					(ciphertext->GetDepth() == 2) ? c->GetElements() : ciphertext->GetElements();

			int64_t scaledConstant = std::llround(constant*powP);

			std::vector<Element> cNew;

			for (size_t i = 0; i < c1.size(); i++)
				cNew.push_back(std::move(c1[i] * scaledConstant));

			newCiphertext->SetElements(std::move(cNew));

			// For EXACTRESCALING, depth always expected to be 2
			newCiphertext->SetDepth( 2 * depth );
			// For EXACTRESCALING, scaling factor always expected to be squared
			newCiphertext->SetScalingFactor( scalingFactor * scalingFactor );
			// For EXACTRESCALING, level will change with ModReduce above, but not with multiplication.
			newCiphertext->SetLevel( level );

			return newCiphertext;
		}

	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey,
		const LPPrivateKey<Element> newPrivateKey) const {

		LPEvalKeyRelin<Element> ek(new LPEvalKeyRelinImpl<Element>(newPrivateKey->GetCryptoContext()));

		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(newPrivateKey->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
		const Element &s = newPrivateKey->GetPrivateElement();

		const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
		typename Element::DugType dug;

		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		std::vector<Element> evalKeyElements(originalPrivateKey->GetPrivateElement().PowersOfBase(relinWindow));
		std::vector<Element> evalKeyElementsGenerated;

		for (usint i = 0; i < (evalKeyElements.size()); i++)
		{
			// Generate a_i vectors
			Element a(dug, elementParams, Format::EVALUATION);
			evalKeyElementsGenerated.push_back(a);

			// Generate a_i * s + e - PowerOfBase(s^2)
			Element e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements.at(i) -= (a*s + e);
		}

		ek->SetAVector(std::move(evalKeyElementsGenerated));
		ek->SetBVector(std::move(evalKeyElements));

		return ek;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::KeySwitch(const LPEvalKey<Element> ek,
		ConstCiphertext<Element> cipherText) const
	{

		Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(ek->GetCryptoParameters());
		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		LPEvalKeyRelin<Element> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek);

		const std::vector<Element> &c = cipherText->GetElements();

		const std::vector<Element> &b = evalKey->GetBVector();
		const std::vector<Element> &a = evalKey->GetAVector();

		std::vector<Element> digitsC2;

		Element ct0(c[0]);

		//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
		if (c.size() > 2)
			ct0.SetFormat(EVALUATION);

		Element ct1;

		if (c.size() == 2) //case of PRE or automorphism
		{
			digitsC2 = c[1].BaseDecompose(relinWindow);
			ct1 = digitsC2[0] * a[0];
		}
		else //case of EvalMult
		{
			digitsC2 = c[2].BaseDecompose(relinWindow);
			ct1 = c[1];
			//Convert ct1 to evaluation representation
			ct1.SetFormat(EVALUATION);
			ct1 += digitsC2[0] * a[0];
		}

		ct0 += digitsC2[0] * b[0];

		for (usint i = 1; i < digitsC2.size(); ++i)
		{
			ct0 += digitsC2[i] * b[i];
			ct1 += digitsC2[i] * a[i];
		}

		newCiphertext->SetElements({ ct0, ct1 });

		newCiphertext->SetDepth(cipherText->GetDepth());

		return newCiphertext;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const {

		Ciphertext<Element> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		return this->KeySwitch(ek, newCiphertext);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMultMutable(Ciphertext<Element> &ciphertext1,
		Ciphertext<Element> &ciphertext2, const LPEvalKey<Element> ek) const {

		Ciphertext<Element> newCiphertext = this->EvalMultMutable(ciphertext1, ciphertext2);

		return this->KeySwitch(ek, newCiphertext);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalNegate(ConstCiphertext<Element> ciphertext) const {

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

		std::vector<Element> cNew;

		for (size_t i = 0; i < cipherTextElements.size(); i++)
			cNew.push_back(cipherTextElements[i].Negate());

		newCiphertext->SetElements(std::move(cNew));
		newCiphertext->SetDepth(ciphertext->GetDepth());
		newCiphertext->SetLevel(ciphertext->GetLevel());
		newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

		return newCiphertext;
	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const
	{

		LPPrivateKey<Element> originalPrivateKeySquared = LPPrivateKey<Element>(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));

		Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

		originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

		return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);

	}

	template <class Element>
	vector<LPEvalKey<Element>> LPAlgorithmSHECKKS<Element>::EvalMultKeysGen(
				const LPPrivateKey<Element> originalPrivateKey) const
	{

		const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(originalPrivateKey->GetCryptoParameters());

		LPPrivateKey<Element> originalPrivateKeyPowered = LPPrivateKey<Element>(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));

		vector<LPEvalKey<Element>> evalMultKeys;

		std::vector<Element> sPower(cryptoParamsLWE->GetMaxDepth());
		std::vector<LPEvalKey<Element>> ek(cryptoParamsLWE->GetMaxDepth());
		//Create powers of original key to be used in keyswitching as evaluation keys after they are encrypted.
		sPower[0] = originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement();
		for(size_t i=1; i<cryptoParamsLWE->GetMaxDepth()-1; i++)
			sPower[i] = sPower[i-1] * originalPrivateKey->GetPrivateElement();

		for(size_t i=0; i<cryptoParamsLWE->GetMaxDepth()-1; i++){
			originalPrivateKeyPowered->SetPrivateElement(std::move(sPower[i]));
			ek[i] = this->KeySwitchGen(originalPrivateKeyPowered, originalPrivateKey);
			evalMultKeys.push_back(ek[i]);
		}

		return evalMultKeys;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const
	{

		Ciphertext<Element> permutedCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c = ciphertext->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c[0].AutomorphismTransform(i)));

		cNew.push_back(std::move(c[1].AutomorphismTransform(i)));

		permutedCiphertext->SetElements(std::move(cNew));

		permutedCiphertext->SetDepth(ciphertext->GetDepth());
		permutedCiphertext->SetLevel(ciphertext->GetLevel());
		permutedCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

		return this->KeySwitch(evalKeys.find(i)->second, permutedCiphertext);

	}

	template <class Element>
	shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmSHECKKS<Element>::EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const
	{

		const Element &privateKeyElement = privateKey->GetPrivateElement();

		usint n = privateKeyElement.GetRingDimension();

		LPPrivateKey<Element> tempPrivateKey(new LPPrivateKeyImpl<Element>(privateKey->GetCryptoContext()));

		shared_ptr<std::map<usint, LPEvalKey<Element>>> evalKeys(new std::map<usint, LPEvalKey<Element>>());

		if (indexList.size() > n - 1)
			PALISADE_THROW(math_error, "size exceeds the ring dimension");
		else {

			for (usint i = 0; i < indexList.size(); i++)
			{
				Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(indexList[i]);

				tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

				(*evalKeys)[indexList[i]] = this->KeySwitchGen(tempPrivateKey, privateKey);

			}

		}

		return evalKeys;

	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmPRECKKS<Element>::ReKeyGen(const LPPublicKey<Element> newPK,
		const LPPrivateKey<Element> origPrivateKey) const
	{
		// Get crypto context of new public key.
		auto cc = newPK->GetCryptoContext();

		// Create an evaluation key that will contain all the re-encryption key elements.
		LPEvalKeyRelin<Element> ek(new LPEvalKeyRelinImpl<Element>(cc));

		// Get crypto and elements parameters
		const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(newPK->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();

		const shared_ptr<LPCryptoParametersCKKS<Element>> BFVcryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(newPK->GetCryptoParameters());

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

		Element s = origPrivateKey->GetPrivateElement();

		std::vector<Element> evalKeyElementsA(K);
		std::vector<Element> evalKeyElementsB(K);

		for (usint i=0; i<K; i++) {
			NativeInteger b = NativeInteger(1) << i*relinWin;

			s.SetFormat(Format::EVALUATION);

			const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
			typename Element::TugType tug;

			const Element &p0 = newPK->GetPublicElements().at(0);
			const Element &p1 = newPK->GetPublicElements().at(1);

			Element u;

			if (cryptoParamsLWE->GetMode() == RLWE)
				u = Element(dgg, elementParams, Format::EVALUATION);
			else
				u = Element(tug, elementParams, Format::EVALUATION);

			Element e1(dgg, elementParams, Format::EVALUATION);
			Element e2(dgg, elementParams, Format::EVALUATION);

			Element c0(elementParams);
			Element c1(elementParams);

			c0 = p0*u + e1 + s*b;

			c1 = p1*u + e2;

			evalKeyElementsA[i] = c0;
			evalKeyElementsB[i] = c1;
		}

		ek->SetAVector(std::move(evalKeyElementsA));
		ek->SetBVector(std::move(evalKeyElementsB));

		return std::move(ek);
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmPRECKKS<Element>::ReEncrypt(const LPEvalKey<Element> EK,
		ConstCiphertext<Element> ciphertext,
		const LPPublicKey<Element> publicKey) const
	{
		Ciphertext<Element> c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);

		if (publicKey == nullptr) { // Recipient PK is not provided - CPA-secure PRE
			return c;
		} else { // Recipient PK provided - HRA-secure PRE
			auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);

			if (publicKey == nullptr) { // Recipient PK is not provided - CPA-secure PRE
				return c;
			} else {
				// Recipient PK provided - HRA-secure PRE
				// To obtain HRA security, we a fresh encryption of zero to the result
				// with noise scaled by K (=log2(q)/relinWin).
				CryptoContext<Element> cc = publicKey->GetCryptoContext();

				// Creating the correct plaintext of zeroes, based on the
				// encoding type of the ciphertext.
				PlaintextEncodings encType = c->GetEncodingType();

				// Encrypting with noise scaled by K
				const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoPars =
						std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(publicKey->GetCryptoParameters());
				const shared_ptr<typename Element::Params> elementParams = cryptoPars->GetElementParams();

				usint relinWin = cryptoPars->GetRelinWindow();
				usint nBits = elementParams->GetModulus().GetLengthForBase(2);
				// K = log2(q)/r, i.e., number of digits in PRE decomposition
				usint K = 1;
				if (relinWin > 0) {
					K = nBits / relinWin;
					if (nBits % relinWin > 0)
						K++;
				}

				Ciphertext<Element> zeroCiphertext(new CiphertextImpl<Element>(publicKey));
				zeroCiphertext->SetEncodingType(encType);

				const typename Element::DggType &dgg = cryptoPars->GetDiscreteGaussianGenerator();
				typename Element::TugType tug;
				// Scaling the distribution standard deviation by K for HRA-security
				auto stdDev = cryptoPars->GetDistributionParameter();
				typename Element::DggType dgg_err(K*stdDev);

				const Element &p0 = publicKey->GetPublicElements().at(0);
				const Element &p1 = publicKey->GetPublicElements().at(1);

				Element u;

				if (cryptoPars->GetMode() == RLWE)
					u = Element(dgg, elementParams, Format::EVALUATION);
				else
					u = Element(tug, elementParams, Format::EVALUATION);

				Element e1(dgg_err, elementParams, Format::EVALUATION);
				Element e2(dgg_err, elementParams, Format::EVALUATION);

				Element c0(elementParams);
				Element c1(elementParams);

				c0 = p0*u + e1;
				c1 = p1*u + e2;

				zeroCiphertext->SetElements({ c0, c1 });

				c->SetKeyTag(zeroCiphertext->GetKeyTag());

				// Add the encryption of zeroes to the re-encrypted ciphertext
				// and return the result.
				return cc->EvalAdd(c, zeroCiphertext);
			}
		}
	}

	template <class Element>
	Ciphertext<Element> LPLeveledSHEAlgorithmCKKS<Element>::ModReduce(ConstCiphertext<Element> cipherText) const {

		std::string errMsg = "LPAlgorithmSHECKKS::ModReduce is only supported for DCRTPoly.";
		PALISADE_THROW(not_implemented_error, errMsg);

	}

	template <class Element>
	Ciphertext<Element> LPLeveledSHEAlgorithmCKKS<Element>::LevelReduce(ConstCiphertext<Element> cipherText1,
			const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {

		std::string errMsg = "LPAlgorithmSHECKKS::LevelReduce is only supported for DCRTPoly.";
		PALISADE_THROW(not_implemented_error, errMsg);

	}

	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const vector<LPPrivateKey<Element>>& secretKeys,
		bool makeSparse)
	{

		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
							std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(cc->GetCryptoParameters());

		if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
			std::string errMsg =
					"MultipartyKeyGen - Multiparty HE is only supported when using BV key switching.";
			PALISADE_THROW(not_available_error, errMsg);
		}

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));
		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		//const auto p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		typename Element::DugType dug;
		typename Element::TugType tug;

		//Generate the element "a" of the public key
		Element a(dug, elementParams, Format::EVALUATION);
		//Generate the secret key
		Element s(elementParams, Format::EVALUATION, true);

		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		size_t numKeys = secretKeys.size();
		for( size_t i = 0; i < numKeys; i++ ) {
			LPPrivateKey<Element> sk1 = secretKeys[i];
			Element s1 = sk1->GetPrivateElement();
			s += s1;
		}
//		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = e - a*s;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

		return kp;
	}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const LPPublicKey<Element> pk1, bool makeSparse, bool pre)
	{
		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(pk1->GetCryptoParameters());

		if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
			std::string errMsg =
					"MultipartyKeyGen - Multiparty HE is only supported when using BV key switching.";
			PALISADE_THROW(not_available_error, errMsg);
		}

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));
		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		//const auto p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		typename Element::DugType dug;
		typename Element::TugType tug;

		//Generate the element "a" of the public key
		Element a = pk1->GetPublicElements()[1];
		//Generate the secret key
		Element s;

		//Supports discrete Gaussian (RLWE), ternary uniform distribution (OPTIMIZED), and sparse distribution (SPARSE) cases
		switch(cryptoParams->GetMode()){
		case RLWE:
			s = Element(dgg, elementParams, Format::COEFFICIENT);
			break;
		case OPTIMIZED:
			s = Element(tug, elementParams, Format::COEFFICIENT);
			break;
		case SPARSE:
			s = Element(tug, elementParams, Format::COEFFICIENT,64);
			break;
		default:
			break;
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();
		//a.SwitchFormat();

		Element b;

		// When PRE is not used, a joint key is computed
		if (!pre)
			b = e - a*s + pk1->GetPublicElements()[0];
		else
			b = e - a*s;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

		return kp;
	}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext) const
{
		const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(privateKey->GetCryptoParameters());

		if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
			std::string errMsg =
					"MultipartyDecryptLead - Multiparty HE is only supported when using BV key switching.";
			PALISADE_THROW(not_available_error, errMsg);
		}

		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const std::vector<Element> &c = ciphertext->GetElements();
		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] + s*c[1];

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
		newCiphertext->SetElements({ b });

		return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext) const
{
	const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(privateKey->GetCryptoParameters());

	if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
		std::string errMsg =
				"MultipartyDecryptMain - Multiparty HE is only supported when using BV key switching.";
		PALISADE_THROW(not_available_error, errMsg);
	}

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = s*c[1];

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetElements({ b });

	return newCiphertext;
}


template <class Element>
DecryptResult LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
		NativePoly *plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(ciphertextVec[0]->GetCryptoParameters());

	if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
		std::string errMsg =
				"MultipartyDecryptFusion - Multiparty HE is only supported when using BV key switching.";
		PALISADE_THROW(not_available_error, errMsg);
	}

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	//const auto p = cryptoParams->GetPlaintextModulus();

	const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	Element b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	b.SwitchFormat();	

	*plaintext = b.ToNativePoly();

	return DecryptResult(plaintext->GetLength());

}


template<class Element>
shared_ptr<vector<Element>> LPAlgorithmSHECKKS<Element>::EvalFastRotationPrecomputeBV(
		ConstCiphertext<Element> cipherText
		) const {

	std::string errMsg = "CKKS EvalFastRotationPrecomputeBV supports only DCRTPoly."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<class Element>
shared_ptr<vector<Element>> LPAlgorithmSHECKKS<Element>::EvalFastRotationPrecomputeGHS(
		ConstCiphertext<Element> cipherText
		) const {

	std::string errMsg = "CKKS EvalFastRotationPrecomputeGHS supports only DCRTPoly."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalFastRotationBV(
		ConstCiphertext<Element> cipherText,
		const usint index,
		const usint m,
		const shared_ptr<vector<Element>> digits,
		LPEvalKey<DCRTPoly> evalKey
		) const {

	std::string errMsg = "CKKS EvalFastRotationBV supports only DCRTPoly."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalFastRotationGHS(
		ConstCiphertext<Element> cipherText,
		const usint index,
		const usint m,
		const shared_ptr<vector<Element>> expandedCiphertext,
		LPEvalKey<DCRTPoly> evalKey
		) const {

	std::string errMsg = "CKKS EvalFastRotationGHS supports only DCRTPoly."; \
	PALISADE_THROW(not_available_error, errMsg);
}

	// Enable for LPPublicKeyEncryptionSchemeLTV
	template <class Element>
	void LPPublicKeyEncryptionSchemeCKKS<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset(new LPAlgorithmCKKS<Element>());
			break;
		case PRE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset(new LPAlgorithmCKKS<Element>());
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE.reset(new LPAlgorithmPRECKKS<Element>());
			break;
		case SHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset(new LPAlgorithmCKKS<Element>());
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE.reset(new LPAlgorithmSHECKKS<Element>());
			break;
		case LEVELEDSHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset(new LPAlgorithmCKKS<Element>());
			if (this->m_algorithmLeveledSHE == NULL)
				this->m_algorithmLeveledSHE.reset(new LPLeveledSHEAlgorithmCKKS<Element>());
			break;
		case MULTIPARTY:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset(new LPAlgorithmCKKS<Element>());
			if (this->m_algorithmMultiparty == NULL)
				this->m_algorithmMultiparty.reset(new LPAlgorithmMultipartyCKKS<Element>());
			break;
		case FHE:
			PALISADE_THROW(not_implemented_error, "FHE feature not supported for CKKS scheme");
		case ADVANCEDSHE:
			PALISADE_THROW(not_implemented_error, "ADVANCEDSHE feature not supported for CKKS scheme");
		case ADVANCEDMP:
			PALISADE_THROW(not_implemented_error, "ADVANCEDMP feature not supported for CKKS scheme");
		}
	}

}  // namespace lbcrypto ends

#endif
