/*
* @file bgv.cpp - BGV scheme implementation.
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
This code implements the Brakerski-Vaikuntanathan (BGV) homomorphic encryption scheme.
The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf (or alternative Internet source:
http://dx.doi.org/10.1007/978-3-642-22792-9_29).
The levelled Homomorphic scheme is described in
"Fully Homomorphic Encryption without Bootstrapping", Internet Source: https://eprint.iacr.org/2011/277.pdf .
Implementation details are provided in
"Homomorphic Evaluation of the AES Circuit" Internet source: https://eprint.iacr.org/2012/099.pdf .

{the link to the ACM TISSEC manuscript to be added}.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef LBCRYPTO_CRYPTO_BGV_C
#define LBCRYPTO_CRYPTO_BGV_C

#include "scheme/bgv/bgv.h"

namespace lbcrypto {

	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmBGV<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
	{

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Element>>(cc->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const auto p = cryptoParams->GetPlaintextModulus();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::DugType dug;

		typename Element::TugType tug;

		//Generate the element "a" of the public key
		Element a(dug, elementParams, Format::EVALUATION);

		//Generate the secret key
		Element s;

		//Done in two steps not to use a random polynomial from a pre-computed pool
		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE) {
			s = Element(dgg, elementParams, Format::COEFFICIENT);
		}
		else {
			s = Element(tug, elementParams, Format::COEFFICIENT);
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));

		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));

		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmBGV<Element>::Encrypt(const LPPublicKey<Element> publicKey,
		Element ptxt) const
	{
		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(publicKey->GetCryptoParameters());

		Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(publicKey));

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const auto p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::TugType tug;

		ptxt.SetFormat(Format::EVALUATION);

		std::vector<Element> cVector;

		const Element &a = publicKey->GetPublicElements().at(0);
		const Element &b = publicKey->GetPublicElements().at(1);

		Element v;

		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE)
			v = Element(dgg, elementParams, Format::EVALUATION);
		else
			v = Element(tug, elementParams, Format::EVALUATION);

		Element e0(dgg, elementParams, Format::EVALUATION);
		Element e1(dgg, elementParams, Format::EVALUATION);

		Element c0(b*v + p*e0 + ptxt);

		Element c1(a*v + p*e1);

		cVector.push_back(std::move(c0));

		cVector.push_back(std::move(c1));

		ciphertext->SetElements(std::move(cVector));


		return ciphertext;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmBGV<Element>::Encrypt(const LPPrivateKey<Element> privateKey,
		Element ptxt) const
	{
		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(privateKey->GetCryptoParameters());

		Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(privateKey));

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const auto p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::DugType dug;

		ptxt.SwitchFormat();

		std::vector<Element> cVector;

		Element a(dug, elementParams, Format::EVALUATION);
		const Element &s = privateKey->GetPrivateElement();
		Element e(dgg, elementParams, Format::EVALUATION);

		Element c0(a*s + p*e + ptxt);
		Element c1(a);

		cVector.push_back(std::move(c0));
		cVector.push_back(std::move(c1));

		ciphertext->SetElements(std::move(cVector));

		return ciphertext;
	}

	template <class Element>
	DecryptResult LPAlgorithmBGV<Element>::Decrypt(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext,
		NativePoly *plaintext) const
	{
		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const auto p = cryptoParams->GetPlaintextModulus();
		const std::vector<Element> &c = ciphertext->GetElements();
		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] - s*c[1];

		b.SwitchFormat();

		*plaintext = b.DecryptionCRTInterpolate(p);

		return DecryptResult(plaintext->GetLength());
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalAdd(
			ConstCiphertext<Element> ciphertext1,
			ConstCiphertext<Element> ciphertext2) const
	{
		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + c2[0]));

		cNew.push_back(std::move(c1[1] + c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalAdd(
			ConstCiphertext<Element> ciphertext,
			ConstPlaintext plaintext) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		const Element& c2 = plaintext->GetElement<Element>();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + c2));

		cNew.push_back(std::move(c1[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalSub(ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const {

		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - c2[0]));

		cNew.push_back(std::move(c1[1] - c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalSub(ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const {

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		plaintext->SetFormat(EVALUATION);
		const Element& c2 = plaintext->GetElement<Element>();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - c2));

		cNew.push_back(std::move(c1[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalMult(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
	{

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			PALISADE_THROW(not_available_error, "EvalMult cannot multiply in COEFFICIENT domain.");
		}

		Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] * c2[0]));

		cNew.push_back(std::move(c1[0] * c2[1] + c1[1] * c2[0]));

		cNew.push_back(std::move((c1[1] * c2[1]).Negate()));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalMult(
		ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const
	{
		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c1 = ciphertext->GetElements();

		plaintext->SetFormat(EVALUATION);
		const Element& c2 = plaintext->GetElement<Element>();

		if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetElement<Element>().GetFormat() == Format::COEFFICIENT) {
			PALISADE_THROW(not_available_error, "EvalMult cannot multiply in COEFFICIENT domain.");
		}

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] * c2));

		cNew.push_back(std::move(c1[1] * c2));

		//cNew.push_back(std::move(0));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}


	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalMult(ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const {

		Ciphertext<Element> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		return this->KeySwitch(ek, newCiphertext);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalNegate(ConstCiphertext<Element> ciphertext) const {

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

		Element c0 = cipherTextElements[0].Negate();
		Element c1 = cipherTextElements[1].Negate();

		newCiphertext->SetElements({ c0, c1 });
		return newCiphertext;
	}


	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHEBGV<Element>::KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey) const {

		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(originalPrivateKey->GetCryptoParameters());

		const shared_ptr<typename Element::Params> originalKeyParams = cryptoParams->GetElementParams();

		auto p = cryptoParams->GetPlaintextModulus();

		LPEvalKey<Element> keySwitchHintRelin(new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

		//Getting a reference to the polynomials of new private key.
		const Element &sNew = newPrivateKey->GetPrivateElement();

		//Getting a reference to the polynomials of original private key.
		const Element &s = originalPrivateKey->GetPrivateElement();

		//Getting a refernce to discrete gaussian distribution generator.
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		//Getting a reference to discrete uniform generator.
		typename Element::DugType dug;

		//Relinearization window is used to calculate the base exponent.
		usint relinWindow = cryptoParams->GetRelinWindow();

		//Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
		std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

		//evalKeyElementsGenerated hold the generated noise distribution.
		std::vector<Element> evalKeyElementsGenerated;

		for (usint i = 0; i < (evalKeyElements.size()); i++)
		{
			// Generate a_i vectors
			Element a(dug, originalKeyParams, Format::EVALUATION);

			evalKeyElementsGenerated.push_back(a); //alpha's of i

												   // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
			Element e(dgg, originalKeyParams, Format::EVALUATION);

			evalKeyElements[i] = (a*sNew + p*e) - evalKeyElements[i];

		}

		keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

		keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

		return keySwitchHintRelin;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::KeySwitch(const LPEvalKey<Element> keySwitchHint, ConstCiphertext<Element> cipherText) const {

		Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(keySwitchHint->GetCryptoParameters());

		const LPEvalKeyRelin<Element> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(keySwitchHint);

		const std::vector<Element> &a = evalKey->GetAVector();
		const std::vector<Element> &b = evalKey->GetBVector();

		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		const std::vector<Element> &c = cipherText->GetElements();

		std::vector<Element> digitsC1;
		Element ct1;

		if (c.size() == 2) //case of automorphism
		{
			digitsC1 = c[1].BaseDecompose(relinWindow);
			ct1 = digitsC1[0] * a[0];
		}
		else //case of EvalMult
		{
			digitsC1 = c[2].BaseDecompose(relinWindow);
			ct1 = c[1] + digitsC1[0] * a[0];
		}

		Element ct0(c[0] + digitsC1[0] * b[0]);

		//Relinearization Step.
		for (usint i = 1; i < digitsC1.size(); ++i)
		{
			ct0 += digitsC1[i] * b[i];
			ct1 += digitsC1[i] * a[i];
		}

		std::vector<Element> ctVector;

		ctVector.push_back(std::move(ct0));

		ctVector.push_back(std::move(ct1));

		newCiphertext->SetElements(std::move(ctVector));

		return newCiphertext;

	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHEBGV<Element>::EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const
	{

		LPPrivateKey<Element> originalPrivateKeySquared = LPPrivateKey<Element>(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));

		Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

		originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

		return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHEBGV<Element>::EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const
	{

		Ciphertext<Element> permutedCiphertext = ciphertext->CloneEmpty();

		const std::vector<Element> &c = ciphertext->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c[0].AutomorphismTransform(i)));

		cNew.push_back(std::move(c[1].AutomorphismTransform(i)));

		permutedCiphertext->SetElements(std::move(cNew));

		return this->KeySwitch(evalKeys.find(i)->second, permutedCiphertext);

	}

	template <class Element>
	shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmSHEBGV<Element>::EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
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
	LPEvalKey<Element> LPAlgorithmPREBGV<Element>::ReKeyGen(const LPPrivateKey<Element> newSK,
		const LPPrivateKey<Element> origPrivateKey) const
	{
		return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchGen(origPrivateKey, newSK);
	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmPREBGV<Element>::ReKeyGen(const LPPublicKey<Element> newPK,
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

		// The re-encryption key is K ciphertexts, one for each -s(2^r)^i
		for (usint i=0; i<K; i++) {
			NativeInteger bb = NativeInteger(1) << i*relinWin;

			const auto p = cryptoParamsLWE->GetPlaintextModulus();
			const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

			typename Element::TugType tug;

			s.SetFormat(Format::EVALUATION);

			std::vector<Element> cVector;

			const Element &a = newPK->GetPublicElements().at(0);
			const Element &b = newPK->GetPublicElements().at(1);

			Element v;

			if (cryptoParamsLWE->GetMode() == RLWE)
				v = Element(dgg, elementParams, Format::EVALUATION);
			else
				v = Element(tug, elementParams, Format::EVALUATION);

			Element e0(dgg, elementParams, Format::EVALUATION);
			Element e1(dgg, elementParams, Format::EVALUATION);

			Element c0(b*v + p*e0 - s*bb);

			Element c1(a*v + p*e1);

			evalKeyElementsA[i] = c1;
			evalKeyElementsB[i] = c0;
		}

		ek->SetAVector(std::move(evalKeyElementsA));
		ek->SetBVector(std::move(evalKeyElementsB));

		return std::move(ek);
	}

	//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
	template <class Element>
	Ciphertext<Element> LPAlgorithmPREBGV<Element>::ReEncrypt(
			const LPEvalKey<Element> EK,
			ConstCiphertext<Element> ciphertext,
			const LPPublicKey<Element> publicKey) const
	{
		if (publicKey == nullptr) { // Sender PK is not provided - CPA-secure PRE
			auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);
			return c;
		} else {// Sender PK provided - HRA-secure PRE
			// Get crypto and elements parameters
			const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());
			const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();

			const auto p = cryptoParamsLWE->GetPlaintextModulus();

			const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
			typename Element::TugType tug;

			PlaintextEncodings encType = ciphertext->GetEncodingType();

			Ciphertext<Element> zeroCiphertext(new CiphertextImpl<Element>(publicKey));
			zeroCiphertext->SetEncodingType(encType);

			const Element &a = publicKey->GetPublicElements().at(0);
			const Element &b = publicKey->GetPublicElements().at(1);

			Element v;
			if (cryptoParamsLWE->GetMode() == RLWE)
				v = Element(dgg, elementParams, Format::EVALUATION);
			else
				v = Element(tug, elementParams, Format::EVALUATION);

			Element e0(dgg, elementParams, Format::EVALUATION);
			Element e1(dgg, elementParams, Format::EVALUATION);

			Element c0(b*v + p*e0);
			Element c1(a*v + p*e1);

			zeroCiphertext->SetElements({ c0, c1 });

			// Add the encryption of zero for re-randomization purposes
			auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(ciphertext, zeroCiphertext);

			// Do key switching and return the result
			return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, c);

		}
	}

	template <class Element>
	Ciphertext<Element> LPLeveledSHEAlgorithmBGV<Element>::ModReduce(ConstCiphertext<Element> cipherText) const {

		Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

		std::vector<Element> cipherTextElements(cipherText->GetElements());

		const auto plaintextModulus = cipherText->GetCryptoParameters()->GetPlaintextModulus();

		for (auto &cipherTextElement : cipherTextElements) {
			cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.
		}

		newCiphertext->SetElements(cipherTextElements);

		return newCiphertext;
	}


	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmMultipartyBGV<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const vector<LPPrivateKey<Element>>& secretKeys,
		bool makeSparse)
	{

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));
		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const auto p = cryptoParams->GetPlaintextModulus();
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

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBGV<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const LPPublicKey<Element> pk1, bool makeSparse, bool pre)
	{


		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));
		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const auto p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		typename Element::DugType dug;
		typename Element::TugType tug;

		//Generate the element "a" of the public key
		Element a = pk1->GetPublicElements()[0];
		//Generate the secret key
		Element s;

		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE) {
			s = Element(dgg, elementParams, Format::COEFFICIENT);
		}
		else {
			s = Element(tug, elementParams, Format::COEFFICIENT);
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
			b = a*s + p*e + pk1->GetPublicElements()[1];
		else
			b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBGV<Element>::MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext) const
{

		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const std::vector<Element> &c = ciphertext->GetElements();
		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] - s*c[1];

		Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
		newCiphertext->SetElements({ b });

		return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBGV<Element>::MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
		ConstCiphertext<Element> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = s*c[1];

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetElements({ b });

	return newCiphertext;
}


template <class Element>
DecryptResult LPAlgorithmMultipartyBGV<Element>::MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();

	const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	Element b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
		b -= c2[0];
	}

	b.SwitchFormat();	

	*plaintext = b.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());

}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBGV<Element>::MultiKeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey,
	const LPEvalKey<Element> ek) const {
		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(originalPrivateKey->GetCryptoParameters());

		const shared_ptr<typename Element::Params> originalKeyParams = cryptoParams->GetElementParams();

		const auto &p = cryptoParams->GetPlaintextModulus();

		LPEvalKey<Element> keySwitchHintRelin(new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

		//Getting a reference to the polynomials of new private key.
		const Element &sNew = newPrivateKey->GetPrivateElement();

		//Getting a reference to the polynomials of original private key.
		const Element &s = originalPrivateKey->GetPrivateElement();

		//Getting a refernce to discrete gaussian distribution generator.
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		//Relinearization window is used to calculate the base exponent.
		usint relinWindow = cryptoParams->GetRelinWindow();

		//Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
		std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

		//evalKeyElementsGenerated hold the generated noise distribution.
		std::vector<Element> evalKeyElementsGenerated;

		const std::vector<Element> &a = ek->GetAVector();

		for (usint i = 0; i < (evalKeyElements.size()); i++)
		{

			evalKeyElementsGenerated.push_back(a[i]); //alpha's of i

			// Generate a_i * newSK + p * e - PowerOfBase(oldSK)
			Element e(dgg, originalKeyParams, Format::EVALUATION);

			evalKeyElements.at(i) = (a[i]*sNew + p*e) - evalKeyElements.at(i);

		}

		keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

		keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

		return keySwitchHintRelin;

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmMultipartyBGV<Element>::MultiEvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
	const std::vector<usint> &indexList) const {
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

				(*evalKeys)[indexList[i]] = MultiKeySwitchGen(tempPrivateKey, privateKey, eAuto->find(indexList[i])->second);

			}

		}

		return evalKeys;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmMultipartyBGV<Element>::MultiEvalSumKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const {

		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();
		usint m = elementParams->GetCyclotomicOrder();

		// stores automorphism indices needed for EvalSum
		std::vector<usint> indices;

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

		return MultiEvalAutomorphismKeyGen(privateKey, eSum, indices);

}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBGV<Element>::MultiAddEvalKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const {

	LPEvalKey<Element> evalKeySum(new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

	const std::vector<Element> &a = evalKey1->GetAVector();

	const std::vector<Element> &b1 = evalKey1->GetBVector();
	const std::vector<Element> &b2 = evalKey2->GetBVector();

	std::vector<Element> b;

	for (usint i = 0; i < a.size(); i++)
	{
		b.push_back(b1[i] + b2[i]);
	}

	evalKeySum->SetAVector(std::move(a));

	evalKeySum->SetBVector(std::move(b));

	return evalKeySum;

}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBGV<Element>::MultiMultEvalKey(LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk) const {

		const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Element>>(evalKey->GetCryptoContext()->GetCryptoParameters());
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const auto &p = cryptoParams->GetPlaintextModulus();

		LPEvalKey<Element> evalKeyResult(new LPEvalKeyRelinImpl<Element>(evalKey->GetCryptoContext()));

		const std::vector<Element> &a0 = evalKey->GetAVector();
		const std::vector<Element> &b0 = evalKey->GetBVector();

		const Element &s = sk->GetPrivateElement();

		std::vector<Element> a;
		std::vector<Element> b;

		for (usint i = 0; i < a0.size(); i++)
		{
			Element f1(dgg, elementParams, Format::COEFFICIENT);
			f1.SwitchFormat();

			Element f2(dgg, elementParams, Format::COEFFICIENT);
			f2.SwitchFormat();

			a.push_back(a0[i] * s + p*f1);
			b.push_back(b0[i] * s + p*f2);
		}

		evalKeyResult->SetAVector(std::move(a));

		evalKeyResult->SetBVector(std::move(b));

		return evalKeyResult;

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmMultipartyBGV<Element>::MultiAddEvalSumKeys(const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2) const {

		shared_ptr<std::map<usint, LPEvalKey<Element>>> evalSumKeys(new std::map<usint, LPEvalKey<Element>>());

		for (typename std::map<usint, LPEvalKey<Element>>::iterator it = es1->begin(); it != es1->end(); ++it)
		{
			(*evalSumKeys)[it->first] = this->MultiAddEvalKeys(it->second, es2->find(it->first)->second);
		}

		return evalSumKeys;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBGV<Element>::MultiAddEvalMultKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const {

		LPEvalKey<Element> evalKeySum(new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

		const std::vector<Element> &a1 = evalKey1->GetAVector();
		const std::vector<Element> &a2 = evalKey2->GetAVector();

		const std::vector<Element> &b1 = evalKey1->GetBVector();
		const std::vector<Element> &b2 = evalKey2->GetBVector();

		std::vector<Element> a;
		std::vector<Element> b;

		for (usint i = 0; i < a1.size(); i++)
		{
			a.push_back(a1[i] + a2[i]);
			b.push_back(b1[i] + b2[i]);
		}

		evalKeySum->SetAVector(std::move(a));

		evalKeySum->SetBVector(std::move(b));

		return evalKeySum;

}

	// Enable for LPPublicKeyEncryptionSchemeLTV
	template <class Element>
	void LPPublicKeyEncryptionSchemeBGV<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmBGV<Element>() );
			break;
		case PRE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmBGV<Element>() );
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE.reset( new LPAlgorithmPREBGV<Element>() );
			break;
		case SHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmBGV<Element>() );
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE.reset( new LPAlgorithmSHEBGV<Element>() );
			break;
		case LEVELEDSHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmBGV<Element>() );
			if (this->m_algorithmLeveledSHE == NULL)
				this->m_algorithmLeveledSHE.reset( new LPLeveledSHEAlgorithmBGV<Element>() );
			break;
		case MULTIPARTY:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption.reset( new LPAlgorithmBGV<Element>() );
			if (this->m_algorithmMultiparty == NULL)
				this->m_algorithmMultiparty.reset( new LPAlgorithmMultipartyBGV<Element>() );
			break;
		case FHE:
			PALISADE_THROW(not_implemented_error, "FHE feature not supported for BGV scheme");
		case ADVANCEDSHE:
			PALISADE_THROW(not_implemented_error, "ADVANCEDSHE feature not supported for BGV scheme");
		case ADVANCEDMP:
			PALISADE_THROW(not_implemented_error, "ADVANCEDMP feature not supported for BGV scheme");
		}
	}

}  // namespace lbcrypto ends

#endif
