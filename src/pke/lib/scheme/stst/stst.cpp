/*
* @file ltv.cpp - Stehle-Steinfeld scheme implementation.
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
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publishâ€“Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and LÃ©o Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *
 */

#ifndef LBCRYPTO_CRYPTO_STST_C
#define LBCRYPTO_CRYPTO_STST_C

#include "scheme/stst/stst.h"

namespace lbcrypto {

template <class Element>
LPKeyPair<Element> LPAlgorithmStSt<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
{
	LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

	const shared_ptr<LPCryptoParametersStehleSteinfeld<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersStehleSteinfeld<Element>>(cc->GetCryptoParameters());

	const auto &p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGeneratorStSt();

	Element f(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

	f = p*f;

	f = f + 1;

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		//std::cout << "inverse does not exist" << std::endl;
		Element temp(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + 1;
		f.SwitchFormat();
	}

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse());

	return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmStSt<Element>::Encrypt(const LPPublicKey<Element> publicKey,
	Element ptxt) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

	Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(publicKey));

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	ptxt.SwitchFormat();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey->GetPublicElements().at(0);

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

	Element c(elementParams);

	c = h*s + p*e + ptxt;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmStSt<Element>::Encrypt(const LPPrivateKey<Element> privateKey,
	Element ptxt) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(privateKey->GetCryptoParameters());

	Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(privateKey));

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	ptxt.SwitchFormat();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	// Placeholder implementation that is mostly correct
	Element g(dgg, elementParams, Format::COEFFICIENT);
	g.SwitchFormat();
	const Element h = p*g*privateKey->GetPrivateElement().MultiplicativeInverse();

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

	Element c(elementParams);

	c = h*s + p*e + ptxt;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmStSt<Element>::Decrypt(const LPPrivateKey<Element> privateKey,
	ConstCiphertext<Element> ciphertext,
	NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();

	const Element& c = ciphertext->GetElement();

	const Element& f = privateKey->GetPrivateElement();

	Element b = f*c;

	b.SwitchFormat();

	*plaintext = b.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalAdd(
		ConstCiphertext<Element> ciphertext1,
		ConstCiphertext<Element> ciphertext2) const
{
	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	Element cResult = ciphertext1->GetElement() + ciphertext2->GetElement();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalAdd(
		ConstCiphertext<Element> ciphertext,
		ConstPlaintext plaintext) const
{
	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	Element cResult = ciphertext->GetElement() + plaintext->GetElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalSub(
	ConstCiphertext<Element> ciphertext1,
	ConstCiphertext<Element> ciphertext2) const
{
	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalSub crypto parameters are not the same";
		PALISADE_THROW(config_error, errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	Element cResult = ciphertext1->GetElement() - ciphertext2->GetElement();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalSub(
	ConstCiphertext<Element> ciphertext,
	ConstPlaintext plaintext) const
{
//	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
//		std::string errMsg = "EvalSub crypto parameters are not the same";
//		PALISADE_THROW(palisade_error, errMsg);
//	}

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	plaintext->SetFormat(EVALUATION);

	Element cResult = ciphertext->GetElement() - plaintext->GetElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalMult(
	ConstCiphertext<Element> ciphertext,
	ConstPlaintext plaintext) const
{
	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	plaintext->SetFormat(EVALUATION);

	if (ciphertext->GetElement().GetFormat() == Format::COEFFICIENT || plaintext->GetElement<Element>().GetFormat() == Format::COEFFICIENT ) {
		PALISADE_THROW(not_available_error, "EvalMult cannot multiply in COEFFICIENT domain.");
	}

	Element cResult = ciphertext->GetElement() * plaintext->GetElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::EvalNegate(ConstCiphertext<Element> ciphertext) const {

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	const Element& c1 = ciphertext->GetElement();

	newCiphertext->SetElement(c1.Negate());

	return newCiphertext;
}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
LPEvalKey<Element> LPAlgorithmSHEStSt<Element>::KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
	const LPPrivateKey<Element> origPrivateKey) const
{

	// create a new EvalKey of the proper type, in this context
	LPEvalKeyNTRURelin<Element> ek(new LPEvalKeyNTRURelinImpl<Element>(newPublicKey->GetCryptoContext()));

	// the wrapper checked to make sure that the input keys were created in the proper context

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(newPublicKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const auto p = cryptoParamsLWE->GetPlaintextModulus();
	const Element &f = origPrivateKey->GetPrivateElement();

	const Element &hn = newPublicKey->GetPublicElements().at(0);

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(f.PowersOfBase(relinWindow));

	const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

	for (usint i = 0; i < evalKeyElements.size(); ++i)
	{
		Element s(dgg, elementParams, Format::EVALUATION);
		Element e(dgg, elementParams, Format::EVALUATION);

		evalKeyElements.at(i) += hn*s + p*e;
	}

	ek->SetAVector(std::move(evalKeyElements));

	return ek;
}

//Function for re-encypting ciphertext using the array generated by KeySwitchRelinGen
template <class Element>
Ciphertext<Element> LPAlgorithmSHEStSt<Element>::KeySwitchRelin(const LPEvalKey<Element>evalKey,
	ConstCiphertext<Element> ciphertext) const
{
	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(evalKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();

	const std::vector<Element> &proxy = evalKey->GetAVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const Element& c = ciphertext->GetElement();

	std::vector<Element> digits(c.BaseDecompose(relinWindow));

	Element ct(digits[0] * proxy[0]);

	for (usint i = 1; i < digits.size(); ++i)
		ct += digits[i] * proxy[i];

	newCiphertext->SetElement(std::move(ct));

	return newCiphertext;
}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
LPEvalKey<Element> LPAlgorithmPREStSt<Element>::ReKeyGen(const LPPublicKey<Element> newPK,
	const LPPrivateKey<Element> origPrivateKey) const
{
	return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelinGen(newPK, origPrivateKey);
}

//Function for re-encypting ciphertext using the array generated by ReKeyGen
template <class Element>
Ciphertext<Element> LPAlgorithmPREStSt<Element>::ReEncrypt(const LPEvalKey<Element> evalKey,
	ConstCiphertext<Element> ciphertext,
	const LPPublicKey<Element> publicKey) const
{
	return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelin(evalKey, ciphertext);
}

}  // namespace lbcrypto ends

#endif
