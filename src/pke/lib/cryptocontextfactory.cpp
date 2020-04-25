/*
 * @file cryptocontextfactory.cpp -- Factory implementation
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @section LICENSE
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
 */

#include "cryptocontext.h"
#include "utils/serial.h"

namespace lbcrypto {

template <typename Element>
vector<CryptoContext<Element>>	CryptoContextFactory<Element>::AllContexts;

template <typename Element>
void
CryptoContextFactory<Element>::ReleaseAllContexts() {
	AllContexts.clear();
}

template <typename Element>
int
CryptoContextFactory<Element>::GetContextCount() {
	return AllContexts.size();
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetSingleContext() {
	if( GetContextCount() == 1 )
		return AllContexts[0];
	PALISADE_THROW(config_error, "More than one context");
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetContext(
		shared_ptr<LPCryptoParameters<Element>> params,
		shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
		const string & schemeId) {

	for( CryptoContext<Element> cc : AllContexts ) {
		if( *cc->GetEncryptionAlgorithm().get() == *scheme.get() &&
				*cc->GetCryptoParameters().get() == *params.get() ) {
			return cc;
		}
	}

	CryptoContext<Element> cc(new CryptoContextImpl<Element>(params,scheme, schemeId));
	AllContexts.push_back(cc);

    if( cc->GetEncodingParams()->GetPlaintextRootOfUnity() != 0 ) {
            PackedEncoding::SetParams(cc->GetCyclotomicOrder(), cc->GetEncodingParams());
    }

	return cc;
}

template <typename Element>
CryptoContext<Element>
CryptoContextFactory<Element>::GetContextForPointer(
		CryptoContextImpl<Element>* cc) {
	for( CryptoContext<Element> ctx : AllContexts ) {
		if( ctx.get() == cc )
			return ctx;
	}
	return 0;
}

template <typename T>
const vector<CryptoContext<T>>& CryptoContextFactory<T>::GetAllContexts() { return AllContexts; }

// factory methods for the different schemes

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
		{
	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(ep,
					plaintextmodulus,
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					typename T::Integer(delta),
					mode,
					typename T::Integer(bigmodulus),
					typename T::Integer(bigrootofunity),
					typename T::Integer(bigmodulusarb),
					typename T::Integer(bigrootofunityarb),
					depth,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb, int maxDepth)
		{
	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(ep,
					encodingParams,
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					typename T::Integer(delta),
					mode,
					typename T::Integer(bigmodulus),
					typename T::Integer(bigrootofunity),
					typename T::Integer(bigmodulusarb),
					typename T::Integer(bigrootofunityarb),
					depth,
					maxDepth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFV(encodingParams,securityLevel,relinWindow, dist,
			numAdds, numMults, numKeyswitches, mode, maxDepth, n);

		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					typename T::Integer(0),
					mode,
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFV(
		EncodingParams encodingParams, SecurityLevel securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFV<T>> params(
			new LPCryptoParametersBFV<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					typename T::Integer(0),
					mode,
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					typename T::Integer(0),
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)) );

	shared_ptr<LPCryptoParametersBFVrns<T>> params( new LPCryptoParametersBFVrns<T>(
			ep,
			EncodingParams(new EncodingParamsImpl(plaintextModulus)),
			dist,
			36.0,
			securityLevel,
			relinWindow,
			mode,
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFVrns<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFVrns(encodingParams, securityLevel, dist, numAdds, numMults,
			numKeyswitches, mode, maxDepth, relinWindow, dcrtBits, n);

		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrns<T>> params(
			new LPCryptoParametersBFVrns<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrns<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrns(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrns context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrns<T>> params(
			new LPCryptoParametersBFVrns<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrns<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)) );

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params( new LPCryptoParametersBFVrnsB<T>(
			ep,
			EncodingParams(new EncodingParamsImpl(plaintextModulus)),
			dist,
			36.0,
			securityLevel,
			relinWindow,
			mode,
			1,
			maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBFVrnsB<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		const PlaintextModulus plaintextModulus, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{

	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

	return genCryptoContextBFVrnsB(encodingParams, securityLevel, dist, numAdds, numMults,
			numKeyswitches, mode, maxDepth, relinWindow, dcrtBits, n);

		}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params(
			new LPCryptoParametersBFVrnsB<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrnsB<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBFVrnsB(
		EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode, int maxDepth,
		uint32_t relinWindow, size_t dcrtBits, uint32_t n)
		{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		PALISADE_THROW(config_error, "only one of (numAdds,numMults,numKeyswitches) can be nonzero in BFVrnsB context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	shared_ptr<LPCryptoParametersBFVrnsB<T>> params(
			new LPCryptoParametersBFVrnsB<T>(
					ep,
					encodingParams,
					dist,
					36.0,
					securityLevel,
					relinWindow,
					mode,
					1,
					maxDepth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBFVrnsB<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBGV(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth)
		{
	shared_ptr<LPCryptoParametersBGV<T>> params( new LPCryptoParametersBGV<T>(
			ep,
			plaintextmodulus,
			stDev,
			36, // assuranceMeasure,
			1.006, // securityLevel,
			relinWindow, // Relinearization Window
			mode, //Mode of noise generation
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBGV<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextBGV(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
		usint relinWindow, float stDev,
		MODE mode, int depth)
		{
	shared_ptr<LPCryptoParametersBGV<T>> params(new LPCryptoParametersBGV<T>(
			ep,
			encodingParams,
			stDev,
			36, // assuranceMeasure,
			1.006, // securityLevel,
			relinWindow, // Relinearization Window
			mode, //Mode of noise generation
			depth
	));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBGV<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextCKKS(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth, int maxDepth,
		enum KeySwitchTechnique ksTech,
		RescalingTechnique rsTech)
{
	shared_ptr<LPCryptoParametersCKKS<T>> params( new LPCryptoParametersCKKS<T>(
		ep,
		plaintextmodulus,
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode,
		depth,
		maxDepth) );

	params->PrecomputeCRTTables(ksTech, rsTech);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeCKKS<T>() );

    auto cc = CryptoContextFactory<T>::GetContext(params,scheme);

    cc->setSchemeId("CKKS");

    return cc;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextCKKS(shared_ptr<typename T::Params> ep,
	EncodingParams encodingParams,
	usint relinWindow, float stDev,
	MODE mode, int depth, int maxDepth,
	enum KeySwitchTechnique ksTech,
	RescalingTechnique rsTech)
{
	shared_ptr<LPCryptoParametersCKKS<T>> params(new LPCryptoParametersCKKS<T>(
		ep,
		encodingParams,
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode,
		depth,
		maxDepth
	));

	params->PrecomputeCRTTables(ksTech, rsTech);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeCKKS<T>());

	auto cc = CryptoContextFactory<T>::GetContext(params,scheme);

	cc->setSchemeId("CKKS");

	return cc;
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextCKKSWithParamsGen(
		   usint cyclOrder,
		   usint numPrimes,
		   usint scaleExp,
		   usint relinWindow,
		   usint batchSize,
		   MODE mode,
		   int depth,
		   int maxDepth,
		   usint firstModSize,
		   enum KeySwitchTechnique ksTech,
		   enum RescalingTechnique rsTech,
		   uint32_t numLargeDigits) {

	uint64_t p = scaleExp;
	float stdDev = 3.19;

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	EncodingParams encodingParams(new EncodingParamsImpl(p));
	encodingParams->SetBatchSize(batchSize);

	shared_ptr<LPCryptoParametersCKKS<T>> params(new LPCryptoParametersCKKS<T>(
		ep,
		encodingParams,
		stdDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode,
		depth,
		maxDepth
	));

	auto schemeCKKS = new LPPublicKeyEncryptionSchemeCKKS<T>();
	schemeCKKS->ParamsGen(params, cyclOrder, numPrimes, scaleExp, relinWindow, mode, ksTech, firstModSize, rsTech, numLargeDigits);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(schemeCKKS);

	auto cc = CryptoContextFactory<T>::GetContext(params,scheme);

	cc->setSchemeId("CKKS");

	return cc;
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextCKKS(
		   usint multiplicativeDepth,
		   usint scalingFactorBits,
		   usint batchSize,
		   SecurityLevel stdLevel,
		   usint ringDim,
		   enum RescalingTechnique rsTech,
		   enum KeySwitchTechnique ksTech,
		   uint32_t numLargeDigits,
		   int maxDepth,
		   usint firstModSize,
		   usint relinWindow,
		   MODE mode) {

	float stdDev = 3.19;

	shared_ptr<typename T::Params> ep(new typename T::Params(0, typename T::Integer(0), typename T::Integer(0)));

	// In CKKS, the plaintext modulus is equal to the scaling factor.
	EncodingParams encodingParams(new EncodingParamsImpl(scalingFactorBits));
	encodingParams->SetBatchSize(batchSize);

	shared_ptr<LPCryptoParametersCKKS<T>> params(new LPCryptoParametersCKKS<T>(
		ep,
		encodingParams,
		stdDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode,
		1, // depth
		maxDepth
	));

	params->SetStdLevel(stdLevel);

	// Setting the default value for numLargeDigits for HYBRID
	if (numLargeDigits == 0) { // Choose one of the default values
		if (multiplicativeDepth > 3) // If more than 4 towers, use 3 digits
			numLargeDigits = 3;
		else if (multiplicativeDepth == 3) // If 4 towers, use two digits
			numLargeDigits = 2;
		else // If less than 4 towers, use as many digits as available towers (equivalent to RNS decomposition (BV) + 1 special prime)
			numLargeDigits = multiplicativeDepth;
	}

	auto schemeCKKS = new LPPublicKeyEncryptionSchemeCKKS<T>();
	schemeCKKS->ParamsGen(
			params,
			2*ringDim,
			multiplicativeDepth+1,
			scalingFactorBits,
			relinWindow,
			mode,
			ksTech,
			firstModSize,
			rsTech,
			numLargeDigits);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(schemeCKKS);

	auto cc = CryptoContextFactory<T>::GetContext(params,scheme);

	cc->setSchemeId("CKKS");

	return cc;
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
		{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			plaintextmodulus,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			stDevStSt,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
		{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params(new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			encodingParams,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			stDevStSt,
			depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return CryptoContextFactory<T>::GetContext(params,scheme);
		}

template <>
CryptoContext<DCRTPoly>
CryptoContextFactory<DCRTPoly>::genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus)
{
	vector<NativeInteger> moduli = {ptModulus};
	vector<NativeInteger> roots = {1};
	shared_ptr<typename DCRTPoly::Params> ep( new typename DCRTPoly::Params(m, moduli, roots) );
	shared_ptr<LPCryptoParametersNull<DCRTPoly>> params( new LPCryptoParametersNull<DCRTPoly>(ep, ptModulus) );
	shared_ptr<LPPublicKeyEncryptionScheme<DCRTPoly>> scheme( new LPPublicKeyEncryptionSchemeNull<DCRTPoly>() );

	return CryptoContextFactory<DCRTPoly>::GetContext(params,scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus)
{
	shared_ptr<typename T::Params> ep( new typename T::Params(m, typename T::Integer(ptModulus), 1) );
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, ptModulus) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

template <>
CryptoContext<DCRTPoly>
CryptoContextFactory<DCRTPoly>::genCryptoContextNull(unsigned int m, EncodingParams encodingParams)
{
	vector<NativeInteger> moduli = {encodingParams->GetPlaintextModulus()};
	vector<NativeInteger> roots = {1};
	shared_ptr<typename DCRTPoly::Params> ep( new typename DCRTPoly::Params(m, moduli, roots) );
	shared_ptr<LPCryptoParametersNull<DCRTPoly>> params( new LPCryptoParametersNull<DCRTPoly>(ep, encodingParams) );
	shared_ptr<LPPublicKeyEncryptionScheme<DCRTPoly>> scheme( new LPPublicKeyEncryptionSchemeNull<DCRTPoly>() );

	return CryptoContextFactory<DCRTPoly>::GetContext(params,scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextNull(unsigned int m, EncodingParams encodingParams)
{
	shared_ptr<typename T::Params> ep( new typename T::Params(m, encodingParams->GetPlaintextModulus(), 1) );
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, encodingParams) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return CryptoContextFactory<T>::GetContext(params,scheme);
}

}

