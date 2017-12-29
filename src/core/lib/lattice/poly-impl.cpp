/*
 * @file poly-impl.cpp - implementation of the integer lattice
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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

#include "elemparams.cpp"
#include "ilparams.cpp"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"
#include "poly.cpp"

// This creates all the necessary class implementations for Poly

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigInteger,BigVector>;
template class BinaryUniformGeneratorImpl<BigInteger,BigVector>;
template class TernaryUniformGeneratorImpl<BigInteger,BigVector>;
template class DiscreteUniformGeneratorImpl<BigInteger,BigVector>;

}

namespace lbcrypto {
template class ElemParams<BigInteger>;
template class ILParamsImpl<BigInteger>;
template class PolyImpl<BigInteger,BigInteger,BigVector,ILParams>;

template<>
PolyImpl<BigInteger,BigInteger,BigVector,ILParams>::PolyImpl(const shared_ptr<ILDCRTParams<BigInteger>> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format) {
	// construct a local params out of the stuff from the DCRT Params
	m_params.reset( new ILParams(params->GetCyclotomicOrder(), params->GetModulus(), 1));

	if (initializeElementToZero) {
		this->SetValuesToZero();
	}
}

}
