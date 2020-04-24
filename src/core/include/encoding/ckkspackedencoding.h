/**
 * @file ckkspackedencoding.h
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

#ifndef LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H
#define LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "plaintext.h"
#include "encodingparams.h"
#include <functional>
#include <numeric>

namespace lbcrypto
{

enum RescalingTechnique {
	APPROXRESCALE,
	EXACTRESCALE
};

// STL pair used as a key for some tables in CKKSPackedEncoding
using ModulusM = std::pair<NativeInteger, uint64_t>;

/**
 * @class CKKSPackedEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type vector<uint64_t>.
 * This class uses bit packing techniques to enable efficient computing on vectors of integers.
 * It is NOT supported for DCRTPoly
 */

class CKKSPackedEncoding : public PlaintextImpl
{

public:
	// these two constructors are used inside of Decrypt
	CKKSPackedEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep) { depth = 1; }

	CKKSPackedEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep) { depth = 1; }

	CKKSPackedEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep) { depth = 1; }


	CKKSPackedEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep,
						const std::vector<std::complex<double>> &coeffs,
						size_t depth, uint32_t level, double scFact) :
						PlaintextImpl(vp,ep), value(coeffs) {
		this->depth = depth;
		this->level = level;
		this->scalingFactor = scFact;
	}

	CKKSPackedEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep,
						const std::vector<std::complex<double>> &coeffs,
						size_t depth, uint32_t level, double scFact) :
		PlaintextImpl(vp,ep), value(coeffs) {
		this->depth = depth;
		this->level = level;
		this->scalingFactor = scFact;
	}

	/*
	 * @param depth depth of plaintext to create.
	 * @param level level of plaintext to create.
	 * @param scFact scaling factor of a plaintext of this level at depth 1.
	 *
	 */
	CKKSPackedEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep,
						const std::vector<std::complex<double>> &coeffs,
						size_t depth, uint32_t level, double scFact) :
		PlaintextImpl(vp,ep), value(coeffs) {
		this->depth = depth;
		this->level = level;
		this->scalingFactor = scFact;
	}

	/**
	 * @brief Constructs a container with a copy of each of the elements in rhs, in the same order.
	 * @param rhs - The input object to copy.
	 */
	CKKSPackedEncoding(const std::vector<std::complex<double>> &rhs)
		: PlaintextImpl(shared_ptr<Poly::Params>(0),NULL), value(rhs) { depth = 1; }

	/**
	 * @brief Default empty constructor with empty uninitialized data elements.
	 */
	CKKSPackedEncoding()
		: PlaintextImpl(shared_ptr<Poly::Params>(0),NULL), value() { depth = 1; }

	bool Encode();

	bool Decode();

	bool Decode(size_t depth, long double scalingFactor, RescalingTechnique rsTech);

	const std::vector<std::complex<double>>& GetCKKSPackedValue() const { return value; }

	/**
	* Static utility method to multiply two numbers in CRT representation.
	* CRT representation is stored in a vector of native integers, and each
	* position corresponds to the remainder of the number against one of
	* the moduli in mods.
	*
	* @param a is the first number in CRT representation.
	* @param b is the second number in CRT representation.
	* @return the product of the two numbers in CRT representation.
	*/
	static std::vector<DCRTPoly::Integer> CRTMult(
			std::vector<DCRTPoly::Integer> a,
			std::vector<DCRTPoly::Integer> b,
			std::vector<DCRTPoly::Integer> mods);

	/**
	 * GetEncodingType
	 * @return this is a Packed encoding
	 */
	PlaintextEncodings GetEncodingType() const { return CKKSPacked; }

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const {
		return value.size();
	}

	/**
	 * SetLength of the plaintext to the given size
	 * @param siz
	 */
	void SetLength(size_t siz) {
			value.resize(siz);
	}

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const PlaintextImpl& other) const {
		const std::vector<std::complex<double>>& lv = dynamic_cast<const std::vector<std::complex<double>>&>(*this);
		const std::vector<std::complex<double>>& rv = dynamic_cast<const std::vector<std::complex<double>>&>(other);
		return lv == rv;
	}

	/**
	 * @brief Destructor method.
	 */
	static void Destroy();

	void PrintValue(std::ostream& out) const {
		// for sanity's sake, trailing zeros get elided into "..."
		//out.precision(15);
		out << "(";
		size_t i = value.size();
		while( --i > 0 )
			if( value[i] != std::complex<double>(0,0) )
				break;

		for( size_t j = 0; j <= i; j++ ) {
			//out << ' ' << value[j].real();
			out << " (" << value[j].real() << "," << value[j].imag() << "),";
		}

		out << " ... )";
	}

private:

	std::vector<std::complex<double>> value;

	/**
	 * Set modulus and recalculates the vector values to fit the modulus
	 *
	 * @param &vec input vector
	 * @param &bigValue big bound of the vector values.
	 * @param &modulus modulus to be set for vector.
	 */
	void FitToNativeVector(const std::vector<int64_t> &vec, int64_t bigBound, NativeVector *nativeVec) const;

};

}

#endif
