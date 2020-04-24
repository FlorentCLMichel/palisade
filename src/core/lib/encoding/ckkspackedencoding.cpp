/*
 * @file ckkspackedencoding.cpp
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

#include "encoding/ckkspackedencoding.h"
#include "math/dftransfrm.h"

namespace lbcrypto {

std::vector<DCRTPoly::Integer> CKKSPackedEncoding::CRTMult(
		std::vector<DCRTPoly::Integer> a,
		std::vector<DCRTPoly::Integer> b,
		std::vector<DCRTPoly::Integer> mods) {

	std::vector<DCRTPoly::Integer> result(mods.size());

	for (usint i=0; i<a.size(); i++) {
		result[i] = a[i].ModMulFast(b[i], mods[i]);
	}

	return result;
}

bool CKKSPackedEncoding::Encode() {

	if ( this->isEncoded ) return true;

	uint32_t Nh = (this->GetElementRingDimension() >> 1);

	std::vector<std::complex<double>> inverse  = value;
	inverse.resize(Nh);
	DiscreteFourierTransform::FFTSpecialInv(inverse);

	if (this->typeFlag == IsDCRTPoly) {
		double powP = scalingFactor;

		int64_t q;
		q = 9223372036854775295; // 2^63-2^9-1 - max value that could be round to int64_t
		double dq = q;

		std::vector<int64_t> temp(this->GetElementRingDimension());
		size_t i, jdx, idx;
		int64_t re, im;
		double dre, dim;
		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {
			// Check for possible overflow in llround function
			dre = inverse[i].real() * powP;
			dim = inverse[i].imag() * powP;
			if(std::abs(dre) >= dq || std::abs(dim) >= dq) {
				PALISADE_THROW(math_error, "Overflow, try to decrease scaling factor");
			}

			re = std::llround(dre);
			im = std::llround(dim);

			temp[idx] = (re < 0) ? q + re : re;
			temp[jdx] = (im < 0) ? q + im : im;
		}

		const shared_ptr<ILDCRTParams<BigInteger>> params = this->encodedVectorDCRT.GetParams();
		const std::vector<std::shared_ptr<ILNativeParams>> &nativeParams = params->GetParams();

		for (i = 0; i < nativeParams.size(); i++ ) {
			NativeVector nativeVec(this->GetElementRingDimension(), nativeParams[i]->GetModulus());
			FitToNativeVector(temp, q, &nativeVec);
			NativePoly element = this->GetElement<DCRTPoly>().GetElementAtIndex(i);
			element.SetValues(nativeVec, Format::COEFFICIENT); //output was in coefficient format
			this->encodedVectorDCRT.SetElementAtIndex(i,element);
		}


		usint numTowers = nativeParams.size();
		std::vector<DCRTPoly::Integer> moduli(numTowers);
		for (usint i=0; i<numTowers; i++) {
			moduli[i] = nativeParams[i]->GetModulus();
		}

		DCRTPoly::Integer intPowP = std::llround(powP);
		std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

		auto currPowP = crtPowP;

		// We want to scale temp by 2^(pd), and the loop starts from j=2
		// because temp is already scaled by 2^p in the re/im loop above,
		// and currPowP already is 2^p.
		for (i = 2; i < depth; i++) {
			currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
		}

		if (depth > 1) {
			this->encodedVectorDCRT = this->encodedVectorDCRT.Times(currPowP);
		}

		this->GetElement<DCRTPoly>().SetFormat(Format::EVALUATION);

		scalingFactor = pow(scalingFactor, depth);

	} else if (this->typeFlag == IsNativePoly) {

		double p = this->encodingParams->GetPlaintextModulus();
		double powP = pow(2, p * depth);

		int64_t q;
		q = this->GetElementModulus().ConvertToInt();
		NativeVector temp(this->GetElementRingDimension(), q);

		double dq = q;
		size_t i, jdx, idx;
		int64_t re, im;
		double dre, dim;
		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {
			dre = inverse[i].real() * powP;
			dim = inverse[i].imag() * powP;
			// Check for possible overflow in llround function
			if(std::abs(dre) >= dq || std::abs(dim) >= dq) {
				PALISADE_THROW(math_error, "Overflow, try to decrease depth or plaintext modulus");
			}

			re = std::llround(dre);
			im = std::llround(dim);

			temp[idx] = (re < 0) ? NativeInteger(q + re) : NativeInteger(re);
			temp[jdx] = (im < 0) ? NativeInteger(q + im) : NativeInteger(im);
		}

		this->GetElement<NativePoly>().SetValues(temp, Format::COEFFICIENT); //output was in coefficient format
		this->GetElement<NativePoly>().SetFormat(Format::EVALUATION);

	} else {

		// Scale inverse by scaling factor
		double p = this->encodingParams->GetPlaintextModulus();
		double powP = pow(2, p * depth);

		const BigInteger &q = this->GetElementModulus();
		double dq = std::min(9223372036854775295., q.ConvertToDouble()); //min of q and 2^63-2^9-1 - max value that could be round to int64_t

		BigVector temp(this->GetElementRingDimension(), this->GetElementModulus());

		int64_t re, im;
		size_t i, jdx, idx;
		double dre, dim;
		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {
			dre = inverse[i].real() * powP;
			dim = inverse[i].imag() * powP;
			// Check for possible overflow in llround function
			if(std::abs(dre) >= dq || std::abs(dim) >= dq) {
				PALISADE_THROW(math_error, "Overflow, try to decrease depth or plaintext modulus");
			}

			re = std::llround(dre);
			im = std::llround(dim);

			temp[idx] = (re < 0) ? q - BigInteger(llabs(re)) : BigInteger(re);
			temp[jdx] = (im < 0) ? q - BigInteger(llabs(im)) : BigInteger(im);
		}

		this->GetElement<Poly>().SetValues(temp, Format::COEFFICIENT); //output was in coefficient format
		this->GetElement<Poly>().SetFormat(Format::EVALUATION);
	}
	this->isEncoded = true;
	return true;
}


bool CKKSPackedEncoding::Decode(size_t depth, long double scalingFactor, enum RescalingTechnique rsTech) {

	double p = this->encodingParams->GetPlaintextModulus();
	long double powP = 0.0;
	uint32_t Nh = this->GetElementRingDimension()/2;
	value.clear();

	if (rsTech == EXACTRESCALE)
		powP = pow(scalingFactor, -1);
	else
		powP = pow(2,-p*depth);

	if ( this->typeFlag == IsNativePoly ) {

		const NativeInteger &q = this->GetElementModulus().ConvertToInt();
		NativeInteger qHalf = q >> 1;

		std::vector<std::complex<double>> curValues;

		for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {

			std::complex<double> cur;

			if (this->GetElement<NativePoly>()[idx] > qHalf)
				cur.real(-((q - this->GetElement<NativePoly>()[idx])).ConvertToDouble()*powP);
			else
				cur.real((this->GetElement<NativePoly>()[idx]).ConvertToDouble()*powP);

			if (this->GetElement<NativePoly>()[idx + Nh] > qHalf)
				cur.imag(-((q - this->GetElement<NativePoly>()[idx + Nh])).ConvertToDouble()*powP);
			else
				cur.imag((this->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble()*powP);

			curValues.push_back(cur);

		}

		DiscreteFourierTransform::FFTSpecial(curValues);

		value = curValues;

	}
	else {

		const BigInteger &q = this->GetElementModulus();
		BigInteger qHalf = q >> 1;

		std::vector<std::complex<double>> curValues;

		for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {

			std::complex<double> cur;

			if (this->GetElement<Poly>()[idx] > qHalf)
				cur.real(-((q - this->GetElement<Poly>()[idx])).ConvertToDouble()*powP);
			else
				cur.real((this->GetElement<Poly>()[idx]).ConvertToDouble()*powP);

			if (this->GetElement<Poly>()[idx + Nh] > qHalf)
				cur.imag(-((q - this->GetElement<Poly>()[idx + Nh])).ConvertToDouble()*powP);
			else
				cur.imag((this->GetElement<Poly>()[idx + Nh]).ConvertToDouble()*powP);

			curValues.push_back(cur);

		}

		DiscreteFourierTransform::FFTSpecial(curValues);

		value = curValues;

	}

	return true;
}

bool CKKSPackedEncoding::Decode() {

	double p = this->encodingParams->GetPlaintextModulus();
	double powP = pow(2,-p);
	uint32_t Nh = this->GetElementRingDimension()/2;
	value.clear();

	if( this->typeFlag == IsNativePoly ) {

		const NativeInteger &q = this->GetElementModulus().ConvertToInt();
		NativeInteger qHalf = q >> 1;

		std::vector<std::complex<double>> curValues;

		for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {

			std::complex<double> cur;

			if (this->GetElement<NativePoly>()[idx] > qHalf)
				cur.real(-((q - this->GetElement<NativePoly>()[idx])).ConvertToDouble()*powP);
			else
				cur.real((this->GetElement<NativePoly>()[idx]).ConvertToDouble()*powP);

			if (this->GetElement<NativePoly>()[idx + Nh] > qHalf)
				cur.imag(-((q - this->GetElement<NativePoly>()[idx + Nh])).ConvertToDouble()*powP);
			else
				cur.imag((this->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble()*powP);

			curValues.push_back(cur);

		}

		DiscreteFourierTransform::FFTSpecial(curValues);

		value = curValues;

	}
	else {

		const BigInteger &q = this->GetElementModulus();
		BigInteger qHalf = q >> 1;

		std::vector<std::complex<double>> curValues;

		for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {

			std::complex<double> cur;

			if (this->GetElement<Poly>()[idx] > qHalf)
				cur.real(-((q - this->GetElement<Poly>()[idx])).ConvertToDouble()*powP);
			else
				cur.real((this->GetElement<Poly>()[idx]).ConvertToDouble()*powP);

			if (this->GetElement<Poly>()[idx + Nh] > qHalf)
				cur.imag(-((q - this->GetElement<Poly>()[idx + Nh])).ConvertToDouble()*powP);
			else
				cur.imag((this->GetElement<Poly>()[idx + Nh]).ConvertToDouble()*powP);

			curValues.push_back(cur);

		}

		DiscreteFourierTransform::FFTSpecial(curValues);

		value = curValues;

	}

	return true;
}


void CKKSPackedEncoding::Destroy()
{

}

void CKKSPackedEncoding::FitToNativeVector(const std::vector<int64_t> &vec, int64_t bigBound, NativeVector *nativeVec) const {
	NativeInteger bigValueHf(bigBound >> 1);
	NativeInteger modulus(nativeVec->GetModulus());
	NativeInteger diff = bigBound - modulus;
	for (usint i = 0; i < vec.size(); i++) {
		NativeInteger n(vec[i]);
		if (n > bigValueHf) {
			(*nativeVec)[i] = n.ModSub(diff, modulus);
		} else {
			(*nativeVec)[i] = n.Mod(modulus);
		}
	}
}

}
