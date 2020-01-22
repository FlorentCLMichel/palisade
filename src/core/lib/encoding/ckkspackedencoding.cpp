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
		result[i] = a[i].ModMul(b[i], mods[i]);
	}

	return result;
}

bool CKKSPackedEncoding::Encode() {

	if( this->isEncoded ) return true;

	double p = this->encodingParams->GetPlaintextModulus();

	uint32_t Nh = this->GetElementRingDimension()/2;

	if(this->typeFlag == IsDCRTPoly ){
		int64_t q;
		q = 9223372036854775807; // 2^63-1
		NativeVector temp(this->GetElementRingDimension(), q);

		std::vector<std::complex<double>> inverse  = value;

		inverse.resize(Nh);

		DiscreteFourierTransform::FFTSpecialInv(inverse);

		const shared_ptr<ILDCRTParams<BigInteger>> params = this->encodedVectorDCRT.GetParams();
		const std::vector<std::shared_ptr<ILNativeParams>> &nativeParams = params->GetParams();

		size_t i, jdx, idx;

		double powP = scalingFactor;

		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {

			int64_t re = std::llround(inverse[i].real()*powP);
			int64_t im = std::llround(inverse[i].imag()*powP);

			if (re < 0)
				temp[idx] = NativeInteger(q + re);
			else
				temp[idx] = NativeInteger(re);
			if (im < 0)
				temp[jdx] = NativeInteger(q + im);
			else
				temp[jdx] = NativeInteger(im);

		}

		this->isEncoded = true;

		NativeVector switched = temp;
		switched.SwitchModulus(nativeParams[0]->GetModulus());
		NativePoly firstElement = this->GetElement<DCRTPoly>().GetElementAtIndex(0);
		firstElement.SetValues(switched, Format::COEFFICIENT); //output was in coefficient format
		this->encodedVectorDCRT.SetElementAtIndex(0,firstElement);

		for (size_t i = 1; i < nativeParams.size(); i++ ) {
			switched = temp;
			switched.SwitchModulus(nativeParams[i]->GetModulus());
			NativePoly element = this->GetElement<DCRTPoly>().GetElementAtIndex(i);
			element.SetValues(switched, Format::COEFFICIENT); //output was in coefficient format
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
		for (usint j=2; j<depth; j++) {
			currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
		}

		if ( depth > 1 )
			this->encodedVectorDCRT = this->encodedVectorDCRT.Times(currPowP);

		this->GetElement<DCRTPoly>().SetFormat(Format::EVALUATION);

		scalingFactor = pow(scalingFactor, depth);

	} else if( this->typeFlag == IsNativePoly ){

		double powP = pow(2,p*depth);

		int64_t q;

		q = this->GetElementModulus().ConvertToInt();

		NativeVector temp(this->GetElementRingDimension(), q);

		std::vector<std::complex<double>> inverse  = value;

		inverse.resize(Nh);

		DiscreteFourierTransform::FFTSpecialInv(inverse);

		size_t i, jdx, idx;

		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {

			int64_t re = std::llround(inverse[i].real()*powP);
			int64_t im = std::llround(inverse[i].imag()*powP);

			if (re < 0)
				temp[idx] = NativeInteger(q + re);
			else
				temp[idx] = NativeInteger(re);
			if (im < 0)
				temp[jdx] = NativeInteger(q + im);
			else
				temp[jdx] = NativeInteger(im);

		}

		this->isEncoded = true;

		this->GetElement<NativePoly>().SetValues(temp, Format::COEFFICIENT); //output was in coefficient format
		this->GetElement<NativePoly>().SetFormat(Format::EVALUATION);

	}
	else {

		double powP = pow(2,p*depth);

		BigVector temp(this->GetElementRingDimension(), this->GetElementModulus());

		std::vector<std::complex<double>> inverse = value;

		inverse.resize(Nh);

		DiscreteFourierTransform::FFTSpecialInv(inverse);

		size_t i, jdx, idx;

		const BigInteger &q = this->GetElementModulus();

		for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {

			int64_t re = std::llround(inverse[i].real()*powP);
			int64_t im = std::llround(inverse[i].imag()*powP);

			if (re < 0)
				temp[idx] = q - BigInteger(llabs(re)) ;
			else
				temp[idx] = BigInteger(re);
			if (im < 0)
				temp[jdx] = q - BigInteger(llabs(im));
			else
				temp[jdx] = BigInteger(im);

		}

		this->isEncoded = true;

		this->GetElement<Poly>().SetValues(temp, Format::COEFFICIENT); //output was in coefficient format
		this->GetElement<Poly>().SetFormat(Format::EVALUATION);
	}

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

}
