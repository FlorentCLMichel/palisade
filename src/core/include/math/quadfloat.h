/**
 * @file quadfloat.h This file has the definitions for the quad-precision floating-point data type
 *
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

#ifndef LBCRYPTO_MATH_QUADFLOAT_H
#define LBCRYPTO_MATH_QUADFLOAT_H

#ifdef  WITH_NTL
  #include <NTL/quad_float.h>
  #include <NTL/xdouble.h>
#else
  #ifdef __x86_64__              //the gnu compiler has native quad support
    #include <quadmath.h>
  #else
    #include "armquadmath.h"
  #endif
#endif

///////// definition of the quad-precision floating-point and extended double data types
#ifdef WITH_NTL
typedef NTL::quad_float QuadFloat;
typedef NTL::xdouble ExtendedDouble;

namespace cereal {
	template<class Archive>
	void CEREAL_SAVE_FUNCTION_NAME(Archive & archive, const QuadFloat& m)
	{
		archive( m.hi, m.lo );
	}

	template<class Archive>
	void CEREAL_LOAD_FUNCTION_NAME(Archive & archive, QuadFloat& m)
	{
		archive( m.hi, m.lo );
	}
}
#elif __x86_64__
// If no NTL is available, use __float128 for both quad floats and extended doubles
typedef __float128 QuadFloat;
typedef QuadFloat ExtendedDouble;

#else  //arm platform

//no QUADMATH IS USED
#define NO_QUADMATH

#define NO_EXTENDEDDOUBLE

#endif

namespace ext_double {

#ifdef WITH_NTL
int64_t quadFloatRound(const QuadFloat& input);
QuadFloat quadFloatFromInt64(const long long int input);
inline QuadFloat floor(const QuadFloat& input) {return NTL::floor(input); }

inline ExtendedDouble sqrt(const ExtendedDouble& input) {return NTL::sqrt(input); }
inline double log(const ExtendedDouble& input) {return NTL::log(input); }
inline ExtendedDouble ceil(const ExtendedDouble& input) {return NTL::ceil(input); }
inline long int to_long(const ExtendedDouble& input) {return NTL::to_long(input); }
inline ExtendedDouble power(const ExtendedDouble& a, long b) {return NTL::power(a,b); }
inline ExtendedDouble fabs(const ExtendedDouble& input) {return NTL::fabs(input); }
inline ExtendedDouble floor(const ExtendedDouble& input) {return NTL::floor(input); }

#elif __x86_64__ //use GCC quadmath

inline long long int quadFloatRound(const QuadFloat& input) {return llroundq(input);}
inline QuadFloat quadFloatFromInt64(const long long int input) {return QuadFloat(input);}

inline QuadFloat sqrt(const QuadFloat& input) {return sqrtq(input); }
inline QuadFloat log(const QuadFloat& input) {return logq(input); }
inline QuadFloat ceil(const QuadFloat& input) {return ceilq(input); }
inline long int to_long(const QuadFloat& input) {return lroundq(input); }
inline QuadFloat power(const QuadFloat& a, const QuadFloat& b) {return powq(a,b); }
inline QuadFloat fabs(const QuadFloat& input) {return fabsq(input); }
inline QuadFloat floor(const QuadFloat& input) {return floorq(input); }

#else //arm

#ifndef NO_EXTENDEDDOUBLE
 inline ExtendedDouble sqrt(const ExtendedDouble& input) {return sqrt(input); }
 inline double log(const ExtendedDouble& input) {return log(input); }
 inline ExtendedDouble ceil(const ExtendedDouble& input) {return ceil(input); }
 inline long to_long(const ExtendedDouble& input) {return long(input); }
 
 inline ExtendedDouble power(const ExtendedDouble& a, long b) {return power(a,b); }
 inline ExtendedDouble fabs(const ExtendedDouble& input) {return fabs(input); }
 inline ExtendedDouble floor(const ExtendedDouble& input) {return floor(input); }
#endif

#endif

} // namespace lbcrypto ends

#endif
