/*
 * @file matrixser-impl.cpp - matrix serialization implementation
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

// this is the implementation of matrixes of things that are in pke

// FIXME there is much duplicated redundant code here, and we should do this better

#include "palisade.h"
#include "cryptocontext.h"
#include "rationalciphertext.h"

#include "../../core/lib/../../core/lib/math/matrix.cpp"
using std::invalid_argument;

namespace lbcrypto {

template class Matrix<Ciphertext<Poly>>;
template class Matrix<RationalCiphertext<Poly>>;
template class Matrix<Ciphertext<NativePoly>>;
template class Matrix<RationalCiphertext<NativePoly>>;
template class Matrix<Ciphertext<DCRTPoly>>;
template class Matrix<RationalCiphertext<DCRTPoly>>;

template<>
Matrix<RationalCiphertext<Poly>>& Matrix<RationalCiphertext<Poly>>::Ones() {
	PALISADE_THROW(not_available_error, "Cannot fill matrix of ciphertext with 1's");
}

template<>
Matrix<RationalCiphertext<Poly>>& Matrix<RationalCiphertext<Poly>>::Identity() {
	PALISADE_THROW(not_available_error, "Cannot create identity matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<Poly>> Matrix<RationalCiphertext<Poly>>::GadgetVector(int64_t base) const {
	PALISADE_THROW(not_available_error, "Cannot create gadget matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<NativePoly>>& Matrix<RationalCiphertext<NativePoly>>::Ones() {
	PALISADE_THROW(not_available_error, "Cannot fill matrix of ciphertext with 1's");
}

template<>
Matrix<RationalCiphertext<NativePoly>>& Matrix<RationalCiphertext<NativePoly>>::Identity() {
	PALISADE_THROW(not_available_error, "Cannot create identity matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<NativePoly>> Matrix<RationalCiphertext<NativePoly>>::GadgetVector(int64_t base) const {
	PALISADE_THROW(not_available_error, "Cannot create gadget matrix of ciphertext");
}

}
