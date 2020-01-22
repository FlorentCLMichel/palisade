/*
* @file bgv-ser.h -- serialize BGV; include this in any app that needs to serialize this scheme
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

#ifndef LBCRYPTO_CRYPTO_BGVSER_H
#define LBCRYPTO_CRYPTO_BGVSER_H

#include "palisade.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParametersBGV<lbcrypto::Poly>;
extern template class lbcrypto::LPCryptoParametersBGV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::Poly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmBGV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmBGV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmMultipartyBGV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmMultipartyBGV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmSHEBGV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmSHEBGV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPCryptoParametersBGV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmBGV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmMultipartyBGV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmSHEBGV<lbcrypto::DCRTPoly>;

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBGV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBGV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBGV<lbcrypto::DCRTPoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBGV<lbcrypto::DCRTPoly>);

#endif
