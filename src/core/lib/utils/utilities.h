/**
 * @file utilities.h This file contains the utility function functionality.
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

#ifndef LBCRYPTO_UTILS_UTILITIES_H
#define LBCRYPTO_UTILS_UTILITIES_H

#include "../math/backend.h"
#include "../math/nbtheory.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Zero Padding of Elements. 
 * Adds zeros to form a polynomial of length 2n  (corresponding to cyclotomic order m = 2n). 
 * It is used by the forward transform of ChineseRemainderTransform (a modified version of ZeroPadd will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.	  	  
 */
BigVector ZeroPadForward(const BigVector &InputPoly, usint target_order);

/**
 * Zero Pad Inverse of Elements.
 * Adds alternating zeroes to form a polynomial of length of length 2n (corresponding to cyclotomic order m = 2n). 
 * It is used by the inverse transform of ChineseRemainderTransform (a modified version of ZeroPadInverse will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.	  	  
 */
BigVector ZeroPadInverse(const BigVector &InputPoly, usint target_order);

/**
 * Determines if a number is a power of 2.
 *
 * @param Input to test if it is a power of 2.
 * @return is true if the unsigned int is a power of 2.	  	  
 */
bool IsPowerOfTwo(usint Input);

/**
 * Auxiliary function to replace a specific character "in" with another character "out"
 *
 * @param str string where in which characters are replaced
 * @param in character being replaced
 * @param out character to be replaced with
 * @return the modified string.	  	  
 */
// auxiliary function to replace a specific character "in" with another character "out"
std::string replaceChar(std::string str, char in, char out); 

} // namespace lbcrypto ends

#endif
