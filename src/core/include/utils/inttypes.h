/**
 * @file inttypes.h  This code provides basic integer types for lattice crypto.
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

#ifndef LBCRYPTO_UTILS_INTTYPES_H
#define LBCRYPTO_UTILS_INTTYPES_H

#include <string>
#include <stdint.h>

/**
 * @brief Type used for representing unsigned 8-bit integers.
 */
typedef uint8_t uschar;

/**
 * @brief Type used for representing unsigned 16-bit short integers.
 */
typedef uint16_t usshort;

/**
 * @brief Type used for representing unsigned 32-bit integers.
 */
typedef uint32_t usint;

typedef uint64_t PlaintextModulus;

#define ABSL_HAVE_INTRINSIC_INT128 1
/*************************************************
 *********** this does not work for android so
 *********** i am temporarily commenting it out
 ***********
 *********** for now, we assume everyone has an int128
 ***********
// the following useful snippet comes from the Abseil library

// ABSL_HAVE_INTRINSIC_INT128
//
// Checks whether the __int128 compiler extension for a 128-bit integral type is
// supported.
//
// Note: __SIZEOF_INT128__ is defined by Clang and GCC when __int128 is
// supported, but we avoid using it in certain cases:
// * On Clang:
//   * Building using Clang for Windows, where the Clang runtime library has
//     128-bit support only on LP64 architectures, but Windows is LLP64.
//   * Building for aarch64, where __int128 exists but has exhibits a sporadic
//     compiler crashing bug.
// * On Nvidia's nvcc:
//   * nvcc also defines __GNUC__ and __SIZEOF_INT128__, but not all versions
//     actually support __int128.
#ifdef ABSL_HAVE_INTRINSIC_INT128
#error ABSL_HAVE_INTRINSIC_INT128 cannot be directly set
#elif defined(__SIZEOF_INT128__)
#if (defined(__clang__) && !defined(_WIN32) && !defined(__aarch64__)) || \
    (defined(__CUDACC__) && __CUDACC_VER_MAJOR__ >= 9) ||                \
    (defined(__GNUC__) && !defined(__clang__) && !defined(__CUDACC__))
#define ABSL_HAVE_INTRINSIC_INT128 1
#elif defined(__CUDACC__)
// __CUDACC_VER__ is a full version number before CUDA 9, and is defined to a
// string explaining that it has been removed starting with CUDA 9. We use
// nested #ifs because there is no short-circuiting in the preprocessor.
// NOTE: `__CUDACC__` could be undefined while `__CUDACC_VER__` is defined.
#if __CUDACC_VER__ >= 70000
#define ABSL_HAVE_INTRINSIC_INT128 1
#endif  // __CUDACC_VER__ >= 70000
#endif  // defined(__CUDACC__)
#endif  // ABSL_HAVE_INTRINSIC_INT128
*************************************************/

/**
 * @brief Represents whether the polynomial ring is in EVALUATION or COEFFICIENT representation.
 */
enum Format{ EVALUATION=0, COEFFICIENT=1};

/**
 * @brief Lists all features supported by public key encryption schemes
 */
enum PKESchemeFeature{ 
	ENCRYPTION=0x01,
	PRE=0x02,
	SHE=0x04,
	FHE=0x08,
	LEVELEDSHE=0x10,
	MULTIPARTY=0x20,
	ADVANCEDSHE=0x40,
	ADVANCEDMP=0x80
};

/**
* @brief Lists all modes for RLWE schemes, such as BGV and FV
*/
enum MODE {
	RLWE = 0,
	OPTIMIZED = 1,
	SPARSE = 2
};

#endif
