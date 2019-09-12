/**
 * @file binint.h This file contains the main class for native integers.
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
 /*
 * This file contains the main class for native integers.
 * It implements the same methods as other mathematical backends.
 */

#ifndef LBCRYPTO_MATH_NATIVE_BININT_H
#define LBCRYPTO_MATH_NATIVE_BININT_H

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <stdexcept>
#include <functional>
#include <cstdlib>
#include <memory>
#include "../interface.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"
#include "utils/memory.h"
#include "utils/palisadebase64.h"
#include "utils/exception.h"
#include "utils/debug.h"
#include "../nbtheory.h"

// the default behavior of the native integer layer is
// to assume that the user does not need bounds/range checks
// in the native integer code
// if you want them, change this #define to true
// we use a #define to resolve which to use at compile time
// sadly, making the choice according to some setting that
// is checked at runtime has awful performance; using this
// #define in a simple expression causes the compiler to
// optimize away the test
#define NATIVEINT_DO_CHECKS	false

#ifndef PALISADE_NATIVEINT_BITS
#define PALISADE_NATIVEINT_BITS 64
#endif

#if PALISADE_NATIVEINT_BITS == 32
        typedef uint32_t        NativeInt
        typedef uint64_t        DNativeInt
        typedef int32_t         SignedNativeInt
#elif PALISADE_NATIVEINT_BITS == 64
        typedef uint64_t        				NativeInt;
        typedef lbcrypto::DoubleNativeInt		DNativeInt;
        typedef int64_t							SignedNativeInt;
        #define PALISADE_NATIVE_LOWMASK (NativeInt)0xFFFFFFFF
        #define PALISADE_NATIVE_LOWSIZE 32
        #define PALISADE_NATIVE_HIMASK (PALISADE_NATIVE_LOWMASK << PALISADE_NATIVE_LOWSIZE)
#else
#error Unsupported size for NativeInteger
#endif

#if __APPLE__
#define ADD_OVERFLOW_TEST __builtin_uaddll_overflow
#define SUB_OVERFLOW_TEST __builtin_usubll_overflow
#define MUL_OVERFLOW_TEST __builtin_umulll_overflow
#elif ((PALISADE_NATIVEINT_BITS/8) == 8) && (__WORDSIZE == 64)
#define ADD_OVERFLOW_TEST __builtin_uaddl_overflow
#define SUB_OVERFLOW_TEST __builtin_usubl_overflow
#define MUL_OVERFLOW_TEST __builtin_umull_overflow
#else
#define ADD_OVERFLOW_TEST __builtin_uaddll_overflow
#define SUB_OVERFLOW_TEST __builtin_usubll_overflow
#define MUL_OVERFLOW_TEST __builtin_umulll_overflow
#endif

namespace native_int {

const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.

// a data structure to represent a double-word integer as two single-word integers
struct typeD {
   NativeInt hi, lo;
};


/**
 * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
 * @tparam NativeInt native unsigned integer type
 * @tparam BITLENGTH maximum bitdwidth supported for big integers
 */
class NativeInteger : public lbcrypto::BigIntegerInterface<NativeInteger>
{
public:
	/**
	 * Default constructor.
	 */
	NativeInteger() : m_value(0) {}

	/**
	 * Basic constructor for specifying the integer.
	 *
	 * @param str is the initial integer represented as a string.
	 */
	NativeInteger(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic constructor for initializing from an unsigned integer.
	 *
	 * @param init is the initial integer.
	 */
	NativeInteger(const NativeInt& init) : m_value(init) {}

#if ABSL_HAVE_INTRINSIC_INT128
	NativeInteger(const unsigned __int128& init) : m_value(init) {}
#endif

	/**
	 * Basic constructor for copying 
	 *
	 * @param bigInteger is the integer to be copied.
	 */
	NativeInteger(const NativeInteger& nInteger) : m_value(nInteger.m_value) {}

	NativeInteger(const lbcrypto::BigInteger& bi) : m_value(bi.ConvertToInt()) {}

    /**
     * Constructors from smaller basic types
     * @param init
     */
	NativeInteger(int init) : NativeInteger( uint64_t(init) ) {}
	NativeInteger(uint32_t init) : NativeInteger( uint64_t(init) ) {}
	NativeInteger(long init) : NativeInteger( uint64_t(init) ) {}
	NativeInteger(long long init) : NativeInteger( uint64_t(init) ) {}

    /**
     * Constructor from double is not permitted
     * @param d
     */
	NativeInteger(double d) __attribute__ ((deprecated("Cannot construct from a double")));

    /**
	 * Assignment operator
	 *
	 * @param &rhs is the integer to be assigned from.
	 * @return assigned ref.
	 */
	const NativeInteger&  operator=(const NativeInteger &rhs) {
		this->m_value = rhs.m_value;
		return *this;
	}

	/**
	 * Assignment operator
	 *
	 * @param &rhs is the integer to be assigned from.
	 * @return assigned BigInteger ref.
	 */
	const NativeInteger&  operator=(const NativeInteger &&rhs) {
		this->m_value = rhs.m_value;
		return *this;
	}

	/**
	 * Assignment operator from unsigned integer
	 *
	 * @param val is the unsigned integer value that is assigned.
	 * @return the assigned BigInteger ref.
	 */
	const NativeInteger& operator=(const NativeInt& val) {
		this->m_value = val;
		return *this;
	}

	/**
	 * Basic set method for setting the value of an integer
	 *
	 * @param str is the string representation of the integer to be copied.
	 */
	void SetValue(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic set method for setting the value of an integer
	 *
	 * @param a is the big binary integer representation of the big binary integer to be assigned.
	 */
	void SetValue(const NativeInteger& a) {
		m_value = a.m_value;
	}


	/**
	 * Returns the MSB location of the value.
	 *
	 * @return the index of the most significant bit.
	 */
	usint GetMSB() const { return lbcrypto::GetMSB64(this->m_value); }

	/**
	 * Converts the value to an int.
	 *
	 * @return the int representation of the value as usint.
	 */
	uint64_t ConvertToInt() const {
		return m_value;
	}

	/**
	 * Converts the value to an double.
	 *
	 * @return double representation of the value.
	 */
	double ConvertToDouble() const {
		return m_value;
	}

	//Arithmetic Operations

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	NativeInteger Plus(const NativeInteger& b) const {
		return NATIVEINT_DO_CHECKS ? PlusCheck(b) : PlusFast(b);
	}

	/**
	 * PlusCheck is the addition operation with bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	NativeInteger PlusCheck(const NativeInteger& b) const {
		NativeInt newv = m_value + b.m_value;
		if( newv < m_value || newv < b.m_value ) {
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		}
		return newv;
	}

	/**
	 * PlusFast is the addition operation without bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	NativeInteger PlusFast(const NativeInteger& b) const {
		return m_value + b.m_value;
	}

	/**
	 * Addition in place operation.
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	const NativeInteger& PlusEq(const NativeInteger& b) {
		return NATIVEINT_DO_CHECKS ? PlusEqCheck(b) : PlusEqFast(b);
	}

	/**
	 * PlusEqCheck is the addition in place operation with bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	const NativeInteger& PlusEqCheck(const NativeInteger& b) {
		NativeInt oldv = m_value;

		m_value += b.m_value;
		if( m_value < oldv ) {
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		}

		return *this;
	}

	/**
	 * PlusEqFast is the addition in place operation without bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	const NativeInteger& PlusEqFast(const NativeInteger& b) {
		m_value += b.m_value;
		return *this;
	}

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract from this
	 * @return result of the subtraction operation
	 */
	NativeInteger Minus(const NativeInteger& b) const {
		return NATIVEINT_DO_CHECKS ? MinusCheck(b) : MinusFast(b);
	}

	/**
	 * MinusCheck is the subtraction operation with bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	NativeInteger MinusCheck(const NativeInteger& b) const {
		return m_value <= b.m_value ? 0 : m_value - b.m_value;
	}

	/**
	 * MinusFast is the subtraction operation without bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	NativeInteger MinusFast(const NativeInteger& b) const {
		return m_value - b.m_value;
	}

	/**
	 * Subtraction in place operation.
	 *
	 * @param b is the value to subtract
	 * @return result of the subtraction operation
	 */
	const NativeInteger& MinusEq(const NativeInteger& b) {
		return NATIVEINT_DO_CHECKS ? MinusEqCheck(b) : MinusEqFast(b);
	}

	/**
	 * MinusEqCheck is the subtraction in place operation with bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	const NativeInteger& MinusEqCheck(const NativeInteger& b) {
		m_value = m_value <= b.m_value ? 0 : m_value - b.m_value;
		return *this;
	}

	/**
	 * MinusEqFast is the subtraction in place operation without bounds checking
	 *
	 * @param b is the value to add to this
	 * @return result of the addition operation
	 */
	const NativeInteger& MinusEqFast(const NativeInteger& b) {
		m_value -= b.m_value;
		return *this;
	}

	/**
	 * Multiplication operation.
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	NativeInteger Times(const NativeInteger& b) const {
		return NATIVEINT_DO_CHECKS ? TimesCheck(b) : TimesFast(b);
	}

	/**
	 * TimesCheck is the multiplication operation with bounds checking
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	NativeInteger TimesCheck(const NativeInteger& b) const {
		NativeInt prod = m_value * b.m_value;
		if( prod > 0 && (prod < m_value || prod < b.m_value) )
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		return prod;
	}

	/**
	 * TimesFast is the multiplication operation without bounds checking
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	NativeInteger TimesFast(const NativeInteger& b) const {
		return m_value * b.m_value;
	}

	/**
	 * Multiplication in place operation.
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	const NativeInteger& TimesEq(const NativeInteger& b) {
		return NATIVEINT_DO_CHECKS ? TimesEqCheck(b) : TimesEqFast(b);
	}

	/**
	 * TimesEqCheck is the multiplication in place operation with bounds checking
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	const NativeInteger& TimesEqCheck(const NativeInteger& b) {
		NativeInt oldval = m_value;

		m_value *= b.m_value;

		if( m_value < oldval )
			PALISADE_THROW( lbcrypto::math_error, "Overflow");

		return *this;
	}

	/**
	 * TimesEqFast is the multiplication in place operation without bounds checking
	 *
	 * @param b is the value to multiply with
	 * @return result of the multiplication operation
	 */
	const NativeInteger& TimesEqFast(const NativeInteger& b) {
		m_value *= b.m_value;
		return *this;
	}

	/**
	 * Division operation.
	 *
	 * @param b of type NativeInteger is the value to divide by.
	 * @return result of the division operation.
	 */
	NativeInteger DividedBy(const NativeInteger& b) const {
		if( b.m_value == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");
		return this->m_value / b.m_value;
	}

	/**
	 * Division operation.
	 *
	 * @param b of type NativeInteger is the value to divide by.
	 * @return result of the division operation.
	 */
	const NativeInteger& DividedByEq(const NativeInteger& b) {
		if( b.m_value == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");
		this->m_value /= b.m_value;
		return *this;
	}

	//modular arithmetic operations

	// subroutines and data types for fast native modular arithmetic

	/**
	 * Multiplies two single-word integers and stores the result in a typeD data structure
	 * Currently this is hard-coded to 64-bit words on a x86-64 processor
	 *
	 * @param a multiplier
	 * @param b multiplicand
	 * @param &x result of multiplication
	 */
	inline static void
	MultD(NativeInt a, NativeInt b, typeD& x)
	{
	   __asm__ (
	   "mulq %[b]" :
	   [lo] "=a" (x.lo), [hi] "=d" (x.hi) :
	   [a] "%[lo]" (a), [b] "rm" (b) :
	   "cc"
	   );
	}

	/**
	 * Extracts the high word of a two-word integer
	 *
	 * @param &x double-word input
	 * @return the high word
	 */
	inline static NativeInt
	GetDHi(const typeD& x)
	{
	   return x.hi;
	}

	/**
	 * Multiplies two single-word integers and stores the high word of the result
	 *
	 * @param a multiplier
	 * @param b multiplicand
	 * @return the high word of the result
	 */
	inline static NativeInt
	MultDHi(NativeInt a, NativeInt b)
	{
	  typeD x;
	  MultD(a, b, x);
	  return GetDHi(x);
	}

	/**
	 * Right shifts a typeD integer by a specific number of bits
	 * and stores the result as a single-word integer.
	 *
	 * @param &x double-word input
	 * @param shift the number of bits to shift by
	 * @return the result of right-shifting
	 */
	static NativeInt
	RShiftD(const typeD &x, long shift)
	{
	   	   return (x.lo >> shift) | (x.hi << (PALISADE_NATIVEINT_BITS-shift));
	}

	/**
	 * Converts a double-word integer from typeD representation
	 * to DNativeInt.
	 *
	 * @param &x double-word input
	 * @return the result as DNativeInt
	 */
	static inline DNativeInt
	GetD(const typeD& x)
	{
	   return (DNativeInt(x.hi) << PALISADE_NATIVEINT_BITS) | x.lo;
	}

	/**
	 * returns the modulus with respect to the input value
	 *
	 * @param modulus is value of the modulus to perform
	 * @return NativeInteger that is the result of the modulus operation.
	 */
	NativeInteger Mod(const NativeInteger& modulus) const {
		return m_value % modulus.m_value;
	}

	/**
	 * performs %=
	 *
	 * @param modulus is value of the modulus to perform
	 * @return NativeInteger that is the result of the modulus operation.
	 */
	const NativeInteger& ModEq(const NativeInteger& modulus) {
		m_value %= modulus.m_value;
		return *this;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Included here for compatibility with backend 2.
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->m_value%modulus.m_value;
	}

	/**
	* returns the modulus with respect to the input value - In place version.
	* Included here for compatibility with backend 2.
	*
	* @param modulus is the modulus to perform.
	* @param mu is the Barrett value.
	* @return is the result of the modulus operation.
	*/
	void ModBarrettInPlace(const NativeInteger& modulus, const NativeInteger& mu) {
		this->m_value %= modulus.m_value;
		return;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Included here for compatibility with backend 2.
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger mu_arr[BARRETT_LEVELS+1]) const {
		return this->m_value%modulus.m_value;
	}

	/**
	 * returns the modulus inverse with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return result of the modulus inverse operation.
	 */
	NativeInteger ModInverse(const NativeInteger& mod) const {

		NativeInt result = 0;
		NativeInt modulus = mod.m_value;

		std::vector<NativeInt> mods;
		std::vector<NativeInt> quotient;
		mods.push_back(modulus);
		if (this->m_value > modulus)
			mods.push_back(this->m_value%modulus);
		else
			mods.push_back(this->m_value);

		NativeInt first(mods[0]);
		NativeInt second(mods[1]);
		if(mods[1]==1){
			result = 1;
			return result;
		}

		//Zero does not have a ModInverse
		if(second == 0) {
			throw std::logic_error("Zero does not have a ModInverse");
		}


		//NORTH ALGORITHM
		while(true){
			mods.push_back(first%second);
			quotient.push_back(first/second);
			if(mods.back()==1)
				break;
			if(mods.back()==0){
				std::string msg = std::to_string(m_value) + " does not have a ModInverse using " + std::to_string(modulus);
				throw std::logic_error(msg);
			}

			first = second;
			second = mods.back();
		}

		mods.clear();
		mods.push_back(0);
		mods.push_back(1);

		first = mods[0];
		second = mods[1];

		//SOUTH ALGORITHM
		for(int i=quotient.size()-1;i>=0;i--){
			mods.push_back(quotient[i]*second + first);
			first = second;
			second = mods.back();
		}


		if(quotient.size()%2==1){
			result = (modulus - mods.back());
		}
		else{
			result = mods.back();
		}

		return result;
	}

    /**
     * Modulo addition.
     *
     * @param &b is the NativeInteger to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
	NativeInteger ModAdd(const NativeInteger& b, const NativeInteger& modulus) const {
        NativeInt op1 = m_value >= modulus.m_value ? m_value % modulus.m_value : m_value;
        NativeInt op2 = b.m_value >= modulus.m_value ? b.m_value % modulus.m_value : b.m_value;
        DNativeInt mod(modulus.m_value);
		DNativeInt modsum(op1);
		modsum += DNativeInt(op2);
		if (modsum >= mod)
			modsum %= mod;
		return NativeInteger(modsum);
	}

    /**
     * Modulo addition in place.
     *
     * @param &b is the NativeInteger to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
	const NativeInteger& ModAddEq(const NativeInteger& b, const NativeInteger& modulus) {
        NativeInt op1 = m_value >= modulus.m_value ? m_value % modulus.m_value : m_value;
        NativeInt op2 = b.m_value >= modulus.m_value ? b.m_value % modulus.m_value : b.m_value;
        DNativeInt mod(modulus.m_value);
		DNativeInt modsum(op1);
		modsum += DNativeInt(op2);
		if (modsum >= mod)
			modsum %= mod;
		*this = NativeInteger(modsum);
		return *this;
	}

    /**
     * Fast Modulo addition - assumes operands are already mod modulus,
     * and modulus is small enough that there will be no overflow
     *
     * @param &b is the NativeInteger to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
	inline NativeInteger ModAddFast(const NativeInteger& b, const NativeInteger& modulus) const {
        DNativeInt mod(modulus.m_value);
		DNativeInt modsum(m_value);
		modsum += DNativeInt(b.m_value);
		if (modsum >= mod)
			modsum %= mod;
		return NativeInteger(modsum);
	}

    /**
     * Fast modulo addition in place - assumes operands are already mod modulus,
     * and modulus is small enough that there will be no overflow
     *
     * @param &b is the NativeInteger to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
	const NativeInteger& ModAddFastEq(const NativeInteger& b, const NativeInteger& modulus) {
        DNativeInt mod(modulus.m_value);
		DNativeInt modsum(m_value);
		modsum += DNativeInt(b.m_value);
		if (modsum >= mod)
			modsum %= mod;
		*this = NativeInteger(modsum);
		return *this;
	}

	/**
	 * Fast modulo addition. Optimized version.
	 *
	 * @param &b is the NativeInteger to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	NativeInteger ModAddFastOptimized(const NativeInteger& b, const NativeInteger& modulus) const {
  		NativeInt r = this->m_value + b.m_value;
		return r>=modulus.m_value ? r-modulus.m_value : r;
	}

	/**
	 * Fast modulo addition in-place. Optimized version.
	 *
	 * @param &b is the NativeInteger to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	const NativeInteger& ModAddFastOptimizedEq(const NativeInteger& b, const NativeInteger& modulus) {
		this->m_value += b.m_value;
		this->m_value = this->m_value>=modulus.m_value ? this->m_value-modulus.m_value : this->m_value;
		return *this;
	}

	/**
	 * Modulo addition where Barrett modulo reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the NativeInteger to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->Plus(b).ModBarrett(modulus,mu_arr);
	}

	/**
	 * Modulo addition where Barrett modulo reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the NativeInteger to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is one precomputed Barrett value.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->Plus(b).ModBarrett(modulus,mu);
	}

    /**
     * Modulo subtraction.
     *
     * @param &b is the NativeInteger to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus subtraction operation.
     */
	NativeInteger ModSub(const NativeInteger& b, const NativeInteger& modulus) const {
		DNativeInt av(m_value);
		DNativeInt bv(b.m_value);
		DNativeInt mod(modulus.m_value);

		//reduce this to a value lower than modulus
		if(av >= mod) {
			av %= mod;
		}
		//reduce b to a value lower than modulus
		if(bv >= mod){
			bv %= mod;
		}

		if(av >= bv){
			return NativeInteger((av - bv) % mod);
		}
		else{
			return NativeInteger((av + mod) - bv);
		}
	}

    /**
     * Modulo subtraction in place.
     *
     * @param &b is the NativeInteger to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus subtraction operation.
     */
	const NativeInteger& ModSubEq(const NativeInteger& b, const NativeInteger& modulus) {
		// can't do in place, so...
		return *this = this->ModSub(b, modulus);
	}

	/**
	 * Fast modulo subtraction. Assumes both arguments are in [0,modulus-1].
	 *
	 * @param &b is the NativeInteger to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	inline NativeInteger ModSubFast(const NativeInteger& b, const NativeInteger& modulus) const {
		if(m_value >= b.m_value){
			return NativeInteger(m_value - b.m_value);
		}
		else{
			return NativeInteger((m_value + modulus.m_value) - b.m_value);
		}
	}

	/**
	 * Fast modulo subtraction in-place. Assumes both arguments are in [0,modulus-1].
	 *
	 * @param &b is the NativeInteger to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	const NativeInteger& ModSubFastEq(const NativeInteger& b, const NativeInteger& modulus) {
		if(m_value >= b.m_value){
			m_value -= b.m_value;
		}
		else{
			m_value += (modulus.m_value - b.m_value);
		}
		return *this;
	}

	/**
	 * Modulo subtraction where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the NativeInteger to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Modulo subtraction where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param b is the NativeInteger to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Modulo multiplication.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMul(const NativeInteger& b, const NativeInteger& modulus) const {
		DNativeInt av(m_value);
		DNativeInt bv(b.m_value);
		DNativeInt mod(modulus.m_value);

		if( av >= mod ) av %= mod;
		if( bv >= mod ) bv %= mod;

		DNativeInt result = av*bv;
		if( result >= mod ) result %= mod;

		return NativeInteger(result);
	}

	/**
	 * Modulo multiplication in place.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	const NativeInteger& ModMulEq(const NativeInteger& b, const NativeInteger& modulus) {
		return *this = this->ModMul(b, modulus);
	}

	/**
     * Fast Modulo multiplication - assumes operands are already mod modulus
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMulFast(const NativeInteger& b, const NativeInteger& modulus) const {
		DNativeInt av(m_value);
		DNativeInt bv(b.m_value);

		return NativeInteger((av*bv)%DNativeInt(modulus.m_value));
	}

	/**
	 * Fast Modulo multiplication in place.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	const NativeInteger& ModMulFastEq(const NativeInteger& b, const NativeInteger& modulus) {
		return *this = this->ModMulFast(b, modulus);
	}

	// Optimized modular multiplication subroutines

	/**
	 * Precomputes a parameter for generalized Barrett modular multiplication. Used by
	 * ModMulFastOptimized and ModMulFastEqOptimized.
	 *
	 * @return the precomputed parameter.
	 */
	NativeInteger ComputeMu() const {
		DNativeInt temp(1);
		temp <<= 2 * this->GetMSB() + 3;
		return NativeInt(temp / DNativeInt(this->m_value));
	}

	/**
	 * Modular multiplication using the generalized Barrett modular reduction algorithm.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param &modulus is the modulus to perform operations with.
	 * @param &mu precomputed Barrett modular reduction parameter.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMulFastOptimized(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) const {

		/* Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
		@article{knezevicspeeding,
		  title={Speeding Up Barrett and Montgomery Modular Multiplications},
		  author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
		}
		We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally
		proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail
		in the PhD thesis of the author published at
		http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
		We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
		Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
		We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3). The value of \mu
		is computed by NativeVector::ComputeMu.
		*/

		NativeInteger ans(*this);

		// handles cases when the multiplier is larger than the modulus
		// as Barrett's method requires this
		if (ans.m_value > modulus.m_value)
			ans.m_value %= modulus.m_value;

		typeD prod1;
		MultD(ans.m_value, b.m_value, prod1);
		DNativeInt prod = GetD(prod1);
		typeD qO(prod1);

		long n = modulus.GetMSB();
		long alpha = n + 3;
		long beta = -2;

		// RShiftD is more efficient than the right-shifting of DNativeInt
		NativeInt ql = RShiftD(qO,n + beta);
		MultD(ql, mu.m_value, qO);
		DNativeInt q = GetD(qO);

		// we cannot use RShiftD here because alpha - beta > 63
		// for q larger than 57 bits
		q >>= alpha - beta;
		prod -= q*DNativeInt(modulus.m_value);

		ans.m_value = NativeInt(prod);

		// correction at the end
		if (ans.m_value > modulus.m_value)
			ans.m_value -= modulus.m_value;

		return ans;

	}

	/**
	 * Modular multiplication in place using the generalized Barrett modular reduction algorithm.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param &modulus is the modulus to perform operations with.
	 * @param &mu precomputed Barrett modular reduction parameter.
	 * @return is the result of the modulus multiplication operation.
	 */
	void ModMulFastEqOptimized(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) {

		/* Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
		@article{knezevicspeeding,
		  title={Speeding Up Barrett and Montgomery Modular Multiplications},
		  author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
		}
		We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally
		proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail
		in the PhD thesis of the author published at
		http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
		We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
		Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
		We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3). The value of \mu
		is computed by NativeVector::ComputeMu.
		*/

		// handles cases when the multiplier is larger than the modulus
		// as Barrett's method requires this
		if (this->m_value > modulus.m_value)
			this->m_value %= modulus.m_value;

		typeD prod1;
		MultD(this->m_value, b.m_value, prod1);
		DNativeInt prod = GetD(prod1);
		typeD qO(prod1);

		long n = modulus.GetMSB();
		long alpha = n + 3;
		long beta = -2;

		// RShiftD is more efficient than the right-shifting of DNativeInt
		NativeInt ql = RShiftD(qO,n + beta);
		MultD(ql, mu.m_value, qO);
		DNativeInt q = GetD(qO);

		// we cannot use RShift128 here because alpha - beta > 63
		// for q larger than 57 bits
		q >>= alpha - beta;
		prod -= q*DNativeInt(modulus.m_value);

		this->m_value = NativeInt(prod);

		// correction at the end
		if (this->m_value > modulus.m_value)
			this->m_value -= modulus.m_value;

		return;
	}

	/*  The next three subroutines implement the modular multiplication algorithm for the case
		when the multiplicand is used multiple times (known in advance), as in NTT. The algorithm is described
		in https://arxiv.org/pdf/1205.2926.pdf (Dave Harvey, FASTER ARITHMETIC FOR NUMBER-THEORETIC
		TRANSFORMS). The algorithm is described in lines 5-7 of Algorithm 2. The algorithm was originally proposed and
		implemented in NTL (https://www.shoup.net/ntl/) by Victor Shoup.
	*/

	/**
	 * Modular multiplication using a precomputation for the multiplicand
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param &bInv precomputation for b.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMulPreconOptimized(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& bInv) const {
	   NativeInt q = MultDHi(this->m_value, bInv.m_value);
	   NativeInt yprime = this->m_value*b.m_value - q*modulus.m_value;
	   return SignedNativeInt(yprime)-SignedNativeInt(modulus.m_value) >= 0 ? yprime-modulus.m_value :  yprime;
	}

	/**
	 * Optimized modulo multiplication in place using a precomputation for the multiplicand. In-place version.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param &bInv precomputation for b.
	 * @return is the result of the modulus multiplication operation.
	 */
	const NativeInteger& ModMulPreconOptimizedEq(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& bInv) {
		NativeInt q = MultDHi(this->m_value, bInv.m_value);
		NativeInt yprime = this->m_value*b.m_value - q*modulus.m_value;
		this->m_value = SignedNativeInt(yprime)-SignedNativeInt(modulus.m_value) >= 0 ? yprime-modulus.m_value : yprime;
		return *this;
	}

	/**
	 * Precomputation for a multiplicand.
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @return the precomputed factor.
	 */
	const NativeInteger PrepModMulPreconOptimized(const NativeInteger& modulus) const {
		DNativeInt w = DNativeInt(this->m_value)<<64;
		return NativeInt(w / DNativeInt(modulus.m_value));
	}

	/**
	 * Modulo multiplication where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the precomputed Barrett value.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->ModMul(b,modulus);
	}

	/**
	* Modulo multiplication where Barrett modular reduction is used - In-place version
	* Included here for compatibility with backend 2.
	*
	* @param b is the NativeInteger to multiply.
	* @param modulus is the modulus to perform operations with.
	* @param mu is the precomputed Barrett value.
	* @return is the result of the modulus multiplication operation.
	*/
	void ModBarrettMulInPlace(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) {
		*this = this->ModMulFast(b,modulus);
		return;
	}

	/**
	 * Modulo multiplication where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the NativeInteger to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModMul(b,modulus);
	}

	/**
	 * Modulo exponentiation. Square-and-multiply algorithm is used.
	 *
	 * @param &b is the NativeInteger to exponentiate.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus exponentiation operation.
	 */
	NativeInteger ModExp(const NativeInteger& b, const NativeInteger& mod) const {
		DNativeInt exp(b.m_value);
		DNativeInt product(1);
		DNativeInt modulus(mod.m_value);
		DNativeInt mid(m_value % mod.m_value);
		const DNativeInt ZERO(0);
		const DNativeInt ONE(1);
		const DNativeInt TWO(2);

		while( true ) {
			if( exp%TWO == ONE )
				product = product * mid;

			//running product is calculated
			if(product >= modulus){
				product = product % modulus;
			}

			//divide by 2 and check even to odd to find bit value
			exp >>= 1;
			if(exp == ZERO)
				break;

			//mid calculates mid^2%q
			mid = mid*mid;

			mid = mid % modulus;
		}
		return NativeInteger(product);
	}

	//Shift Operators

	/**
	 * Left shift operator
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  LShift(usshort shift) const {
		return m_value << shift;
	}

	/**
	 * Left shift operator uses in-place algorithm and operates on the same variable.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	const NativeInteger&  LShiftEq(usshort shift) {
		m_value <<= shift;
		return *this;
	}

	/**
	 * Right shift operator
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  RShift(usshort shift) const {
		return m_value >> shift;
	}

	/**
	 * Right shift operator uses in-place algorithm and operates on the same variable.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	const NativeInteger&  RShiftEq(usshort shift) {
		m_value >>= shift;
		return *this;
	}

	/**
	 * Stores the based 10 equivalent/Decimal value of the NativeInteger in a string object and returns it.
	 *
	 * @return value of this NativeInteger in base 10 represented as a string.
	 */
	const std::string ToString() const {
		return std::to_string(m_value);
	}
	
    static const std::string IntegerTypeName() { return "NativeI"; }

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();}

	/**
	* Get a specific digit at "digit" index; big integer is seen as an array of digits, where a 0 <= digit < base
	*
	* @param index is the "digit" index of the requested digit
	* @param base is the base with which to determine length in.
	* @return is the requested digit
	*/
	usint GetDigitAtIndexForBase(usint index, usint base) const {

		usint DigitLen = ceil(log2(base));

		usint digit = 0;
		usint newIndex = 1 + (index - 1)*DigitLen;
		for (usint i = 1; i < base; i = i * 2)
		{
			digit += GetBitAtIndex(newIndex)*i;
			newIndex++;
		}
		return digit;
	}

	/**
	 * Convert a string representation of a binary number to a decimal BigInteger.
	 *
	 * @param bitString the binary num in string.
	 * @return the binary number represented as a big binary int.
	 */
	static NativeInteger BitStringToBigInteger(const std::string& bitString) {
		if( bitString.length() > m_uintBitLength ) {
			throw std::logic_error("Bit string is too long to fit in a native_int");
		}

		NativeInt v = 0;
		for( size_t i=0 ; i < bitString.length() ; i++ ) {
			int n = bitString[i] - '0';
			if( n < 0 || n > 1 ) {
				throw std::logic_error("Bit string must contain only 0 or 1");
			}

			v <<= 1;
			v |= n;
		}

		return v;
	}

	/**
	 * Exponentiation. Returns x^p
	 *
	 * @param p the exponent.
	 * @return the integer x^p.
	 */
	NativeInteger Exp(usint p) const {
		if (p == 0) return 1;
		if (p == 1) return *this;

		NativeInteger tmp = (*this).Exp(p/2);
		if (p%2 == 0) return tmp * tmp;
		else return tmp * tmp * (*this);
	}

	/**
	 * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding operation.
	 *
	 * @param p is the numerator to be multiplied.
	 * @param q is the denominator to be divided.
	 * @return the result of multiply and round.
	 */
	NativeInteger MultiplyAndRound(const NativeInteger &p, const NativeInteger &q) const {
		NativeInteger ans = m_value*p.m_value;
		return ans.DivideAndRound(q);
	}

	/**
	 * Computes the quotient of x*p/q, where x,p,q are all NativeInt numbers, x is the current value; uses DNativeInt arithmetic
	 *
	 * @param p is the multiplicand
	 * @param q is the divisor
	 * @return the quotient
	 */
	NativeInteger MultiplyAndDivideQuotient(const NativeInteger &p, const NativeInteger &q) const {
		DNativeInt xD = m_value;
		DNativeInt pD = p.m_value;
		DNativeInt qD = q.m_value;
		return NativeInteger(xD*pD/qD);
	}

	/**
	 * Computes the remainder of x*p/q, where x,p,q are all NativeInt numbers, x is the current value; uses DNativeInt arithmetic
	 *
	 * @param p is the multiplicand
	 * @param q is the divisor
	 * @return the remainder
	 */
	NativeInteger MultiplyAndDivideRemainder(const NativeInteger &p, const NativeInteger &q) const {
		DNativeInt xD = m_value;
		DNativeInt pD = p.m_value;
		DNativeInt qD = q.m_value;
		return NativeInteger((xD*pD)%qD);
	}

	/**
	 * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
	 *
	 * @param q is the denominator to be divided.
	 * @return the result of divide and round.
	 */
	NativeInteger DivideAndRound(const NativeInteger &q) const {

		if( q == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");

		NativeInt ans = m_value/q.m_value;
		NativeInt rem = m_value%q.m_value;
		NativeInt halfQ = q.m_value >> 1;

		if (!(rem <= halfQ)) {
			ans += 1;
		}

		return ans;
	}

	//overloaded binary operators based on integer arithmetic and comparison functions
	NativeInteger operator-() const { return NativeInteger(0).Minus(*this); }

	/**
	 * Console output operation.
	 *
	 * @param os is the std ostream object.
	 * @param ptr_obj is NativeInteger to be printed.
	 * @return is the ostream object.
	 */
	friend std::ostream& operator<<(std::ostream& os, const NativeInteger &ptr_obj) {
		os << ptr_obj.m_value;
		return os;
	}

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const {
		if(index==0) {
			throw std::logic_error("Zero index in GetBitAtIndex");
		}

		return (m_value >> (index-1)) & 0x01;
	}

	/**
	 * Gets the 6 bits at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return 6 bit pattern
	 */
	uschar Get6BitsAtIndex(usint index) const {
		return lbcrypto::get_6bits_atoffset(m_value, index);
	}

	/**
	 * Compares the current NativeInteger to NativeInteger a.
	 *
	 * @param a is the NativeInteger to be compared with.
	 * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
	 */
	int Compare(const NativeInteger& a) const {
		if( this->m_value < a.m_value )
			return -1;
		else if( this->m_value > a.m_value )
			return 1;
		return 0;
	}

	/**
	 *  Set this int to 1.
	 *  Note some compilers don't like using the ONE constant, above :(
	 */
	void SetIdentity() { this->m_value = 1; };

	/**
	 * A zero allocator that is called by the Matrix class.
	 * It is used to initialize a Matrix of NativeInteger objects.
	 */
	static NativeInteger Allocator() { return 0; }

	template <class Archive>
	void save( Archive & ar, std::uint32_t const version ) const
	{
		ar( ::cereal::make_nvp("v", m_value) );
	}

	template <class Archive>
	void load( Archive & ar, std::uint32_t const version )
	{
		if( version > SerializedVersion() ) {
			PALISADE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) + " is from a later version of the library");
		}
		ar( ::cereal::make_nvp("v", m_value) );
	}

	std::string SerializedObjectName() const { return "NativeInteger"; }
	static uint32_t	SerializedVersion() { return 1; }

protected:

	/**
	 * Converts the string v into base-r integer where r is equal to 2^bitwidth of integral data type.
	 *
	 * @param v The input string
	 */
	void AssignVal(const std::string& str) {
		NativeInt test_value = 0;
		m_value = 0;
		for( size_t i=0; i<str.length(); i++ ) {
			int v = str[i] - '0';
			if( v < 0 || v > 9 ) {
				throw std::logic_error("String contains a non-digit");
			}
			m_value *= 10;
			m_value += v;

			if( m_value < test_value ) {
				throw std::logic_error(str + " is too large to fit in this native integer object");
			}
			test_value = m_value;
		}
	}

private:

	// representation as a
	NativeInt m_value;

	//variable to store the bit width of the integral data type.
	static const uschar m_uintBitLength = PALISADE_NATIVEINT_BITS;

	//variable to store the maximum value of the integral data type.
	static const NativeInt m_uintMax = std::numeric_limits<NativeInt>::max();
};

}

#endif
