/**
 * @file gmpint.cpp  This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTL
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRI CT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 *
 * This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTLLL
 */


#ifdef WITH_NTL

#define _SECURE_SCL 0 // to speed up VS

#include <iostream>
#include <fstream>
#include <sstream>
#include "../backend.h"

#include "gmpint.h"

namespace NTL {

  // constant log2 of limb bitlength
  const usint myZZ::m_log2LimbBitLength = Log2<NTL_ZZ_NBITS>::value;

  myZZ::myZZ():ZZ() {SetMSB();}

  myZZ::myZZ(const NativeInteger& n) : myZZ(n.ConvertToInt()) {}

  myZZ::myZZ(uint64_t d): ZZ(0) {

    DEBUG_FLAG(false);
    static_assert(NTL_ZZ_NBITS != sizeof(uint64_t) , "can't compile gmpint on this architecture");
    
    DEBUGEXP(NTL_ZZ_NBITS);
    DEBUGEXP(sizeof(ZZ_limb_t));
    DEBUGEXP(NTL_BITS_PER_LONG);
    if (d==0)
      return;
    DEBUGEXP(sizeof(ZZ_limb_t));
    const ZZ_limb_t d1(d);
    ZZ_limbs_set(*this, &d1, 1);
    SetMSB();
  }
  myZZ::myZZ(const std::string &s): ZZ(conv<ZZ>(s.c_str())) {SetMSB();}
  myZZ::myZZ(const NTL::ZZ &a): ZZ(a) {SetMSB();}
  myZZ::myZZ(NTL::ZZ &&a) : ZZ() {this->swap(a);SetMSB();}
  void myZZ::SetValue(const std::string& str) 
  {
    *this = conv<ZZ>(str.c_str());
    SetMSB();
  }

  void myZZ::SetValue(const myZZ& a)
  {
    *this = a;
    SetMSB();
  }

  usint myZZ::GetMSB() const {
    //note: originally I did not worry about this, and just set the 
    //MSB whenever this was called, but then that violated constness in the 
    // various libraries that used this heavily
    //this->SetMSB(); //note no one needs to SetMSB()
    //return m_MSB;

    //SO INSTEAD I am just regenerating the MSB each time
    size_t sz = this->size();
    usint MSB;
    if (sz==0) { //special case for empty data
      MSB = 0;
      return(MSB);
    }

    MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.

    MSB+=tmp;
    m_MSB = MSB;
    return(MSB);
  }

  void myZZ::SetMSB()
  {

    size_t sz = this->size();
    if (sz==0) { //special case for empty data
      m_MSB = 0;
    }
    else {
    m_MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    //could also try
    //m_MSB = NumBytes(*this)*8;
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);

    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    m_MSB+=tmp;
  }
    return;
  }

 // inline static usint GetMSBLimb_t(ZZ_limb_t x){
  usint myZZ::GetMSBLimb_t( ZZ_limb_t x) const {
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  //Splits the binary string to equi sized chunks and then populates the internal array values.
  myZZ myZZ::FromBinaryString(const std::string& vin){
    DEBUG_FLAG(false);		// if true then print dbg output
    DEBUG("FromBinaryString");

    std::string v = vin;
    // strip off leading spaces from the input string
    v.erase(0, v.find_first_not_of(' '));
    // strip off leading zeros from the input string
    v.erase(0, v.find_first_not_of('0'));

    if (v.size() == 0) {
      //caustic case of input string being all zeros
      v = "0"; //set to one zero
    }

    myZZ value;
    //value.clear(); //clear out all limbs
    clear(value); //clear out all limbs

    usint len = v.length();
    ///new code here

    const unsigned int bitsPerByte = 8;
    //parse out string 8 bits at a time into array of bytes
    vector<unsigned char> bytes;

    DEBUG("input string: "<<v);
    DEBUG("len/bitsperbyte = "<<len/bitsPerByte);
    //reverse the string to make code easier
    std::reverse(v.begin(), v.end());
    DEBUG("reversedinput string: "<<v);

    DEBUG("len = "<<len);
    for (usint i = 0; i < len; i+=bitsPerByte){
      std::string bits = v.substr(0, bitsPerByte);
      //reverse the bits
      std::reverse(bits.begin(), bits.end());
      DEBUG("i = "<<i<<" bits: "<<bits);
      int newlen = v.length()-bitsPerByte;
      size_t nbits;
      DEBUG("newlen = "<<newlen);      
      unsigned char byte = std::stoi(bits, &nbits, 2);
      DEBUG("byte = "<<(unsigned int)byte);
      bytes.push_back(byte);
      if (newlen<1)
	break;
      v = v.substr(bitsPerByte, newlen);
      DEBUG("input string now: "<<v);
   }
    DEBUG("bytes size now "<<bytes.size());
    for (auto it = bytes.begin(); it != bytes.end(); ++it){
	DEBUG("bytes ="<< (unsigned int)(*it));
    }
    ZZFromBytes(value, bytes.data(), bytes.size());
    DEBUG("value ="<<value);    
    return(value);


  }

  myZZ myZZ::BitStringToBigInteger(const std::string& vin){ 
    myZZ ans;
    return ans.FromBinaryString(vin);
  }

  // utility function introduced in Backend 6 to get a subset of bits from a Bigint 
  usint myZZ::GetBitRangeAtIndex(usint ppo, usint length) const{
    long pin = ppo-1;
    long bl;
    long sa;
    _ntl_limb_t wh;
    
    if (pin < 0 || !this->rep) return 0;
    
    usint out(0);
    
    for (usint p = pin, i = 0; i<length; i++, p++){
      
      bl = p/NTL_ZZ_NBITS;
      wh = ((_ntl_limb_t) 1) << (p - NTL_ZZ_NBITS*bl);
      
      sa = this->size();
      if (sa < 0) sa = -sa;
      
      if (sa <= bl) {
	return out;
      }
      if (ZZ_limbs_get(*this)[bl] & wh) {
	out |= 1<<i;
      }
    }
    return out;
  }
  
  
  usint myZZ::GetDigitAtIndexForBase(usint index, usint base) const{
    DEBUG_FLAG(false);		// if true then print dbg output
    DEBUG("myZZ::GetDigitAtIndexForBase:  index = " << index
	  << ", base = " << base);

    usint DigitLen = std::ceil(log2(base));
    usint digit = 0;
    usint newIndex = 1 + (index - 1)*DigitLen;

    //newIndex 1 is lsb
    digit = GetBitRangeAtIndex(newIndex, DigitLen);
    DEBUG("digit = " << digit);
    return digit;
  }

  // returns the bit at the index into the binary format of the big integer, 
  // note that msb is 1 like all other bit indicies in PALISADE. 

  uschar myZZ::GetBitAtIndex(usint index) const{
    DEBUG_FLAG(false);		// if true then print dbg output
    DEBUG("myZZ::GetBitAtIndex(" << index << "), this=" << *this);
    return (uschar) GetBitRangeAtIndex( index, 1);
  }

  // returns a group of 6  bist at the index into the binary format of the big integer, 
  // note that msb is 1 like all other bit indicies in PALISADE. 

  uschar myZZ::Get6BitsAtIndex(usint index) const{
    DEBUG_FLAG(false);		// if true then print dbg output
    DEBUG("myZZ::Get6BitsAtIndex(" << index << "), this=" << *this);
    return (uschar) GetBitRangeAtIndex( index, 6);
  }

  //optimized ceiling function after division by number of bits in the limb data type.
  usint myZZ::ceilIntByUInt( const ZZ_limb_t Number){
    //mask to perform bitwise AND
    static ZZ_limb_t mask = NTL_ZZ_NBITS-1;

    if(!Number)
      return 1;

    if((Number&mask)!=0)
      return (Number>>m_log2LimbBitLength)+1;
    else
      return Number>>m_log2LimbBitLength;
  }

  //palisade conversion methods

   uint64_t myZZ::ConvertToInt() const{
     DEBUG_FLAG(false);

     DEBUG("in myZZ::ConvertToInt() this.size() "<<this->size());
     DEBUG("in myZZ::ConvertToInt() this "<<*this);

     std::stringstream s; //slower
     s <<*this;
     //uint64_t result = s.str().stoull();
     uint64_t result;
     s>>result;

     if ((this->GetMSB() > (sizeof(uint64_t)*8)) ||
 	(this->GetMSB() > NTL_ZZ_NBITS)) {
       std::cerr<<"Warning myZZ::ConvertToInt() Loss of precision. "<<std::endl;
       std::cerr<<"input  "<< *this<<std::endl;
       std::cerr<<"result  "<< result<<std::endl;
     }
     return result;
   }
    
  double myZZ::ConvertToDouble() const{ return (conv<double>(*this));}

  const myZZ& myZZ::operator=(const myZZ &rhs){

    if(this!=&rhs){
      _ntl_gcopy(rhs.rep, &(this->rep));
      this->m_MSB = rhs.m_MSB;
  }
    return *this;
  }

  std::ostream& operator<<(std::ostream& os, const myZZ& ptr_obj){
    DEBUG_FLAG(false);
    ZZ tmp = ptr_obj;
    DEBUG("in operator<< "<<tmp);

    os << tmp;
    return os;
  }
  
  const std::string myZZ::ToString() const
  {
    std::stringstream result("");
    result << *this;
    return result.str();
  }	

  myZZ myZZ::MultiplyAndRound(const myZZ &p, const myZZ &q) const
  {
    
    myZZ ans(*this);
    ans *= p;
    ans = ans.DivideAndRound(q);
    
    return ans;
    
  }
  myZZ myZZ::DivideAndRound(const myZZ &q) const 
  {
    DEBUG_FLAG(false);
    
    //check for garbage initialization and 0 condition
    //check for garbage initialization and 0 condition
    if(q==myZZ(0))
      throw std::logic_error("DivideAndRound() Divisor is zero");
    
    myZZ halfQ(q>>1);
    DEBUG("halfq "<<halfQ.ToString());
    
    if (*this < q) {
      if (*this <= halfQ)
	return myZZ(0);
      else
	return myZZ(1);
    }
    //=============
    myZZ ans(0);
    myZZ rv(0);
    
    
    DEBUG( "*this "<<this->ToString());
    DEBUG("q "<<q.ToString());
    
    
    DivRem(ans, rv, *this,q);
    
    //f = divqr_vect(ans, rv,  *this,  q);
    //if (f!= 0)
    ///throw std::logic_error("Divqr() error in DivideAndRound");
    
    //ans.NormalizeLimbs();
    //rv.NormalizeLimbs();
    
    ans.SetMSB();
    rv.SetMSB();
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    //==============
    //Rounding operation from running remainder
    if (!(rv <= halfQ)) {
      ans += myZZ(1);
      DEBUG("added1 ans "<<ans.ToString());
    }
    return ans;
  }
  
} // namespace NTL ends

#endif
