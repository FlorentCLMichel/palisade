// @file ckkspackedencoding.cpp
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "encoding/ckkspackedencoding.h"
#include "math/dftransfrm.h"

namespace lbcrypto {

std::vector<std::complex<double>> Conjugate(
    const std::vector<std::complex<double>> &vec) {
  uint32_t n = vec.size();
  std::vector<std::complex<double>> result(n);
  for (size_t i = 1; i < n; i++) {
    result[i] = {-vec[n - i].imag(), -vec[n - i].real()};
  }
  result[0] = {vec[0].real(), -vec[0].imag()};
  return result;
}

// Estimate standard deviation using the imaginary part of decoded vector z
// Compute m(X) - m(1/X) as a proxy for z - Conj(z) = 2*Im(z)
// vec is m(X) corresponding to z
// conjugate is m(1/X) corresponding to Conj(z)

double StdDev(const std::vector<std::complex<double>> &vec,
              const std::vector<std::complex<double>> &conjugate) {
  uint32_t Nh = vec.size();
  // ring dimension
  uint32_t n = Nh * 2;

  // extract the complex part using identity z - Conj(z) == 2*Im(z)
  // here we actually compute m(X) - m(1/X) corresponding to 2*Im(z).
  // we only need first Nh/2 + 1 components of the imaginary part
  // as the remaining Nh/2 - 1 components have a symmetry
  // w.r.t. components from 1 to Nh/2 - 1
  std::vector<std::complex<double>> complexValues(Nh / 2 + 1);
  for (size_t i = 0; i < Nh / 2 + 1; ++i) {
    complexValues[i] = vec[i] - conjugate[i];
  }

  // Calculate the mean
  auto mean_func = [](double accumulator, const std::complex<double> &val) {
    return accumulator + (val.real() + val.imag());
  };

  // use the symmetry condition
  double mean =
      2 * std::accumulate(complexValues.begin() + 1,
                          complexValues.begin() + Nh / 2, 0.0, mean_func);
  // and then add values at indices 0 and Nh/2
  mean += complexValues[0].imag();
  mean += 2 * complexValues[Nh / 2].real();
  // exclude the real part at index 0 as it is always 0
  mean /= static_cast<double>(n) - 1.0;

  // Now calculate the variance
  auto variance_func = [&mean](double accumulator,
                               const std::complex<double> &val) {
    return accumulator + (val.real() - mean) * (val.real() - mean) +
           (val.imag() - mean) * (val.imag() - mean);
  };

  // use the symmetry condition
  double variance =
      2 * accumulate(complexValues.begin() + 1, complexValues.begin() + Nh / 2,
                     0.0, variance_func);
  // and then add values at indices 0 and Nh/2
  variance +=
      (complexValues[0].imag() - mean) * (complexValues[0].imag() - mean);
  variance += 2 * (complexValues[Nh / 2].real() - mean) *
              (complexValues[Nh / 2].real() - mean);
  // exclude the real part at index 0 as it is always 0
  variance /= static_cast<double>(n) - 2.0;
  // scale down by 2 as we have worked with 2*Im(z) up to this point
  double stddev = 0.5 * std::sqrt(variance);

  return stddev;
}

std::vector<DCRTPoly::Integer> CKKSPackedEncoding::CRTMult(
    const std::vector<DCRTPoly::Integer> &a,
    const std::vector<DCRTPoly::Integer> &b,
    const std::vector<DCRTPoly::Integer> &mods) {
  std::vector<DCRTPoly::Integer> result(mods.size());

  for (usint i = 0; i < a.size(); i++) {
    result[i] = a[i].ModMulFast(b[i], mods[i]);
  }

  return result;
}

bool CKKSPackedEncoding::Encode() {
  if (this->isEncoded) return true;

  uint32_t Nh = (this->GetElementRingDimension() >> 1);

  std::vector<std::complex<double>> inverse = value;

  // clears all imaginary values as CKKS for complex numbers
  // is not supported
  for (size_t i = 0; i < inverse.size(); i++) inverse[i].imag(0.0);

  inverse.resize(Nh);
  DiscreteFourierTransform::FFTSpecialInv(inverse);

  if (this->typeFlag == IsDCRTPoly) {
    double powP = scalingFactor;

    // 2^63-2^9-1 - max value that could be round to int64_t
    int64_t q = 9223372036854775295;

    double dq = q;

    std::vector<int64_t> temp(this->GetElementRingDimension());
    size_t i, jdx, idx;
    int64_t re, im;
    double dre, dim;
    for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {
      // Check for possible overflow in llround function
      dre = inverse[i].real() * powP;
      dim = inverse[i].imag() * powP;
      if (std::abs(dre) >= dq || std::abs(dim) >= dq) {
        // IFFT formula:
        // x[n] = (1/N) * \Sum^(N-1)_(k=0) X[k] * exp( j*2*pi*n*k/N )
        // n is i
        // k is idx below
        // N is inverse.size()
        //
        // In the following, we switch to original data domain,
        // and we identify the component that has the maximum
        // contribution to the values in the iFFT domain. We do
        // this to report it to the user, so they can identify
        // large inputs.

        DiscreteFourierTransform::FFTSpecial(inverse);

        double invLen = static_cast<double>(inverse.size());
        double factor = 2 * M_PI * i;

        double realMax = -1, imagMax = -1;
        uint32_t realMaxIdx = -1, imagMaxIdx = -1;

        for (uint32_t idx = 0; idx < inverse.size(); idx++) {
          // exp( j*2*pi*n*k/N )
          std::complex<double> expFactor = {cos((factor * idx) / invLen),
                                            sin((factor * idx) / invLen)};

          // X[k] * exp( j*2*pi*n*k/N )
          std::complex<double> prodFactor = inverse[idx] * expFactor;

          double realVal = prodFactor.real();
          double imagVal = prodFactor.imag();

          if (realVal > realMax) {
            realMax = realVal;
            realMaxIdx = idx;
          }
          if (imagVal > imagMax) {
            imagMax = imagVal;
            imagMaxIdx = idx;
          }
        }

        auto scaledInputSize = ceil(log2(dre));

        std::stringstream buffer;
        buffer
            << std::endl
            << "Overflow in data encoding - scaled input is too large to fit "
               "into a NativeInteger (60 bits). Try decreasing scaling factor."
            << std::endl;
        buffer << "Overflow at slot number " << i << std::endl;
        buffer << "- Max real part contribution from input[" << realMaxIdx
               << "]: " << realMax << std::endl;
        buffer << "- Max imaginary part contribution from input[" << imagMaxIdx
               << "]: " << imagMax << std::endl;
        buffer << "Scaling factor is " << ceil(log2(powP)) << " bits "
               << std::endl;
        buffer << "Scaled input is " << scaledInputSize << " bits "
               << std::endl;

        PALISADE_THROW(math_error, buffer.str());
      }

      re = std::llround(dre);
      im = std::llround(dim);

      temp[idx] = (re < 0) ? q + re : re;
      temp[jdx] = (im < 0) ? q + im : im;
    }

    const shared_ptr<ILDCRTParams<BigInteger>> params =
        this->encodedVectorDCRT.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>> &nativeParams =
        params->GetParams();

    for (i = 0; i < nativeParams.size(); i++) {
      NativeVector nativeVec(this->GetElementRingDimension(),
                             nativeParams[i]->GetModulus());
      FitToNativeVector(temp, q, &nativeVec);
      NativePoly element = this->GetElement<DCRTPoly>().GetElementAtIndex(i);
      // output was in coefficient format
      element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
      this->encodedVectorDCRT.SetElementAtIndex(i, element);
    }

    usint numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
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
      if (std::abs(dre) >= dq || std::abs(dim) >= dq) {
        PALISADE_THROW(math_error,
                       "Overflow, try to decrease depth or plaintext modulus");
      }

      re = std::llround(dre);
      im = std::llround(dim);

      temp[idx] = (re < 0) ? NativeInteger(q + re) : NativeInteger(re);
      temp[jdx] = (im < 0) ? NativeInteger(q + im) : NativeInteger(im);
    }

    // output was in coefficient format
    this->GetElement<NativePoly>().SetValues(std::move(temp),
                                             Format::COEFFICIENT);
    this->GetElement<NativePoly>().SetFormat(Format::EVALUATION);

  } else {
    // Scale inverse by scaling factor
    double p = this->encodingParams->GetPlaintextModulus();
    double powP = pow(2, p * depth);

    const BigInteger &q = this->GetElementModulus();
    // min of q and 2^63-2^9-1 - max value
    // that could be round to int64_t
    double dq = std::min(9223372036854775295., q.ConvertToDouble());

    BigVector temp(this->GetElementRingDimension(), this->GetElementModulus());

    int64_t re, im;
    size_t i, jdx, idx;
    double dre, dim;
    for (i = 0, jdx = Nh, idx = 0; i < Nh; ++i, jdx++, idx++) {
      dre = inverse[i].real() * powP;
      dim = inverse[i].imag() * powP;
      // Check for possible overflow in llround function
      if (std::abs(dre) >= dq || std::abs(dim) >= dq) {
        PALISADE_THROW(math_error,
                       "Overflow, try to decrease depth or plaintext modulus");
      }

      re = std::llround(dre);
      im = std::llround(dim);

      temp[idx] = (re < 0) ? q - BigInteger(llabs(re)) : BigInteger(re);
      temp[jdx] = (im < 0) ? q - BigInteger(llabs(im)) : BigInteger(im);
    }

    // output was in coefficient format
    this->GetElement<Poly>().SetValues(std::move(temp), Format::COEFFICIENT);
    this->GetElement<Poly>().SetFormat(Format::EVALUATION);
  }
  this->isEncoded = true;
  return true;
}

bool CKKSPackedEncoding::Decode(size_t depth, double scalingFactor,
                                enum RescalingTechnique rsTech) {
  double p = encodingParams->GetPlaintextModulus();
  double powP = 0.0;
  uint32_t Nh = GetElementRingDimension() / 2;
  value.clear();

  std::vector<std::complex<double>> curValues(Nh);

  if (this->typeFlag == IsNativePoly) {
    if (rsTech == EXACTRESCALE)
      powP = pow(scalingFactor, -1);
    else
      powP = pow(2, -p);

    const NativeInteger &q = this->GetElementModulus().ConvertToInt();
    NativeInteger qHalf = q >> 1;

    for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {
      std::complex<double> cur;

      if (GetElement<NativePoly>()[idx] > qHalf)
        cur.real(-((q - GetElement<NativePoly>()[idx])).ConvertToDouble());
      else
        cur.real((GetElement<NativePoly>()[idx]).ConvertToDouble());

      if (GetElement<NativePoly>()[idx + Nh] > qHalf)
        cur.imag(-((q - GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
      else
        cur.imag((GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

      curValues[i] = cur;
    }
  } else {
    powP = pow(2, -p);

    // we will bring down the scaling factor to 2^p
    double scalingFactorPre = 0.0;
    if (rsTech == EXACTRESCALE)
      scalingFactorPre = pow(scalingFactor, -1) * pow(2, p);
    else
      scalingFactorPre = pow(2, -p * (depth - 1));

    const BigInteger &q = GetElementModulus();
    BigInteger qHalf = q >> 1;

    for (size_t i = 0, idx = 0; i < Nh; ++i, idx++) {
      std::complex<double> cur;

      if (GetElement<Poly>()[idx] > qHalf)
        cur.real(-((q - GetElement<Poly>()[idx])).ConvertToDouble() *
                 scalingFactorPre);
      else
        cur.real((GetElement<Poly>()[idx]).ConvertToDouble() *
                 scalingFactorPre);

      if (GetElement<Poly>()[idx + Nh] > qHalf)
        cur.imag(-((q - GetElement<Poly>()[idx + Nh])).ConvertToDouble() *
                 scalingFactorPre);
      else
        cur.imag((GetElement<Poly>()[idx + Nh]).ConvertToDouble() *
                 scalingFactorPre);

      curValues[i] = cur;
    }
  }

  // the code below adds a Gaussian noise to the decrypted result
  // to prevent key recovery attacks.
  // The standard deviation of the Gaussian noise is sqrt(M+1)*stddev,
  // where stddev is the standard deviation estimated using the imaginary
  // component and M is the extra factor that increases the number of decryption
  // attacks that is needed to average out the added Gaussian noise (after the
  // noise is removed, the attacker still has to find the secret key using the
  // real part only, which requires another attack). By default (M = 1), stddev
  // requires at least 128 decryption queries (in practice the values are
  // typically closer to 10,000 or so). Then M can be used to increase this
  // number further by M^2 (as desired for a given application). By default we
  // we set M to 1.

  // compute m(1/X) corresponding to Conj(z), where z is the decoded vector
  auto conjugate = Conjugate(curValues);

  // Estimate standard deviation from 1/2 (m(X) - m(1/x)),
  // which corresponds to Im(z)
  double stddev = StdDev(curValues, conjugate);

  double logstd = std::log2(stddev);

  // if stddev < sqrt{N}/8 (minimum approximation error that can be achieved)
  if (stddev < 0.125 * std::sqrt(GetElementRingDimension())) {
    stddev = 0.125 * std::sqrt(GetElementRingDimension());
  }

  // if stddev < sqrt{N}/4 (minimum approximation error that can be achieved)
  // if (stddev < 0.125 * std::sqrt(GetElementRingDimension())) {
  //   if (depth <= 1) {
  //    PALISADE_THROW(math_error,
  //                   "The decryption failed because the approximation error is
  //                   " "too small. Check the protocol used. ");
  //  } else {  // depth > 1 and no rescaling operations have been applied yet
  //    stddev = 0.125 * std::sqrt(GetElementRingDimension());
  //  }
  // }

  // If less than 3 decimal digits (10 bits) of precision is observed
  if (logstd > p - 10.0)
    PALISADE_THROW(math_error,
                   "The decryption failed because the approximation error is "
                   "too high. Check the protocol used. ");

  // real values
  std::vector<std::complex<double>> realValues(Nh);

  // CKKS_M_FACTOR is a compile-level parameter
  // set to 1 by default
  stddev = sqrt(CKKS_M_FACTOR + 1) * stddev;

  double scale = 0.5 * powP;

  std::normal_distribution<> d(0, stddev);
  PRNG &g = PseudoRandomNumberGenerator::GetPRNG();
  // Alternative way to do Gaussian sampling
  // DiscreteGaussianGenerator dgg;

  // TODO we can sample Nh integers instead of 2*Nh
  // We would add sampling only for even indices of i.
  // This change should be done together with the one below.
  for (size_t i = 0; i < Nh; ++i) {
    double real = scale * (curValues[i].real() + conjugate[i].real());
    // real += powP * dgg.GenerateIntegerKarney(0.0, stddev);
    real += powP * d(g);
    double imag = scale * (curValues[i].imag() + conjugate[i].imag());
    // imag += powP * dgg.GenerateIntegerKarney(0.0, stddev);
    imag += powP * d(g);
    realValues[i].real(real);
    realValues[i].imag(imag);
  }

  // TODO we can half the dimension for the FFT by decoding in
  // Z[X + 1/X]/(X^n + 1). This would change the complexity from n*logn to
  // roughly (n/2)*log(n/2). This change should be done together with the one
  // above.
  DiscreteFourierTransform::FFTSpecial(realValues);

  // clears all imaginary values for security reasons
  for (size_t i = 0; i < realValues.size(); ++i) realValues[i].imag(0.0);

  // sets an estimate of the approximation error
  m_logError = std::round(std::log2(stddev * std::sqrt(2 * Nh)));

  value = realValues;

  return true;
}

void CKKSPackedEncoding::Destroy() {}

void CKKSPackedEncoding::FitToNativeVector(const std::vector<int64_t> &vec,
                                           int64_t bigBound,
                                           NativeVector *nativeVec) const {
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

}  // namespace lbcrypto
