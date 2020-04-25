/*
 * @file ckks-dcrtpoly-impl.cpp - CKKS dcrtpoly implementation.
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

#define PROFILE

#include "cryptocontext.h"
#include "ckks.cpp"

namespace lbcrypto {

template class LPCryptoParametersCKKS<Poly>;
template class LPPublicKeyEncryptionSchemeCKKS<Poly>;
template class LPAlgorithmCKKS<Poly>;

template class LPCryptoParametersCKKS<NativePoly>;
template class LPPublicKeyEncryptionSchemeCKKS<NativePoly>;
template class LPAlgorithmCKKS<NativePoly>;

template class LPCryptoParametersCKKS<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeCKKS<DCRTPoly>;
template class LPAlgorithmCKKS<DCRTPoly>;
//template class LPFHEAlgorithmCKKS<DCRTPoly>;

#define NOPOLY \
		std::string errMsg = "CKKS PrecomputeCRTTables does not support Poly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY \
		std::string errMsg = "CKKS PrecomputeCRTTables does not support NativePoly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersCKKS<Poly>::PrecomputeCRTTables(KeySwitchTechnique ksTech, RescalingTechnique rsTech, uint32_t dnum){
	NOPOLY
}

template <>
bool LPCryptoParametersCKKS<NativePoly>::PrecomputeCRTTables(KeySwitchTechnique ksTech, RescalingTechnique rsTech, uint32_t dnum){
	NONATIVEPOLY
}


template<>
shared_ptr<vector<Poly>> LPAlgorithmSHECKKS<Poly>::EvalFastRotationPrecompute(
		ConstCiphertext<Poly> cipherText
		) const {

	std::string errMsg = "CKKS EvalFastRotationPrecompute does not support Poly. Use DCRTPoly instead."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<>
shared_ptr<vector<NativePoly>> LPAlgorithmSHECKKS<NativePoly>::EvalFastRotationPrecompute(
		ConstCiphertext<NativePoly> cipherText
		) const {

	std::string errMsg = "CKKS EvalFastRotationPrecompute does not support NativePoly. Use DCRTPoly instead."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<>
Ciphertext<Poly> LPAlgorithmSHECKKS<Poly>::EvalFastRotation(
		ConstCiphertext<Poly> cipherText,
		const usint index,
		const usint m,
		const shared_ptr<vector<Poly>> digits
		) const {

	std::string errMsg = "CKKS EvalFastRotation does not support Poly. Use DCRTPoly instead."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template<>
Ciphertext<NativePoly> LPAlgorithmSHECKKS<NativePoly>::EvalFastRotation(
		ConstCiphertext<NativePoly> cipherText,
		const usint index,
		const usint m,
		const shared_ptr<vector<NativePoly>> digits
		) const {

	std::string errMsg = "CKKS EvalFastRotation does not support NativePoly. Use DCRTPoly instead."; \
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
DecryptResult LPAlgorithmCKKS<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
	ConstCiphertext<Poly> ciphertext,
	Poly *plaintext) const
{
	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = privateKey->GetCryptoParameters();

	const std::vector<Poly> &c = ciphertext->GetElements();
	const Poly &s = privateKey->GetPrivateElement();

	Poly sPower = s;

	Poly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	Poly cTemp;
	for(size_t i=1; i<ciphertext->GetElements().size(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	b.SwitchFormat();

	*plaintext = b;

	return DecryptResult(plaintext->GetLength());
}

template <>
Ciphertext<NativePoly> LPAlgorithmCKKS<NativePoly>::Encrypt(const LPPublicKey<NativePoly> publicKey,
		NativePoly ptxt) const
{
	std::string errMsg = "LPAlgorithmCKKS<NativePoly>::Encrypt is not implemented for NativePoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}


template <>
Ciphertext<Poly> LPAlgorithmCKKS<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	std::string errMsg = "LPAlgorithmCKKS<Poly>::Encrypt is not implemented for Poly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<NativePoly> LPAlgorithmCKKS<NativePoly>::Encrypt(const LPPrivateKey<NativePoly> privateKey,
		NativePoly ptxt) const
{
	std::string errMsg = "LPAlgorithmCKKS<NativePoly>::Encrypt is not implemented for NativePoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<Poly> LPAlgorithmCKKS<Poly>::Encrypt(const LPPrivateKey<Poly> privateKey,
		Poly ptxt) const
{
	std::string errMsg = "LPAlgorithmCKKS<Poly>::Encrypt is not implemented for Poly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
DecryptResult LPAlgorithmCKKS<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
	ConstCiphertext<NativePoly> ciphertext,
	Poly *plaintext) const
{
	std::string errMsg = "CKKS: Decryption to Poly from NativePoly is not supported as it may lead to incorrect results."; \
			PALISADE_THROW(not_available_error, errMsg);

}

template <>
DecryptResult LPAlgorithmCKKS<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
	ConstCiphertext<Poly> ciphertext,
	NativePoly *plaintext) const
{
	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = privateKey->GetCryptoParameters();

	const std::vector<Poly> &c = ciphertext->GetElements();
	const Poly &s = privateKey->GetPrivateElement();

	Poly sPower = s;

	Poly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	Poly cTemp;
	for(size_t i=1; i<ciphertext->GetElements().size(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	b.SwitchFormat();

	*plaintext = b.ToNativePoly();

	return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmCKKS<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
	ConstCiphertext<NativePoly> ciphertext,
	NativePoly *plaintext) const
{
	const shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams = privateKey->GetCryptoParameters();

	const std::vector<NativePoly> &c = ciphertext->GetElements();
	const NativePoly &s = privateKey->GetPrivateElement();

	NativePoly sPower = s;

	NativePoly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	NativePoly cTemp;
	for(size_t i=1; i<ciphertext->GetElements().size(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	b.SwitchFormat();

	*plaintext = b;

	return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<Poly>::MultipartyDecryptFusion(const vector<Ciphertext<Poly>>& ciphertextVec,
		Poly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	//const auto p = cryptoParams->GetPlaintextModulus();

	const std::vector<Poly> &cElem = ciphertextVec[0]->GetElements();
	Poly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Poly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	b.SwitchFormat();

	*plaintext = b.CRTInterpolate();

	return DecryptResult(plaintext->GetLength());

}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<NativePoly>::MultipartyDecryptFusion(const vector<Ciphertext<NativePoly>>& ciphertextVec,
		Poly *plaintext) const
{
	std::string errMsg = "CKKS: Decryption to Poly from NativePoly is not supported as it may lead to incorrect results."; \
			PALISADE_THROW(not_available_error, errMsg);
}

template <>
bool LPAlgorithmParamsGenCKKS<Poly>::ParamsGen(
		shared_ptr<LPCryptoParameters<Poly>> cryptoParams,
		usint cyclOrder,
		usint numPrimes,
		usint scaleExp,
		usint relinWindow,
		MODE mode,
		KeySwitchTechnique ksTech,
		usint firstModSize,
		RescalingTechnique rsTech,
	    uint32_t numLargeDigits) const {

	std::string errMsg = "LPAlgorithmParamsGenCKKS<Poly>::ParamsGen is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}


template <>
bool LPAlgorithmParamsGenCKKS<NativePoly>::ParamsGen(
		shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams,
		usint cyclOrder,
		usint numPrimes,
		usint scaleExp,
		usint relinWindow,
		MODE mode,
		enum KeySwitchTechnique ksTech,
		usint firstModSize,
		RescalingTechnique rsTech,
		uint32_t numLargeDigits) const {

	std::string errMsg = "LPAlgorithmParamsGenCKKS<NativePoly>::ParamsGen is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}


template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmCKKS<Poly>::LevelReduceInternal(ConstCiphertext<Poly> cipherText1,
		const LPEvalKey<Poly> linearKeySwitchHint, size_t levels)  const {

	std::string errMsg = "LPLeveledSHEAlgorithmCKKS<Poly>::LevelReduceInternal is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}


template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmCKKS<NativePoly>::LevelReduceInternal(ConstCiphertext<NativePoly> cipherText1,
		const LPEvalKey<NativePoly> linearKeySwitchHint, size_t levels)  const {

	std::string errMsg = "LPLeveledSHEAlgorithmCKKS<NativePoly>::LevelReduceInternal is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmCKKS<Poly>::ModReduceInternal(ConstCiphertext<Poly> cipherText) const {

	std::string errMsg = "LPLeveledSHEAlgorithmCKKS<Poly>::ModReduceInternal is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmCKKS<NativePoly>::ModReduceInternal(ConstCiphertext<NativePoly> cipherText) const {

	std::string errMsg = "LPLeveledSHEAlgorithmCKKS<NativePoly>::ModReduceInternal is only supported for DCRTPoly.";
	PALISADE_THROW(not_implemented_error, errMsg);
}

#define NODCRTPOLY \
		std::string errMsg = "CKKS does not support DCRTPoly. Use NativePoly/Poly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

// Precomputation of CRT tables encryption, decryption, and homomorphic multiplication
template <>
bool LPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables(
		KeySwitchTechnique ksTech,
		RescalingTechnique rsTech,
		uint32_t numLargeDigits){

	/*
	 * Overview:
	 *
	 * 1. Get ring dimension and number of moduli in main CRT basis
	 * 2. Construct moduliQ and rootsQ from crypto parameters
	 * 3. Initialize DFT values and pre-compute CRT::FFT values for Q
	 * 4. Pre-compute omega values for rescaling in RNS
	 *
	 * 5. Select number of primes in auxiliary CRT basis
	 * 6. Choose special primes in auxiliary basis and compute their roots
	 * 7. Create the moduli and roots for the extended CRT basis QP
	 * 8. Pre-compute CRT::FFT values for P
	 * 9. Pre-compute values P mod q_j
	 * 10. Pre-compute values P^{-1} mod q_j for all j.
	 * 11. Pre-compute values \hat{p_i} mod q_j
	 * 12. Pre-compute values \hat{p_i}^-1 mod p_i
	 * 13. Pre-compute values \hat{q_{l,j}} mod p_i
	 * 14. Pre-compute values \hat{q_{l,j}}^-1 mod q_j
	 * 15. Pre-compute Barrett mu for 128-bit by 64-bit reduction
	 * 16. Pre-compute scaling factors for each level (for EXACTRESCALE)
	 *
	 * For 5-15 see "A full RNS variant of approximate homomorphic encryption"
	 * by Cheon, et. al.
	 *
	 * For clarity, we maintain a separate index for HYBRID key switching
	 * (some entries are shared with GHS):
	 *
	 * H.1. Compute alpha = ceil((L+1)/dnum), the # of towers per digit
	 * H.2. Compute the composite big moduli Qi for each digit i
	 * H.3. Compute QHat value as QHat_i = Prod_{j!=i}(Qj)
	 * H.4. Pre-compute QHat mod qi and QHat^-1 mod qi values for fast basis conversion
	 * H.5. Compute partitions of qi into dnum digits, to aid in computing the complementary bases for fast basis conversion
	 * H.6 Find number and size of individual special primes.
	 * H.7. Choose special primes in auxiliary basis and compute their roots
	 * H.8. Create the moduli and roots for the extended CRT basis QP
	 * H.9. Pre-compute CRT::FFT values for P
	 * H.10 Pre-compute values P mod q_j
	 * H.11. Pre-compute values P^{-1} mod q_j for all j.
	 * H.12. Pre-compute values \hat{p_i} mod q_j
	 * H.13. Pre-compute values \hat{p_i}^-1 mod p_i
	 * H.14. Pre-compute values \hat{q_{l,j}} mod p_i
	 * H.15. Pre-compute values \hat{q_{l,j}}^-1 mod q_j
	 * H.16. Pre-compute Barrett mu for 128-bit by 64-bit reduction
	 * H.17. Pre-compute compementary partitions for ModUp
	 * H.18. Pre-compute Barrett mu for 128-bit by 64-bit reduction
	 * H.19. Pre-compute values \hat{q_{l,j}} mod p_i for each Ck
	 * H.20. Pre-compute values \hat{q_{l,j}}^-1 mod q_j for each Ck
	 * H.21. Pre-compute Barrett mu for 128-bit by 64-bit reduction
	 * H.22. Pre-compute QHat mod complementary partition qi's
	 *
	 * For H.* see "Better bootstrapping for approximate homomorphic encryption"
	 * by Han and Ki.
	 *
	 */

	// Set the key switching technique. This determines what CRT values we
	// need to precompute.
	this->m_ksTechnique = ksTech;
	this->m_rsTechnique = rsTech;
	this->m_dnum = numLargeDigits;

	// 1. Get ring dimension (n) and number of moduli in main CRT basis (numPrimesQ)
	size_t numPrimesQ = GetElementParams()->GetParams().size();
	size_t n = GetElementParams()->GetRingDimension();


	// 2. Construct moduliQ and rootsQ from crypto parameters
	vector<NativeInteger> moduliQ(numPrimesQ);
	vector<NativeInteger> rootsQ(numPrimesQ);
	for (size_t i = 0; i < numPrimesQ; i++){
		moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
		rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
	}
	BigInteger modulusQ = GetElementParams()->GetModulus();

	// 3. Pre-compute CRT::FFT values for Q
	DiscreteFourierTransform::Initialize(n*2,n/2);
	ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2*n, moduliQ);

	// 4. Pre-compute omega values for rescaling in RNS
	// modulusQ holds Q_l = Product_{i=0}^{i=l}(q_i).
	for (size_t k = 0; k < numPrimesQ-1; k++)
	{
		modulusQ = modulusQ/BigInteger(moduliQ[numPrimesQ-(k+1)]);
		std::vector<NativeInteger> multInt(numPrimesQ-(k+1));
		BigInteger qInverse = modulusQ.ModInverse(moduliQ[numPrimesQ-(k+1)]);
		BigInteger result = (qInverse*modulusQ)/BigInteger(moduliQ[numPrimesQ-(k+1)]);
		for( usint i = 0 ; i < numPrimesQ - (k+1); i++ ) {
			multInt[i] = result.Mod(moduliQ[i]).ConvertToInt();
		}
		m_omega.push_back(multInt);
	}

	if (this->m_ksTechnique == HYBRID) {
		// H.1. Compute alpha = ceil((L+1)/dnum), the # of towers per digit
		uint32_t a = ceil((double)numPrimesQ/this->m_dnum);
		if ( (int32_t)(numPrimesQ - a*(this->m_dnum-1)) <= 0) {
			auto str = "LLPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables - HYBRID key " \
					"switching parameters: Can't appropriately distribute " + to_string(numPrimesQ) +
					" towers into " + to_string(this->m_dnum) +
					" digits. Please select different number of digits.";
			PALISADE_THROW(config_error, str);
		}

		this->m_numTowersPerDigit = a;

		// H.2. Compute the composite big moduli Qi for each digit i
		BigInteger bigQ = BigInteger(1);
		this->m_compositeQ = vector<BigInteger>(this->m_dnum, BigInteger(1));
//		cerr << "HYBRID - Composite moduli: " << endl;
		for (usint j = 0; j < this->m_dnum; j++) {
			//compositeModuli[j] = BigInteger(1);
			for (usint i = a*j; i < (j+1)*a; i++) {
				if (i < moduliQ.size())
					this->m_compositeQ[j] *= moduliQ[i];
			}
			bigQ *= this->m_compositeQ[j];
//			cerr << "\t Q[" << j << "]: " << this->m_compositeQ[j] << " (bits: " << this->m_compositeQ[j].GetLengthForBase(2) << ")" << endl;
		}

		// H.3. Compute QHat value as QHat_i = Prod_{j!=i}(Qj)
		this->m_compositeQHat = vector<BigInteger>(this->m_dnum, BigInteger(1));
//		cerr << "HYBRID - Products QHat: " << endl;
		for (size_t i = 0; i < this->m_dnum; i++) {
			for (size_t j = 0; j < this->m_dnum; j++) {
				if (j != i)
					this->m_compositeQHat[i] *= this->m_compositeQ[j];
			}
//			cerr << "\t QHat[" << i << "]: " << this->m_compositeQHat[i] << " (bits: " << this->m_compositeQHat[i].GetLengthForBase(2) << ")" << endl;
		}

		// H.4. Pre-compute QHat mod qi and QHat^-1 mod qi values for fast basis conversion
		this->m_compositeQHatModqi = vector<vector<NativeInteger>>(this->m_dnum);
		this->m_compositeQHatInvModqi = vector<vector<NativeInteger>>(this->m_dnum);
//		cerr << "HYBRID - Precomputed products QHat mod qi and QHat^-1 mod qi: " << endl;
		for (uint32_t j = 0; j < this->m_dnum; j++) {
			this->m_compositeQHatModqi[j] = vector<NativeInteger>(numPrimesQ, 0);
			this->m_compositeQHatInvModqi[j] = vector<NativeInteger>(numPrimesQ, 0);
			for (uint32_t i = 0; i < numPrimesQ; i++) {
				this->m_compositeQHatModqi[j][i] = this->m_compositeQHat[j].Mod(moduliQ[i]).ConvertToInt();
				if (i >= j*a && i <= ((j+1)*a-1)) {
//					cerr << "\t QHat[" << j << "] mod q[" << i << "]: " << this->m_compositeQHatModqi[j][i] << endl;
					this->m_compositeQHatInvModqi[j][i] = this->m_compositeQHat[j].ModInverse(moduliQ[i]).ConvertToInt();
//					cerr << "\t QHat[" << j << "]^-1 mod q[" << i << "]: " << this->m_compositeQHatInvModqi[j][i] << endl;
				}
			}
		}

		// H.5. Compute partitions of qi into dnum digits
		this->m_partitionsModuliC = vector<shared_ptr<ILDCRTParams<BigInteger>>>(this->m_dnum);
//		cerr << "HYBRID - Partitions: " << endl;
		for (uint32_t j=0; j<this->m_dnum; j++) {
//			cerr << "\t - partition C[" << j << "]: " << endl;
			auto startTower = j*a;
			auto endTower = ((j+1)*a-1 < numPrimesQ) ? (j+1)*a-1 : numPrimesQ - 1;
			vector<shared_ptr<ILNativeParams>> params = GetElementParams()->GetParamPartition(startTower, endTower);
			vector<NativeInteger> moduli(params.size());
			vector<NativeInteger> roots(params.size());
			for (uint32_t i=0; i<params.size(); i++) {
				moduli[i] = params[i]->GetModulus();
				roots[i] = params[i]->GetRootOfUnity();
//				cerr << "\t - " << moduli[i] << endl;
			}
			this->m_partitionsModuliC[j] =
					std::make_shared<ILDCRTParams<BigInteger>>(
							ILDCRTParams<BigInteger>(params[0]->GetCyclotomicOrder(),
							moduli, roots, {}, {}, BigInteger(0)));
		}
	}


	// Reset modulusQ to Q = q0*q1*...*q_L. This is because
	// the code following this statement requires modulusQ.
	modulusQ = GetElementParams()->GetModulus();

	size_t PModSize = 60;
	uint32_t numPrimesP = 1;

	if (this->m_ksTechnique == GHS) {
		// 5. Select number and size of special primes in auxiliary CRT basis
		PModSize = 60;
		uint32_t qBits = modulusQ.GetLengthForBase(2);
		numPrimesP = ceil((double)qBits/PModSize);
	} if (this->m_ksTechnique == HYBRID) {
		// H.6. Find number and size of individual special primes.
		uint32_t maxBits = this->m_compositeQ[0].GetLengthForBase(2);
		for (usint j = 1; j < this->m_dnum; j++) {
			uint32_t bits = this->m_compositeQ[j].GetLengthForBase(2);
			if ( bits > maxBits )
				maxBits = bits;
		}
		uint32_t largerDigitSize = maxBits;

		// Select number of primes in auxiliary CRT basis
		PModSize = 60;
		numPrimesP = ceil((double)largerDigitSize/PModSize);
	}

	if ( this->m_ksTechnique == GHS ||
		 this->m_ksTechnique == HYBRID ) {

		// 6./H.7. Choose special primes in auxiliary basis and compute their roots
		// moduliP holds special primes p1, p2, ..., pk
		// m_modulusP holds the product of special primes P = p1*p2*...pk
		vector<NativeInteger> moduliP(numPrimesP);
		vector<NativeInteger> rootsP(numPrimesP);
		// firstP contains a prime whose size is PModSize.
		NativeInteger firstP = FirstPrime<NativeInteger>(PModSize, 2 * n);
		NativeInteger pPrev = firstP;
		m_modulusP = BigInteger(1);
		for (usint i = 0; i < numPrimesP; i++) {
			// The following loop makes sure that moduli in
			// P and Q are different
			bool foundInQ = false;
			do {
				moduliP[i] = PreviousPrime<NativeInteger>(pPrev, 2 * n);
				foundInQ = false;
				for (usint j=0; j < numPrimesQ; j++)
					if (moduliP[i] == moduliQ[j])
						foundInQ = true;
				pPrev = moduliP[i];
			} while (foundInQ);
			rootsP[i] = RootOfUnity<NativeInteger>(2 * n, moduliP[i]);
			m_modulusP *= moduliP[i];
			pPrev = moduliP[i];
		}

		// Store the created moduli and roots in m_paramsP
		m_paramsP = shared_ptr<ILDCRTParams<BigInteger>>(
				new ILDCRTParams<BigInteger>( 2 * n,
											moduliP,
											rootsP));

		// 7./H.8. Create the moduli and roots for the extended CRT basis QP
		vector<NativeInteger> moduliExpanded(numPrimesQ + numPrimesP);
		vector<NativeInteger> rootsExpanded(numPrimesQ + numPrimesP);
		for (size_t i = 0; i < numPrimesQ; i++ ) {
			moduliExpanded[i] = moduliQ[i];
			rootsExpanded[i] = rootsQ[i];
		}
		for (size_t i = 0; i < numPrimesP; i++ ) {
			moduliExpanded[numPrimesQ + i] = moduliP[i];
			rootsExpanded[numPrimesQ + i] = rootsP[i];
		}

		m_paramsQP = shared_ptr<ILDCRTParams<BigInteger>>(
				new ILDCRTParams<BigInteger>( 2 * n,
									moduliExpanded,
									rootsExpanded));

		// 8./H.9. Pre-compute CRT::FFT values for P
		ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsP, 2*n, moduliP);

		// 9./H.10 Pre-compute values P mod q_j
		m_pModQj = vector<NativeInteger>(numPrimesQ, 0);
		for (usint j = 0; j < numPrimesQ; j++) {
			m_pModQj[j] = m_modulusP.Mod(moduliQ[j]).ConvertToInt();
		}

		// 10./H.11. Pre-compute values P^{-1} mod q_j for all j.
		m_pInvModQj = vector<NativeInteger>(numPrimesQ);
		m_pInvModQjPrecon = vector<NativeInteger>(numPrimesQ);
		for (size_t j=0; j<numPrimesQ; j++) {
			BigInteger pInvModQj = m_modulusP.ModInverse(moduliQ[j]);
			m_pInvModQj[j] = pInvModQj.ConvertToInt();
			m_pInvModQjPrecon[j] = m_pInvModQj[j].PrepModMulConst(moduliQ[j]);
		}

		// 11./H.12. Pre-compute values \hat{p_i} mod q_j
		// 12./H.13. Pre-compute values \hat{p_i}^-1 mod p_i
		m_pHatInvModPi = vector<NativeInteger>(numPrimesP);
		m_pHatInvModPiPrecon = vector<NativeInteger>(numPrimesP);
		m_pHatModQj = vector<vector<NativeInteger>>(numPrimesP);

		for (size_t i=0; i<numPrimesP; i++) {
			BigInteger pHat = m_modulusP/BigInteger(moduliP[i]);
			BigInteger pHatInvModPi = pHat.ModInverse(moduliP[i]);
			m_pHatModQj[i] = vector<NativeInteger>(numPrimesQ);
			m_pHatInvModPi[i] = pHatInvModPi.ConvertToInt();
			m_pHatInvModPiPrecon[i] = m_pHatInvModPi[i].PrepModMulConst(moduliP[i]);
			for (size_t j=0; j<numPrimesQ; j++) {
				BigInteger pHatModQj = pHat.Mod(moduliQ[j]);
				m_pHatModQj[i][j] = pHatModQj.ConvertToInt();
			}
		}

		// 13./H.14 Pre-compute values \hat{q_{l,j}} mod p_i
		// 14./H.15 Pre-compute values \hat{q_{l,j}}^-1 mod q_j
		m_qHatInvModQj = vector<vector<NativeInteger>>(numPrimesQ);
		m_qHatInvModQjPrecon = vector<vector<NativeInteger>>(numPrimesQ);
		m_qHatModPi = vector<vector<vector<NativeInteger>>>(numPrimesQ);
		// l will run from 0 to size-2, but modulusQ values
		// run from Q_{L-1} to Q_{0}
		for (size_t l=0; l<numPrimesQ; l++) {
			if (l > 0)
				modulusQ = modulusQ/BigInteger(moduliQ[numPrimesQ-l]);

			m_qHatInvModQj[numPrimesQ-l-1] = vector<NativeInteger>(numPrimesQ-l);
			m_qHatInvModQjPrecon[numPrimesQ-l-1] = vector<NativeInteger>(numPrimesQ-l);
			m_qHatModPi[numPrimesQ-l-1] = vector<vector<NativeInteger>>(numPrimesQ-l);

			for (size_t j=0; j<numPrimesQ-l; j++) {
				m_qHatModPi[numPrimesQ-l-1][j] = vector<NativeInteger>(numPrimesP);
				BigInteger qHat = modulusQ/BigInteger(moduliQ[j]);
				BigInteger qHatInvModQj = qHat.ModInverse(moduliQ[j]);
				m_qHatInvModQj[numPrimesQ-l-1][j] = qHatInvModQj.ConvertToInt();
				m_qHatInvModQjPrecon[numPrimesQ-l-1][j] = m_qHatInvModQj[numPrimesQ-l-1][j].PrepModMulConst(moduliQ[j]);
				for (size_t i=0; i<numPrimesP; i++) {
					BigInteger qHatModPi = qHat.Mod(moduliP[i]);
					m_qHatModPi[numPrimesQ-l-1][j][i] = qHatModPi.ConvertToInt();
				}
			}
		}

		// 15./H.16. Pre-compute Barrett mu for 128-bit by 64-bit reduction
		const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456"); // 2^128
		const BigInteger TwoPower64("18446744073709551616"); // 2^64
		m_modBarrettPreconP = vector<DoubleNativeInt>(numPrimesP);
		for (uint32_t i = 0; i< moduliP.size(); i++ )
		{
			BigInteger mu = BarrettBase128Bit/BigInteger(moduliP[i]);
			uint64_t val[2];
			val[0] = (mu % TwoPower64).ConvertToInt();
			val[1] = mu.RShift(64).ConvertToInt();

			memcpy(&m_modBarrettPreconP[i], val, sizeof(DoubleNativeInt));
		}
		m_modBarrettPreconQ = vector<DoubleNativeInt>(numPrimesQ);
		for (uint32_t i = 0; i< moduliQ.size(); i++ )
		{
			BigInteger mu = BarrettBase128Bit/BigInteger(moduliQ[i]);
			uint64_t val[2];
			val[0] = (mu % TwoPower64).ConvertToInt();
			val[1] = mu.RShift(64).ConvertToInt();

			memcpy(&m_modBarrettPreconQ[i], val, sizeof(DoubleNativeInt));
		}

//		std::cerr << "PrecomputeCRTTables - modulusP: " << m_modulusP << " (bit size: " << m_modulusP.GetLengthForBase(2) << ")" << std::endl;
//		for (size_t i = 0; i < numPrimesP; i++){
//			std::cerr << "\t moduliP[" << i << "]: " << moduliP[i] << " (bit size: " << moduliP[i].GetLengthForBase(2) << ")" << endl;
//		}

		if (this->m_ksTechnique == HYBRID) {

			// H.17. Pre-compute compementary partitions for ModUp
			uint32_t alpha = ceil((double) numPrimesQ/this->m_dnum);
			this->m_complementaryPartitions = vector<vector<shared_ptr<ILDCRTParams<BigInteger>>>>(numPrimesQ);
			this-> m_modBarrettPreconComplPartition = vector<vector<vector<DoubleNativeInt>>>(numPrimesQ);
			for (int32_t l = numPrimesQ-1; l >= 0; l--) {
				uint32_t beta = ceil((double)(l+1)/alpha);
				this->m_complementaryPartitions[l] = vector<shared_ptr<ILDCRTParams<BigInteger>>>(beta);
				this->m_modBarrettPreconComplPartition[l] = vector<vector<DoubleNativeInt>>(beta);

				for (uint32_t j=0; j<beta; j++) {
					const shared_ptr<ILDCRTParams<BigInteger>> digitPartition = this->GetQPartition(j);
					auto cyclOrder = digitPartition->GetCyclotomicOrder();

					uint32_t digitPartitionSize = digitPartition->GetParams().size();
					if (j == beta - 1)
						digitPartitionSize = (l+1) - j*alpha;
					// Compl basis size = (l+1) - digitPartition.size() + numPrimesP
					uint32_t complementaryBasisSize = (l+1) - digitPartitionSize + numPrimesP;

					vector<NativeInteger> moduli(complementaryBasisSize);
					vector<NativeInteger> roots(complementaryBasisSize);
//					cerr << "Complementary basis[" << l << "][" << j << "]: " << endl;
					for (uint32_t k=0; k<complementaryBasisSize; k++) {
						if (k < (l+1) - digitPartitionSize ) {
							uint32_t currDigit = k / alpha;
							if (currDigit >= j)
								currDigit++;
							moduli[k] = this->GetQPartition(currDigit)->GetParams()[k % alpha]->GetModulus();
							roots[k] = this->GetQPartition(currDigit)->GetParams()[k % alpha]->GetRootOfUnity();
						} else {
							moduli[k] = moduliP[k - ( (l+1) - digitPartitionSize )];
							roots[k] = rootsP[k - ( (l+1) - digitPartitionSize )];
						}
//						cerr << "\t - moduli[" << k << "]: " << moduli[k] << endl;
					}
					const shared_ptr<typename DCRTPoly::Params> params =
						         make_shared<typename DCRTPoly::Params>(
								   DCRTPoly::Params(cyclOrder, moduli, roots, {}, {}, 0));
					this->m_complementaryPartitions[l][j] = params;

					// H.18. Pre-compute Barrett mu for 128-bit by 64-bit reduction
					const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456"); // 2^128
					const BigInteger TwoPower64("18446744073709551616"); // 2^64
					m_modBarrettPreconComplPartition[l][j] = vector<DoubleNativeInt>(moduli.size());
					for (uint32_t i = 0; i< moduli.size(); i++ ) {
						BigInteger mu = BarrettBase128Bit/BigInteger(moduli[i]);
						uint64_t val[2];
						val[0] = (mu % TwoPower64).ConvertToInt();
						val[1] = mu.RShift(64).ConvertToInt();

						memcpy(&m_modBarrettPreconComplPartition[l][j][i], val, sizeof(DoubleNativeInt));
					}
				}
			}

			// H.19. Pre-compute values \hat{q_{l,j}} mod p_i for each Ck
			// H.20. Pre-compute values \hat{q_{l,j}}^-1 mod q_j for each Ck
			this->m_partitionQHatInvModQj = vector<vector<vector<NativeInteger>>>(this->m_dnum);
			this->m_partitionQHatInvModQjPrecon = vector<vector<vector<NativeInteger>>>(this->m_dnum);
			for (uint32_t k=0; k<this->m_dnum; k++) {
				auto params = this->m_partitionsModuliC[k]->GetParams();
				uint32_t partNumPrimesQ = params.size();
				this->m_partitionQHatInvModQj[k] = vector<vector<NativeInteger>>(partNumPrimesQ);
				this->m_partitionQHatInvModQjPrecon[k] = vector<vector<NativeInteger>>(partNumPrimesQ);
				auto modulusPartQ = this->m_partitionsModuliC[k]->GetModulus();

				for (size_t l=0; l<partNumPrimesQ; l++) {
					if (l > 0)
						modulusPartQ = modulusPartQ/BigInteger(params[partNumPrimesQ-l]->GetModulus());

					this->m_partitionQHatInvModQj[k][partNumPrimesQ-l-1] = vector<NativeInteger>(partNumPrimesQ-l);
					this->m_partitionQHatInvModQjPrecon[k][partNumPrimesQ-l-1] = vector<NativeInteger>(partNumPrimesQ-l);
					for (uint32_t totalTowers=0; totalTowers<numPrimesQ; totalTowers++) {

						for (size_t j=0; j<partNumPrimesQ-l; j++) {
							BigInteger qHat = modulusPartQ/BigInteger(params[j]->GetModulus());
//							cout << "HYBRID - qHat[" << k << "][" << partNumPrimesQ-l-1 << "][" << j << "]: " << qHat << endl;
							BigInteger qHatInvModQj = qHat.ModInverse(params[j]->GetModulus());
							this->m_partitionQHatInvModQj[k][partNumPrimesQ-l-1][j] = qHatInvModQj.ConvertToInt();
							this->m_partitionQHatInvModQjPrecon[k][partNumPrimesQ-l-1][j] = this->m_partitionQHatInvModQj[k][partNumPrimesQ-l-1][j].PrepModMulConst(params[j]->GetModulus());
//							cout << "HYBRID - qHat^-1 mod qj[" << k << "][" << partNumPrimesQ-l-1 <<
//								"][" << j << "]: " << this->m_partitionQHatInvModQj[k][partNumPrimesQ-l-1][j] << endl;
						}
					}
				}

				// H.21. Pre-compute Barrett mu for 128-bit by 64-bit reduction
				const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456"); // 2^128
				const BigInteger TwoPower64("18446744073709551616"); // 2^64
				this->m_modBarrettPreconPartitionQ = vector<DoubleNativeInt>(partNumPrimesQ);
				for (uint32_t i = 0; i<partNumPrimesQ; i++ )
				{
					BigInteger mu = BarrettBase128Bit/BigInteger(params[i]->GetModulus());
					uint64_t val[2];
					val[0] = (mu % TwoPower64).ConvertToInt();
					val[1] = mu.RShift(64).ConvertToInt();

					memcpy(&this->m_modBarrettPreconPartitionQ[i], val, sizeof(DoubleNativeInt));
				}
			}

			// H.22. Pre-compute QHat mod complementary partition qi's
//			cerr << "m_partitionQHatModPi:" << endl;
			this->m_partitionQHatModPi = vector<vector<vector<vector<NativeInteger>>>>(numPrimesQ);
			for (uint32_t l=0; l<numPrimesQ; l++) {
				uint32_t alpha = ceil((double) numPrimesQ/this->m_dnum);
				uint32_t beta = ceil((double)(l+1)/alpha);
				this->m_partitionQHatModPi[l] = vector<vector<vector<NativeInteger>>>(beta);
				for (uint32_t k=0; k<beta; k++) {
					auto partition = this->GetQPartition(k)->GetParams();
					auto Q = this->GetQPartition(k)->GetModulus();
					uint32_t digitSize = partition.size();
					if (k == beta - 1) {
						digitSize = l + 1 - k*alpha;
						for (uint32_t idx=digitSize; idx<partition.size(); idx++) {
							Q = Q / BigInteger(partition[idx]->GetModulus());
						}
					}

					this->m_partitionQHatModPi[l][k] = vector<vector<NativeInteger>>(digitSize);
					for (uint32_t j=0; j<digitSize; j++) {
						BigInteger qHat = Q/BigInteger(partition[j]->GetModulus());
						auto complBasis = this->GetComplementaryPartition(l, k);
						this->m_partitionQHatModPi[l][k][j] = vector<NativeInteger>(complBasis->GetParams().size());
						for (size_t i=0; i<complBasis->GetParams().size(); i++) {
							BigInteger qHatModPi = qHat.Mod(complBasis->GetParams()[i]->GetModulus());
//							cerr << "\t\t\t qHatModPi[" << l << "][" << k << "][" << j << "][" << i << "]: " << qHatModPi <<
//									" mod " << complBasis->GetParams()[i]->GetModulus() << endl;
							this->m_partitionQHatModPi[l][k][j][i] = qHatModPi.ConvertToInt();
						}
					}
				}
			}
		}

	}

//	std::cerr << "PrecomputeCRTTables - modulusQ: " << GetElementParams()->GetModulus() << " (bit size: " << GetElementParams()->GetModulus().GetLengthForBase(2) << ")" << std::endl;
//	for (size_t i = 0; i < numPrimesQ; i++){
//		std::cerr << "\t moduliQ[" << i << "]: " << moduliQ[i] << " (bit size: " << moduliQ[i].GetLengthForBase(2) << ")" << endl;
//	}

	// 16. Pre-compute scaling factors for each level (used in EXACT rescaling technique)
	if ( this->m_rsTechnique == EXACTRESCALE ) {
		uint32_t numLevels = numPrimesQ;

		this->m_scalingFactors = vector<double>(numLevels);
		this->m_scalingFactors[0] = moduliQ[ moduliQ.size()-1 ].ConvertToDouble();

//std::cerr << "Scaling factors: " << std::endl;
//std::cerr << std::setprecision(8) << std::fixed << "\t level " << 0 << ": " << this->m_scalingFactors[0] << " (ratio to q_L: " << 1.0 << ")" << std::endl;
		for (uint32_t k = 1; k < numLevels; k++) {
			// SF_n = (SF_n-1)^2 / q_(L-n)
			double tmp = this->m_scalingFactors[k-1]/moduliQ[ moduliQ.size()-k ].ConvertToDouble();
			this->m_scalingFactors[k] = tmp * this->m_scalingFactors[k-1];
			double ratio = this->m_scalingFactors[k]/this->m_scalingFactors[0];
			if (ratio <= 0.5 || ratio >= 2.0)
				PALISADE_THROW(config_error, "LPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables - EXACTRESCALE cannot support this number of levels in this parameter setting. Please use APPROXRESCALE.");
//std::cerr << std::setprecision(8) << std::fixed << "\t level " << k << ": " << this->m_scalingFactors[k] << " (ratio to q_L: " << ratio << ")" << std::endl;
		}
	}

	return true;
}

template <>
bool LPAlgorithmParamsGenCKKS<DCRTPoly>::ParamsGen(
					   shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams,
					   usint cyclOrder,
					   usint numPrimes,
					   usint scaleExp,
					   usint relinWindow,
					   MODE mode,
					   enum KeySwitchTechnique ksTech,
					   usint firstModSize,
					   RescalingTechnique rsTech,
					   uint32_t numLargeDigits) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsCKKS =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(cryptoParams);

	//// HE Standards compliance logic/check
	SecurityLevel stdLevel = cryptoParamsCKKS->GetStdLevel();
	uint32_t PModSize = 60;
	uint32_t n = cyclOrder/2;
	uint32_t qBound = 0;
	// Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
	if (ksTech == BV) {
		qBound = firstModSize + (numPrimes-1)*scaleExp;
	} else if (ksTech == GHS) {
		qBound = firstModSize + (numPrimes-1)*scaleExp;
		qBound += ceil(((double)qBound)/PModSize)*PModSize;
	} else if (ksTech == HYBRID) {
		qBound = firstModSize + (numPrimes-1)*scaleExp;
		qBound += ceil(ceil(((double)qBound)/numLargeDigits)/PModSize)*60;
	}

	//RLWE security constraint
	DistributionType distType = (cryptoParamsCKKS->GetMode() == RLWE) ? HEStd_error : HEStd_ternary;
	auto nRLWE = [&](usint q) -> uint32_t {
		return StdLatticeParm::FindRingDim(
					distType,
					stdLevel,
					q);
	};

	// Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
	if (stdLevel != HEStd_NotSet) {
		if (n==0) {
			// Case 2: SecurityLevel specified, but ring dimension not specified

			// Choose ring dimension based on security standards
			n = nRLWE(qBound);
			cyclOrder = 2*n;
		} else { // if (n!=0)
			// Case 3: Both SecurityLevel and ring dimension specified

			// Check whether particular selection is standards-compliant
			auto he_std_n = nRLWE(qBound);
			if (he_std_n > n) {
				PALISADE_THROW(config_error,
					"The specified ring dimension (" + to_string(n) +
					") does not comply with HE standards recommendation (" +
					to_string(he_std_n) + ")." );
			}
		}
	} else if (n==0)
		PALISADE_THROW(config_error,
				"Please specify the ring dimension or desired security level." );
	//// End HE Standards compliance logic/check

	usint dcrtBits = scaleExp;

	vector<NativeInteger> init_moduli(numPrimes);
	vector<NativeInteger> init_rootsOfUnity(numPrimes);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, cyclOrder);
	init_moduli[numPrimes-1] = q;
	init_rootsOfUnity[numPrimes-1] = RootOfUnity(cyclOrder, init_moduli[numPrimes-1]);

	NativeInteger qNext = q;
	NativeInteger qPrev = q;
	if ( numPrimes > 1 ) {
		if ( rsTech == APPROXRESCALE ) {
			uint32_t cnt = 0;
			for (usint i = numPrimes-2; i >= 1; i--) {
				if ((cnt % 2) == 0) {
					qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
					q = qPrev;
				}
				else
				{
					qNext = lbcrypto::NextPrime(qNext, cyclOrder);
					q = qNext;
				}

				init_moduli[i] = q;
				init_rootsOfUnity[i] = RootOfUnity(cyclOrder, init_moduli[i]);
				cnt++;
			}
		} else { // EXACTRESCALE

			/* Scaling factors in EXACTRESCALE are a bit fragile, in the sense that
			 * once one scaling factor gets far enough from the original scaling
			 * factor, subsequent level scaling factors quickly diverge to either 0
			 * or infinity. To mitigate this problem to a certain extend, we have a
			 * special prime selection process in place. The goal is to maintain the
			 * scaling factor of all levels as close to the original scale factor of
			 * level 0 as possible.
			*/

			double sf = init_moduli[numPrimes-1].ConvertToDouble();
			uint32_t cnt = 0;
			for (usint i = numPrimes-2; i >= 1; i--) {

				sf = (double) pow(sf, 2)/init_moduli[i+1].ConvertToDouble();
				if ((cnt % 2) == 0) {
					NativeInteger sfInt = std::llround(sf);
					NativeInteger sfRem = sfInt.Mod(cyclOrder);
					NativeInteger qPrev = sfInt - NativeInteger(cyclOrder) - sfRem + NativeInteger(1);

					bool hasSameMod = true;
					while (hasSameMod) {
						hasSameMod = false;
						qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
						for (uint32_t j=i+1; j<numPrimes; j++) {
							if (qPrev == init_moduli[j]) {
								hasSameMod = true;
							}
						}
					}
					init_moduli[i] = qPrev;

				} else {

					NativeInteger sfInt = std::llround(sf);
					NativeInteger sfRem = sfInt.Mod(cyclOrder);
					NativeInteger qNext = sfInt + NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
					bool hasSameMod = true;
					while (hasSameMod) {
						hasSameMod = false;
						qNext = lbcrypto::NextPrime(qNext, cyclOrder);
						for (uint32_t j=i+1; j<numPrimes; j++) {
							if (qNext == init_moduli[j]) {
								hasSameMod = true;
							}
						}
					}
					init_moduli[i] = qNext;

				}

				init_rootsOfUnity[i] = RootOfUnity(cyclOrder, init_moduli[i]);
				cnt++;
			}
		}
	}


	if (firstModSize == dcrtBits) { // this requires dcrtBits < 60
		init_moduli[0] = PreviousPrime<NativeInteger>(qPrev, cyclOrder);
	} else {
		NativeInteger firstInteger = FirstPrime<NativeInteger>(firstModSize, cyclOrder);
		init_moduli[0] = PreviousPrime<NativeInteger>(firstInteger, cyclOrder);
	}
	init_rootsOfUnity[0] = RootOfUnity(cyclOrder, init_moduli[0]);


	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(
							new ILDCRTParams<BigInteger>(
									cyclOrder,
									init_moduli,
									init_rootsOfUnity));

	cryptoParamsCKKS->SetElementParams(paramsDCRT);

	// if no batch size was specified, we set batchSize = n/2 by default (for full packing)
	const EncodingParams encodingParams = cryptoParamsCKKS->GetEncodingParams();
	if (encodingParams->GetBatchSize() == 0)
	{
		uint32_t batchSize = n/2;
		EncodingParams encodingParamsNew(new EncodingParamsImpl(encodingParams->GetPlaintextModulus(),batchSize));
		cryptoParamsCKKS->SetEncodingParams(encodingParamsNew);
	}

	return cryptoParamsCKKS->PrecomputeCRTTables(ksTech, rsTech, numLargeDigits);

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmCKKS<DCRTPoly>::Encrypt(const LPPublicKey<DCRTPoly> publicKey,
		DCRTPoly ptxt) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(publicKey->GetCryptoParameters());

	Ciphertext<DCRTPoly> ciphertext(new CiphertextImpl<DCRTPoly>(publicKey));

	const shared_ptr<typename DCRTPoly::Params> ptxtParams = ptxt.GetParams();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	typename DCRTPoly::TugType tug;

	ptxt.SetFormat(EVALUATION);

	std::vector<DCRTPoly> cVector;

	DCRTPoly v;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		v = DCRTPoly(dgg, ptxtParams, Format::EVALUATION);
	else
		v = DCRTPoly(tug, ptxtParams, Format::EVALUATION);

	DCRTPoly e0(dgg, ptxtParams, Format::EVALUATION);
	DCRTPoly e1(dgg, ptxtParams, Format::EVALUATION);

	uint32_t ptxtTowers = ptxtParams->GetParams().size();
	uint32_t pkTowers = publicKey->GetPublicElements()[0].GetParams()->GetParams().size();

	DCRTPoly c0, c1;
	if (ptxtTowers != pkTowers) {
		// Clone public keys because we need to drop towers.
		DCRTPoly b = publicKey->GetPublicElements().at(0).Clone();
		DCRTPoly a = publicKey->GetPublicElements().at(1).Clone();

		int towerDiff = pkTowers - ptxtTowers;
		b.DropLastElements(towerDiff);
		a.DropLastElements(towerDiff);

		c0 = b*v + e0 + ptxt;
		c1 = a*v + e1;
	} else {
		// Use public keys as they are
		const DCRTPoly &b = publicKey->GetPublicElements().at(0);
		const DCRTPoly &a = publicKey->GetPublicElements().at(1);

		c0 = b*v + e0 + ptxt;
		c1 = a*v + e1;
	}

	cVector.push_back(std::move(c0));

	cVector.push_back(std::move(c1));

	ciphertext->SetElements(std::move(cVector));

	// Ciphertext depth, level, and scaling factor should be
	// equal to that of the plaintext. However, Encrypt does
	// not take Plaintext as input (only DCRTPoly), so we
	// don't have access to these here, and we set them in
	// the crypto context Encrypt method.
	ciphertext->SetDepth(1);

	return ciphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmCKKS<DCRTPoly>::Encrypt(const LPPrivateKey<DCRTPoly> privateKey,
		DCRTPoly ptxt) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(privateKey->GetCryptoParameters());

	Ciphertext<DCRTPoly> ciphertext(new CiphertextImpl<DCRTPoly>(privateKey));

	const shared_ptr<typename DCRTPoly::Params> ptxtParams = ptxt.GetParams();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	ptxt.SetFormat(EVALUATION);

	std::vector<DCRTPoly> cVector;

	DCRTPoly e(dgg, ptxtParams, Format::EVALUATION);

	uint32_t ptxtTowers = ptxtParams->GetParams().size();
	uint32_t skTowers = privateKey->GetPrivateElement().GetParams()->GetParams().size();

	typename DCRTPoly::DugType dug;
	DCRTPoly a(dug, ptxtParams, Format::EVALUATION);

	DCRTPoly c0, c1;
	if (ptxtTowers != skTowers) {

		int towerDiff = skTowers - ptxtTowers;

		DCRTPoly s = privateKey->GetPrivateElement().Clone();

		s.DropLastElements(towerDiff);

		c0 = a*s + e + ptxt;
		c1 = -a;

	} else {
		// Use secret key as is
		const DCRTPoly &s = privateKey->GetPrivateElement();

		c0 = a*s + e + ptxt;
		c1 = -a;

	}

	cVector.push_back(std::move(c0));

	cVector.push_back(std::move(c1));

	ciphertext->SetElements(std::move(cVector));

	// Ciphertext depth, level, and scaling factor should be
	// equal to that of the plaintext. However, Encrypt does
	// not take Plaintext as input (only DCRTPoly), so we
	// don't have access to these here, and we set them in
	// the crypto context Encrypt method.
	ciphertext->SetDepth(1);

	return ciphertext;

}

template <>
DecryptResult LPAlgorithmCKKS<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
	ConstCiphertext<DCRTPoly> ciphertext,
	Poly *plaintext) const
	{

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = privateKey->GetCryptoParameters();

		const std::vector<DCRTPoly> &c = ciphertext->GetElements();

		LPPrivateKey<DCRTPoly> sk(privateKey);

		size_t towersToDrop = sk->GetPrivateElement().GetParams()->GetParams().size() - c[0].GetParams()->GetParams().size();

		auto s(sk->GetPrivateElement());
		s.DropLastElements(towersToDrop);

		DCRTPoly sPower = s;

		DCRTPoly b = c[0];
		if(b.GetFormat() == Format::COEFFICIENT)
			b.SwitchFormat();

		DCRTPoly cTemp;
		for(size_t i=1; i<ciphertext->GetElements().size(); i++){
			cTemp = c[i];
			if(cTemp.GetFormat() == Format::COEFFICIENT)
				cTemp.SwitchFormat();

			b += sPower*cTemp;
			sPower *= s;
		}

		// in coefficient representation
		b.SwitchFormat();

		if (b.GetParams()->GetParams().size() > 1)
			*plaintext = b.CRTInterpolate();
		else
		{
			if (b.GetParams()->GetParams().size() == 1)
				*plaintext = Poly(b.GetElementAtIndex(0),COEFFICIENT);
			else
				PALISADE_THROW(math_error, "Decryption failure: No towers left; consider increasing the depth.");
		}

		return DecryptResult(plaintext->GetLength());
	}

template <>
DecryptResult LPAlgorithmCKKS<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
	ConstCiphertext<DCRTPoly> ciphertext,
	NativePoly *plaintext) const
	{

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = privateKey->GetCryptoParameters();

		const std::vector<DCRTPoly> &c = ciphertext->GetElements();

		LPPrivateKey<DCRTPoly> sk(privateKey);

		size_t towersToDrop = sk->GetPrivateElement().GetParams()->GetParams().size() - c[0].GetParams()->GetParams().size();

		auto s(sk->GetPrivateElement());
		s.DropLastElements(towersToDrop);

		DCRTPoly sPower = s;

		DCRTPoly b = c[0];
		if(b.GetFormat() == Format::COEFFICIENT)
			b.SwitchFormat();

		DCRTPoly cTemp;
		for(size_t i=1; i<ciphertext->GetElements().size(); i++){
			cTemp = c[i];
			if(cTemp.GetFormat() == Format::COEFFICIENT)
				cTemp.SwitchFormat();

			b += sPower*cTemp;
			sPower *= s;
		}

		// in coefficient representation
		b.SwitchFormat();

		if (b.GetParams()->GetParams().size() == 1)
			*plaintext = b.GetElementAtIndex(0);
		else
			PALISADE_THROW(math_error, "Decryption failure: No towers left; consider increasing the depth.");

		return DecryptResult(plaintext->GetLength());
	}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchHybridGen(
		const LPPrivateKey<DCRTPoly> oldKey,
		const LPPrivateKey<DCRTPoly> newKey) const {

	auto cc = newKey->GetCryptoContext();
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> paramsQ = cryptoParamsLWE->GetElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsQP = cryptoParamsLWE->GetExtendedElementParams();

	DCRTPoly s1 = oldKey->GetPrivateElement();
	DCRTPoly s2 = newKey->GetPrivateElement().Clone();

	// s2 is currently in basis Q. This extends it to basis QP.
	s2.SetFormat(Format::COEFFICIENT);
	DCRTPoly ext_s2(paramsQP, Format::COEFFICIENT, true);
	for (usint i=0; i<paramsQP->GetParams().size(); i++) {
		if (i < paramsQ->GetParams().size())
			ext_s2.SetElementAtIndex(i, s2.GetElementAtIndex(i));
		else {
			NativeInteger mod_i = paramsQP->GetParams()[i]->GetModulus();
			NativeInteger ru_i = paramsQP->GetParams()[i]->GetRootOfUnity();
			auto s2_i = s2.GetElementAtIndex(0);
			s2_i.SwitchModulus(mod_i, ru_i);
			ext_s2.SetElementAtIndex(i, s2_i);
		}
	}
	ext_s2.SetFormat(Format::EVALUATION);

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	auto dnum = cryptoParamsLWE->GetNumberOfDigits();
	vector<DCRTPoly> av(dnum);
	vector<DCRTPoly> bv(dnum);

	vector<NativeInteger> PModQj = cryptoParamsLWE->GetPModQTable();
	vector<vector<NativeInteger>> QHatModqj = cryptoParamsLWE->GetQHatModqTable();

	for (usint j=0; j<dnum; j++) {
		DCRTPoly e(dgg, paramsQP, Format::EVALUATION);

		DCRTPoly b(paramsQP, Format::EVALUATION, true);
		DCRTPoly a(dug, paramsQP, Format::EVALUATION);

		for (usint i=0; i<paramsQP->GetParams().size(); i++) {

			auto a_i = a.GetElementAtIndex(i);
			auto e_i = e.GetElementAtIndex(i);
			auto s2_i = ext_s2.GetElementAtIndex(i);

			if (i < paramsQ->GetParams().size()) { // The part with basis Q

				auto s1_i = s1.GetElementAtIndex(i);

				auto factor = PModQj[i].ModMulFast(QHatModqj[j][i], paramsQ->GetParams()[i]->GetModulus());

				b.SetElementAtIndex(i, - a_i * s2_i + factor * s1_i + e_i );
			} else { // The part with basis P
				b.SetElementAtIndex(i, - a_i * s2_i + e_i);
			}

		}

		av[j] = a;
		bv[j] = b;
	}

	ek->SetAVector(std::move(av));
	ek->SetBVector(std::move(bv));

	return ek;

}



template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchHybrid(
		const LPEvalKey<DCRTPoly> ek,
		ConstCiphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	const std::vector<DCRTPoly> &b = evalKey->GetBVector();
	const std::vector<DCRTPoly> &a = evalKey->GetAVector();

	DCRTPoly ct0;
	DCRTPoly ct1;

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();
	size_t towersToSkip = cryptoParamsLWE->GetElementParams()->GetParams().size() - cipherTowers;

	DCRTPoly cTmp, cOrig;

	if (c.size() == 2) {//case of PRE or automorphism
		cOrig = c[1];
		cTmp = c[1].Clone();
	} else { //case of EvalMult
		cOrig = c[2];
		cTmp = c[2].Clone();
	}

	uint32_t l = cipherTowers - 1;
	uint32_t alpha = cryptoParamsLWE->GetNumberOfTowersPerDigit();
	uint32_t beta = ceil(((double)(l+1))/alpha); // The number of digits of the current ciphertext
	//uint32_t digits = cryptoParamsLWE->GetNumberOfDigits();
	if (beta > cryptoParamsLWE->GetNumberOfQPartitions())
		beta = cryptoParamsLWE->GetNumberOfQPartitions();

	vector<DCRTPoly> digitsCTmp(beta);

	// Digit decomposition
	// Zero-padding and split
	uint32_t numTowersLastDigit = cryptoParamsLWE->GetQPartition(beta-1)->GetParams().size();
	for (uint32_t j=0; j<beta; j++) {
		if (j == beta-1) {
			auto part = cryptoParamsLWE->GetQPartition(j);
			part->GetParams();

			numTowersLastDigit = cipherTowers - alpha*j;

			vector<NativeInteger> moduli(numTowersLastDigit);
			vector<NativeInteger> roots(numTowersLastDigit);

			for (uint32_t i=0; i<numTowersLastDigit; i++) {
				moduli[i] = part->GetParams()[i]->GetModulus();
				roots[i] = part->GetParams()[i]->GetRootOfUnity();
			}

			auto params = DCRTPoly::Params(part->GetCyclotomicOrder(),
										moduli, roots, {}, {}, 0);

			digitsCTmp[j] = DCRTPoly(std::make_shared<typename DCRTPoly::Params>(params), EVALUATION, true);

		} else
			digitsCTmp[j] = DCRTPoly(cryptoParamsLWE->GetQPartition(j), Format::EVALUATION, true);

		uint32_t iters = (j == beta-1) ? numTowersLastDigit : alpha;
		for (uint32_t i=0; i<iters; i++) {
			if (j*alpha + i <= l) {
				auto tmp = cTmp.GetElementAtIndex(j*alpha+i);
				digitsCTmp[j].SetElementAtIndex(i, tmp);
			}
		}
	}
	// RNS decompose
	for (uint32_t j=0; j<beta; j++) {
		for (uint32_t i=0; i<alpha; i++) {
			if (j*alpha + i <= l) {
				auto tmp = digitsCTmp[j].GetElementAtIndex(i).Times(cryptoParamsLWE->GetQHatInvModqTable()[j][j*alpha+i]);
				digitsCTmp[j].SetElementAtIndex(i, tmp);
			}
		}
	}

	vector<DCRTPoly> pPartExtC(digitsCTmp.size());
	vector<DCRTPoly> expandedC(digitsCTmp.size());
	for (uint32_t j=0; j<digitsCTmp.size(); j++) {

		auto tmpDigit = digitsCTmp[j].Clone();

		tmpDigit.SetFormat(Format::COEFFICIENT);

		const shared_ptr<typename DCRTPoly::Params> params = cryptoParamsLWE->GetComplementaryPartition(cipherTowers-1, j);

		pPartExtC[j] = tmpDigit.ApproxSwitchCRTBasis(cryptoParamsLWE->GetQPartition(j), params, //paramsP,
				cryptoParamsLWE->GetPartitionQHatInvModQTable(j)[digitsCTmp[j].GetNumOfElements()-1],
				cryptoParamsLWE->GetPartitionQHatInvModQPreconTable(j)[digitsCTmp[j].GetNumOfElements()-1],
				cryptoParamsLWE->GetPartitionQHatModPTable(cipherTowers-1)[j],
				cryptoParamsLWE->GetPartitionPrecon(cipherTowers-1)[j]);

		pPartExtC[j].SetFormat(Format::EVALUATION);

		expandedC[j] = DCRTPoly(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);

		for (usint i=0; i<cipherTowers; i++) {
			if (i/alpha == j)
				expandedC[j].SetElementAtIndex(i, digitsCTmp[j].GetElementAtIndex(i % alpha));
			else {
				if (i/alpha < j) {
					expandedC[j].SetElementAtIndex(i, pPartExtC[j].GetElementAtIndex(i));
				} else {
					expandedC[j].SetElementAtIndex(i, pPartExtC[j].GetElementAtIndex(i - alpha));
				}
			}
		}

		for (usint i=0; i<paramsP->GetParams().size(); i++) {
			expandedC[j].SetElementAtIndex(i+cipherTowers, pPartExtC[j].GetElementAtIndex(i + params->GetParams().size() - paramsP->GetParams().size()));
		}
	}

	DCRTPoly cTilda0(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);
	DCRTPoly cTilda1(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);

	for (uint32_t j=0; j<digitsCTmp.size(); j++) {
		for (usint i=0; i<expandedC[j].GetNumOfElements(); i++) {
			// The following skips the switch key elements that are missing from the ciphertext
			usint idx = ( i < cipherTowers ) ? i : i + towersToSkip;
			cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + expandedC[j].GetElementAtIndex(i) * b[j].GetElementAtIndex(idx));
			cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + expandedC[j].GetElementAtIndex(i) * a[j].GetElementAtIndex(idx));
		}
	}

	cTilda0.SetFormat(Format::COEFFICIENT);
	cTilda1.SetFormat(Format::COEFFICIENT);

	DCRTPoly cHat0 = cTilda0.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	DCRTPoly cHat1 = cTilda1.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	cHat0.SetFormat(Format::EVALUATION);
	cHat1.SetFormat(Format::EVALUATION);

	if (c.size() == 2) { //case of PRE or automorphism
		ct0 = c[0] + cHat0;
		ct1 = cHat1;
	} else { //case of EvalMult
		ct0 = c[0] + cHat0;
		ct1 = c[1] + cHat1;
	}

	newCiphertext->SetElements({ ct0, ct1 });
	newCiphertext->SetDepth(cipherText->GetDepth());
	newCiphertext->SetScalingFactor(cipherText->GetScalingFactor());
	newCiphertext->SetLevel(cipherText->GetLevel());

	return newCiphertext;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGHSGen(
		const LPPrivateKey<DCRTPoly> oldKey,
		const LPPrivateKey<DCRTPoly> newKey) const {

	auto cc = newKey->GetCryptoContext();
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> paramsQ = cryptoParamsLWE->GetElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsQP = cryptoParamsLWE->GetExtendedElementParams();

	DCRTPoly s1 = oldKey->GetPrivateElement();
	DCRTPoly s2 = newKey->GetPrivateElement().Clone();

	// s2 is currently in basis Q. This extends it to basis QP.
	s2.SetFormat(Format::COEFFICIENT);
	DCRTPoly ext_s2(paramsQP, Format::COEFFICIENT, true);
	for (usint i=0; i<paramsQP->GetParams().size(); i++) {
		if (i < paramsQ->GetParams().size())
			ext_s2.SetElementAtIndex(i, s2.GetElementAtIndex(i));
		else {
			NativeInteger mod_i = paramsQP->GetParams()[i]->GetModulus();
			NativeInteger ru_i = paramsQP->GetParams()[i]->GetRootOfUnity();
			auto s2_i = s2.GetElementAtIndex(0);
			s2_i.SwitchModulus(mod_i, ru_i);
			ext_s2.SetElementAtIndex(i, s2_i);
		}
	}
	ext_s2.SetFormat(Format::EVALUATION);

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const DCRTPoly a(dug, paramsQP, Format::EVALUATION);
	const DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
	DCRTPoly b(paramsQP, Format::EVALUATION, true);

	vector<NativeInteger> PModQj = cryptoParamsLWE->GetPModQTable();

	for (usint i=0; i<paramsQP->GetParams().size(); i++) {
		auto a_i = a.GetElementAtIndex(i);
		auto e_i = e.GetElementAtIndex(i);
		auto s2_i = ext_s2.GetElementAtIndex(i);

		if (i < paramsQ->GetParams().size()) { // The part with basis Q
			auto s1_i = s1.GetElementAtIndex(i);
			b.SetElementAtIndex(i, - a_i * s2_i + PModQj[i] * s1_i + e_i);
		} else { // The part with basis P
			b.SetElementAtIndex(i, - a_i * s2_i + e_i);
		}
	}

	vector<DCRTPoly> av(1);
	av[0] = a;
	vector<DCRTPoly> bv(1);
	bv[0] = b;

	ek->SetAVector(std::move(av));
	ek->SetBVector(std::move(bv));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGHS(
		const LPEvalKey<DCRTPoly> ek,
		ConstCiphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	const std::vector<DCRTPoly> &b = evalKey->GetBVector();
	const std::vector<DCRTPoly> &a = evalKey->GetAVector();

	DCRTPoly ct0;
	DCRTPoly ct1;

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();
	size_t towersToSkip = cryptoParamsLWE->GetElementParams()->GetParams().size() - cipherTowers;

	DCRTPoly cTmp, cOrig;

	if (c.size() == 2) {//case of PRE or automorphism
		cOrig = c[1];
		cTmp = c[1].Clone();
	} else { //case of EvalMult
		cOrig = c[2];
		cTmp = c[2].Clone();
	}

	cTmp.SetFormat(Format::COEFFICIENT);
	DCRTPoly pPartExtC = cTmp.ApproxSwitchCRTBasis(paramsQ, paramsP,
			cryptoParamsLWE->GetQHatInvModQTable()[cipherTowers-1],
			cryptoParamsLWE->GetQHatInvModQPreconTable()[cipherTowers-1],
			cryptoParamsLWE->GetQHatModPTable()[cipherTowers-1],
			cryptoParamsLWE->GetModBarretPreconPTable());
	pPartExtC.SetFormat(Format::EVALUATION);

	DCRTPoly expandedC(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);
	for (usint i=0; i<expandedC.GetNumOfElements(); i++) {
		if (i < cipherTowers)
			expandedC.SetElementAtIndex(i, cOrig.GetElementAtIndex(i));
		else
			expandedC.SetElementAtIndex(i, pPartExtC.GetElementAtIndex(i-cipherTowers));
	}

	DCRTPoly cTilda0(expandedC.GetParams(), Format::EVALUATION, true);
	DCRTPoly cTilda1(expandedC.GetParams(), Format::EVALUATION, true);

	for (usint i=0; i<expandedC.GetNumOfElements(); i++) {
		// The following skips the switch key elements that are missing from the ciphertext
		usint idx = ( i < cipherTowers ) ? i : i + towersToSkip;
		cTilda0.SetElementAtIndex(i, expandedC.GetElementAtIndex(i) * b[0].GetElementAtIndex(idx));
		cTilda1.SetElementAtIndex(i, expandedC.GetElementAtIndex(i) * a[0].GetElementAtIndex(idx));
	}

	cTilda0.SetFormat(Format::COEFFICIENT);
	cTilda1.SetFormat(Format::COEFFICIENT);

	DCRTPoly cHat0 = cTilda0.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	DCRTPoly cHat1 = cTilda1.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	cHat0.SetFormat(Format::EVALUATION);
	cHat1.SetFormat(Format::EVALUATION);

	if (c.size() == 2) { //case of PRE or automorphism
		ct0 = c[0] + cHat0;
		ct1 = cHat1;
	} else { //case of EvalMult
		ct0 = c[0] + cHat0;
		ct1 = c[1] + cHat1;
	}

	newCiphertext->SetElements({ ct0, ct1 });
	newCiphertext->SetDepth(cipherText->GetDepth());
	newCiphertext->SetScalingFactor(cipherText->GetScalingFactor());
	newCiphertext->SetLevel(cipherText->GetLevel());

	return newCiphertext;
}



template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchBVGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const DCRTPoly &s = newPrivateKey->GetPrivateElement();

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

	DCRTPoly oldKey = originalPrivateKey->GetPrivateElement();

	oldKey.DropLastElements(originalPrivateKey->GetCryptoContext()->GetKeyGenLevel());

	usint nWindows = 0;

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	// used to store the number of digits for each small modulus
	std::vector<usint> arrWindows;

	if (relinWindow > 0)
	{
		// creates an array of digits up to a certain tower
		for (usint i = 0; i < oldKey.GetNumOfElements(); i++) {
			usint nBits = oldKey.GetElementAtIndex(i).GetModulus().GetLengthForBase(2);
			usint curWindows = nBits / relinWindow;
			if (nBits % relinWindow > 0)
				curWindows++;
			arrWindows.push_back(nWindows);
			nWindows += curWindows;
		}
	}
	else
	{
		nWindows = oldKey.GetNumOfElements();
	}

	std::vector<DCRTPoly> evalKeyElements(nWindows);
	std::vector<DCRTPoly> evalKeyElementsGenerated(nWindows);

#pragma omp parallel for
	for (usint i = 0; i < oldKey.GetNumOfElements(); i++)
	{
		typename DCRTPoly::DugType dug;

		if (relinWindow>0)
		{
			vector<typename DCRTPoly::PolyType> decomposedKeyElements = oldKey.GetElementAtIndex(i).PowersOfBase(relinWindow);

			for (size_t k = 0; k < decomposedKeyElements.size(); k++)
			{

				// Creates an element with all zeroes
				DCRTPoly filtered(elementParams,EVALUATION,true);

				filtered.SetElementAtIndex(i,decomposedKeyElements[k]);

				// Generate a_i vectors
				DCRTPoly a(dug, elementParams, Format::EVALUATION);

				evalKeyElementsGenerated[k + arrWindows[i]] = a;

				// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
				DCRTPoly e(dgg, elementParams, Format::EVALUATION);
				evalKeyElements[k + arrWindows[i]] = filtered - (a*s + e);
			}
		}
		else
		{

			// Creates an element with all zeroes
			DCRTPoly filtered(elementParams,EVALUATION,true);

			filtered.SetElementAtIndex(i,oldKey.GetElementAtIndex(i));

			// Generate a_i vectors
			DCRTPoly a(dug, elementParams, Format::EVALUATION);
			evalKeyElementsGenerated[i] = a;

			// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
			DCRTPoly e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements[i] = filtered - (a*s + e);
		}

	}

	ek->SetAVector(std::move(evalKeyElementsGenerated));
	ek->SetBVector(std::move(evalKeyElements));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchBV(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	std::vector<DCRTPoly> b = evalKey->GetBVector();
	std::vector<DCRTPoly> a = evalKey->GetAVector();

	size_t towersToDrop = b[0].GetParams()->GetParams().size() - c[0].GetParams()->GetParams().size();

	for (size_t k = 0; k < b.size(); k++) {
		a[k].DropLastElements(towersToDrop);
		b[k].DropLastElements(towersToDrop);
	}

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<DCRTPoly> digitsC2;

	DCRTPoly ct0(c[0]);

	//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
	if (c.size() > 2)
		ct0.SetFormat(EVALUATION);

	DCRTPoly ct1;

	if (c.size() == 2) //case of PRE or automorphism
	{
		digitsC2 = c[1].CRTDecompose(relinWindow);
		ct1 = digitsC2[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC2 = c[2].CRTDecompose(relinWindow);
		ct1 = c[1];
		//Convert ct1 to evaluation representation
		ct1.SetFormat(EVALUATION);
		ct1 += digitsC2[0] * a[0];

	}

	ct0 += digitsC2[0] * b[0];

	for (usint i = 1; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	newCiphertext->SetElements({ ct0, ct1 });

	newCiphertext->SetDepth(cipherText->GetDepth());
	newCiphertext->SetScalingFactor(cipherText->GetScalingFactor());
	newCiphertext->SetLevel(cipherText->GetLevel());

	return newCiphertext;
}


template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newPrivateKey->GetCryptoParameters());

	if (cryptoParamsLWE->GetKeySwitchTechnique() == BV) {
		return KeySwitchBVGen(originalPrivateKey, newPrivateKey);
	} else if (cryptoParamsLWE->GetKeySwitchTechnique() == GHS) {
		return KeySwitchGHSGen(originalPrivateKey, newPrivateKey);
	} else { // Hybrid
		return KeySwitchHybridGen(originalPrivateKey, newPrivateKey);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitch(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> cipherText) const
{

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(cipherText->GetCryptoParameters());

	Ciphertext<DCRTPoly> cRes;
	if (cryptoParamsLWE->GetKeySwitchTechnique() == BV) {
		cRes = KeySwitchBV(ek, cipherText);
	} else if (cryptoParamsLWE->GetKeySwitchTechnique() == GHS) {
		cRes = KeySwitchGHS(ek, cipherText);
	} else { // Hybrid
		cRes = KeySwitchHybrid(ek, cipherText);
	}

	return cRes;
}


template<>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::ModReduceInternal(
		ConstCiphertext<DCRTPoly> cipherText) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(cipherText->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	vector<DCRTPoly> copy(cipherText->GetElements());

	size_t size = copy[0].GetNumOfElements();

	size_t omegaSize = cryptoParamsLWE->GetOmega().size();

	for (size_t i=0; i < cipherText->GetElements().size(); i++){

		/*

		copy[i].SetFormat(COEFFICIENT);

		Poly interpolated = copy[i].CRTInterpolate();

		interpolated = interpolated.DivideAndRound(qt);

		interpolated.SwitchModulus(newP->GetModulus(),BigInteger(1));

		copy[i] = DCRTPoly(interpolated,newP);

		copy[i].SetFormat(EVALUATION);

		*/

		copy[i].DropLastElementAndScale(cryptoParamsLWE->GetOmega()[omegaSize+1-size]);

	}

	newCiphertext->SetElements(copy);

	newCiphertext->SetDepth(cipherText->GetDepth()-1);
	auto numTowers = cipherText->GetElements()[0].GetNumOfElements();
	auto droppedMod = cipherText->GetElements()[0].GetElementAtIndex(numTowers-1).GetModulus();
	auto scalingFactor = cipherText->GetScalingFactor();
	double fDroppedMod = droppedMod.ConvertToDouble();
	newCiphertext->SetScalingFactor(scalingFactor/fDroppedMod);
	newCiphertext->SetLevel(cipherText->GetLevel() + 1);

	return newCiphertext;

}

template<>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::ModReduce(
		ConstCiphertext<DCRTPoly> cipherText) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
						cipherText->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
//		cerr << "Here - ModReduce " << 1 << endl;

		return ModReduceInternal(cipherText);
	} else { // EXACTRESCALE
		// Do nothing - in EXACTRESCALE rescaling is performed automatically
		return std::make_shared<CiphertextImpl<DCRTPoly>>(*cipherText);
	}

}


template<>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::LevelReduceInternal(
		ConstCiphertext<DCRTPoly> cipherText1,
		const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels)  const {

	Ciphertext<DCRTPoly> newCiphertext = cipherText1->CloneEmpty();
	newCiphertext->SetDepth(cipherText1->GetDepth());
	newCiphertext->SetLevel(cipherText1->GetLevel() + levels);
	newCiphertext->SetScalingFactor(cipherText1->GetScalingFactor());

	vector<DCRTPoly> copy(cipherText1->GetElements());

	for (size_t i = 0; i < copy.size(); i++)
		copy[i].DropLastElements(levels);

	newCiphertext->SetElements(copy);

	return newCiphertext;

}

template<>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::LevelReduce(
		ConstCiphertext<DCRTPoly> cipherText1,
		const LPEvalKey<DCRTPoly> linearKeySwitchHint,
		size_t levels)  const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
						cipherText1->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
		return LevelReduceInternal(cipherText1, linearKeySwitchHint, levels);
	} else { // EXACTRESCALE
		// Do nothing - in EXACTRESCALE level reduce is performed automatically
		return std::make_shared<CiphertextImpl<DCRTPoly>>(*cipherText1);
	}

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd(
	ConstCiphertext<DCRTPoly> ciphertext,
	double constant) const
{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	double powP;
	int32_t depth = ciphertext->GetDepth();

	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
		const auto p = cryptoParams->GetPlaintextModulus();
		// In APPROXRESCALE, the scaling factor is always 2^p
		powP = pow(2,p);
	} else {
		// In EXACTRESCALE, the scaling factor of every level is different
		powP = cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
	}

	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	usint numTowers = ciphertext->GetElements()[0].GetNumOfElements();
	vector<DCRTPoly::Integer> moduli(numTowers);

	for (usint i=0; i<numTowers; i++) {
		moduli[i] = ciphertext->GetElements()[0].GetElementAtIndex(i).GetModulus();
	}

	DCRTPoly::Integer intPowP = std::llround(powP);
	DCRTPoly::Integer scaledConstant = std::llround(constant*powP);

	vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
	vector<DCRTPoly::Integer> crtConstant(numTowers, scaledConstant);

	auto currPowP = crtConstant;
	// multiply c*powP with powP a total of (depth-1) times to get c*powP^d
	for (int i=0; i<depth-1; i++) {
		currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
	}

	std::vector<DCRTPoly> cNew;

	cNew.push_back(c1[0] + currPowP);

	for (size_t i = 1; i < c1.size(); i++) {
		cNew.push_back(std::move(c1[i]));
	}

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth( ciphertext->GetDepth() );
	newCiphertext->SetScalingFactor( ciphertext->GetScalingFactor() );
	newCiphertext->SetLevel( ciphertext->GetLevel() );

	return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
	ConstCiphertext<DCRTPoly> ciphertext,
	double constant) const
{
	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	double powP;
	int32_t depth = ciphertext->GetDepth();

	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
		const auto p = cryptoParams->GetPlaintextModulus();
		// In APPROXRESCALE, the scaling factor is always 2^p
		powP = pow(2,p);
	} else { // EXACTRESCALE
		// In EXACTRESCALE, the scaling factor of every level is different
		powP = cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
	}

	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	usint numTowers = ciphertext->GetElements()[0].GetNumOfElements();
	vector<DCRTPoly::Integer> moduli(numTowers);
	for (usint i=0; i<numTowers; i++) {
		moduli[i] = ciphertext->GetElements()[0].GetElementAtIndex(i).GetModulus();
	}

	DCRTPoly::Integer intPowP = std::llround(powP);
	DCRTPoly::Integer scaledConstant = std::llround(constant*powP);

	vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
	vector<DCRTPoly::Integer> crtConstant(numTowers, scaledConstant);

	auto currPowP = crtConstant;
	// multiply c*powP with powP a total of (depth-1) times to get c*powP^d
	for (int i=0; i<depth-1; i++) {
		currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
	}

	std::vector<DCRTPoly> cNew;

	cNew.push_back(c1[0] - currPowP);

	for (size_t i = 1; i < c1.size(); i++) {
		cNew.push_back(std::move(c1[i]));
	}

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth( ciphertext->GetDepth() );
	newCiphertext->SetScalingFactor( ciphertext->GetScalingFactor() );
	newCiphertext->SetLevel( ciphertext->GetLevel() );

	return newCiphertext;
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
	ConstCiphertext<DCRTPoly> ciphertext,
	double constant) const {

//	TimeVar t;
//	TIC(t);

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	const auto p = cryptoParams->GetPlaintextModulus();
	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	double powP;
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		// Even though EvalMultApprox is mainly for use in APPROXRESCALE
		// it is used in EvalLinearWSum in EXACTRESCALE too, as an
		// optimization.
		powP = cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
	} else {
		powP = pow(2,p);
	}

	int64_t scaledConstant = std::llround(constant*powP);

	std::vector<DCRTPoly> cNew;

	for (size_t i = 0; i < c1.size(); i++)
		cNew.push_back(c1[i] * scaledConstant);

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth(ciphertext->GetDepth()+1);
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor() * powP);
	newCiphertext->SetLevel(ciphertext->GetLevel());

//	double time = TOC_US(t);
//	cerr << "Benchmark, EvalMultApprox, 1, " << time << endl;

	return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
	Ciphertext<DCRTPoly> &ciphertext,
	double constant) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
		// Mutable methods are intended only for EXACTRESCALE, which
		// performs rescaling autmotically.
		return EvalMultApprox(ciphertext, constant);
	} else { // EXACTRESCALING

//		TimeVar t;
//		TIC(t);

		Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

		/*
		To implement EvalMult in EXACTRESCALE, we first have to rescale
		the input ciphertext to depth 1, if it's not already there. Then,
		we scale the input constant by the scaling factor of the ciphertext
		and multiply. No need to take special care for scaling constants to
		greater depths in CRT, because all the input will always get brought
		down to depth 1.
		*/

		// EXACTRESCALE expects all ciphertexts to be either of depth 1 or 2.
		if (ciphertext->GetDepth() > 2) {
			PALISADE_THROW(not_available_error, "Exact rescaling works for ciphertexts " \
					"of depth 1 and 2 only, and depth of 1 is allowed only for fresh ciphertexts");
		}

		auto cc = ciphertext->GetCryptoContext();
		auto algo = cc->GetEncryptionAlgorithm();

		double powP = ciphertext->GetScalingFactor();
		uint32_t depth = ciphertext->GetDepth();
		uint32_t level = ciphertext->GetLevel();
		double scalingFactor = ciphertext->GetScalingFactor();

		// Rescale to bring ciphertext to depth 1
		if (ciphertext->GetDepth() == 2) {
			ciphertext = algo->ModReduceInternal(ciphertext);
			powP = ciphertext->GetScalingFactor();
			depth = ciphertext->GetDepth();
			level = ciphertext->GetLevel();
			scalingFactor = ciphertext->GetScalingFactor();
		}

		const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

		DCRTPoly::Integer scaledConstant = std::llround(constant*powP);

		std::vector<DCRTPoly> cNew;

		for (size_t i = 0; i < c1.size(); i++)
			cNew.push_back(c1[i] * scaledConstant);

		newCiphertext->SetElements(std::move(cNew));

		// For EXACTRESCALING, depth always expected to be 2
		newCiphertext->SetDepth( 2 * depth );
		// For EXACTRESCALING, scaling factor always expected to be squared
		newCiphertext->SetScalingFactor( scalingFactor * scalingFactor );
		// For EXACTRESCALING, level will change with ModReduce above, but not with multiplication.
		newCiphertext->SetLevel( level );

//		double time = TOC_US(t);
//		cerr << "Benchmark, EvalMultMutable, 1, " << time << endl;

		return newCiphertext;
	}

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
	ConstCiphertext<DCRTPoly> ciphertext,
	double constant) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	Ciphertext<DCRTPoly> cRes;
	if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
		cRes = EvalMultApprox(ciphertext, constant);
	} else { // EXACTRESCALING
		Ciphertext<DCRTPoly> c = ciphertext->Clone();

		cRes = EvalMultMutable(c, constant);
	}

	return cRes;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale(
	Ciphertext<DCRTPoly> &c1,
	uint32_t targetLevel) const
{
	if ( c1->GetDepth() != 1 ) {
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale "
				"expects a ciphertext that's at depth 1.");
	}

	if ( c1->GetLevel() >= targetLevel ) {
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale "
				"a ciphertext can only be adjusted to a larger level. Ciphertext level: " +
				std::to_string(c1->GetLevel()) + " and target level is: " +
				std::to_string(targetLevel));
	}

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					c1->GetCryptoParameters());

	CryptoContext<DCRTPoly> cc = c1->GetCryptoContext();
	auto algo = cc->GetEncryptionAlgorithm();

	uint32_t numTowers = c1->GetElements()[0].GetNumOfElements();

	// Multiply with a factor to adjust scaling factor to new level
	double adjustmentFactor = 1.0;
	// Find the modulus of the last tower, which is to be dropped after rescaling
	double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers-1]->GetModulus().ConvertToDouble();
	double targetSF = cryptoParams->GetScalingFactorOfLevel(targetLevel);
	double sourceSF = cryptoParams->GetScalingFactorOfLevel(c1->GetLevel());
	adjustmentFactor = (targetSF/sourceSF)*(modToDrop/sourceSF);

	// Multiply ciphertext with adjustment (first step to get target scaling factor).
	// and manually update the scaling factor of the result.
	c1 = EvalMult(c1, adjustmentFactor);

	// Rescale ciphertext1
	c1 = algo->ModReduceInternal(c1);

	// Drop extra moduli of ciphertext1 to match target level
	uint32_t towerDiff = targetLevel - c1->GetLevel();
	if (towerDiff > 0)
		c1 = algo->LevelReduceInternal(c1, nullptr, towerDiff);

	// At this moment, the adjustment factor is interpreted by
	// the library as part of the encrypted message. We manually
	// update the scaling factor to reflect that it was adjusted
	// by multiplying with adjustmentFactor.
	c1->SetScalingFactor(adjustmentFactor * c1->GetScalingFactor());

	return c1;
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale(
	Ciphertext<DCRTPoly> &c1,
	uint32_t targetLevel ) const
{
	if ( c1->GetDepth() != 1 ) {
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale "
				"expects a ciphertext that's at depth 1.");
	}

	if ( c1->GetLevel() >= targetLevel ) {
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale "
				"a ciphertext can only be adjusted to a larger level. Ciphertext level: " +
				std::to_string(c1->GetLevel()) + " and target level is: " +
				std::to_string(targetLevel) );
	}

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					c1->GetCryptoParameters());

	CryptoContext<DCRTPoly> cc = c1->GetCryptoContext();

	// Multiply with a factor to adjust scaling factor to new level
	double adjustmentFactor = 1.0;
	double targetSF = cryptoParams->GetScalingFactorOfLevel(targetLevel);
	double sourceSF = cryptoParams->GetScalingFactorOfLevel(c1->GetLevel());
	adjustmentFactor = (targetSF/sourceSF)*(targetSF/sourceSF);

	// Multiply ciphertext with adjustment factor.
	c1 = EvalMult(c1, adjustmentFactor);

	// At this moment, the adjustment factor is interpreted by
	// the library as part of the encrypted message. We manually
	// update the scaling factor to reflect that it was adjusted
	// by multiplying with adjustmentFactor.
	c1->SetScalingFactor(adjustmentFactor * c1->GetScalingFactor());

	// Drop extra moduli of ciphertext1 to match target level
	auto algo = cc->GetEncryptionAlgorithm();
	uint32_t towerDiff = targetLevel - c1->GetLevel();
	if (towerDiff > 0)
		c1 = algo->LevelReduceInternal(c1, nullptr, towerDiff);

	return c1;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(
	ConstCiphertext<DCRTPoly> ciphertext,
	DCRTPoly ptElem, usint ptDepth) const
{
	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(ciphertext->GetCryptoParameters());
	const auto p = cryptoParams->GetPlaintextModulus();

	// Bring to same depth if not already same
	if (ptDepth < ciphertext->GetDepth()) {
		// Find out how many levels to scale plaintext up.
		size_t depthDiff = ciphertext->GetDepth() - ptDepth;

		DCRTPoly ptElemClone = ptElem.Clone();

		// Get moduli chain to create CRT representation of powP
		usint numTowers = ciphertext->GetElements()[0].GetNumOfElements();
		vector<DCRTPoly::Integer> moduli(numTowers);
		for (usint i=0; i<numTowers; i++)
			moduli[i] = ciphertext->GetElements()[0].GetElementAtIndex(i).GetModulus();

		// Create CRT representation of powP
		double powP = pow(2,p);
		DCRTPoly::Integer intPowP = std::llround(powP);
		std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
		// Compute powP^depthDiff in CRT
		auto currPowP = crtPowP;
		for (usint j=1; j<depthDiff; j++)
			currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);

		// Update ptElem with scaled up element
		ptElem = ptElemClone.Times(currPowP);
	} else if (ptDepth > ciphertext->GetDepth())
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd " \
				"- plaintext cannot be encoded at a larger depth than that of the ciphertext.");

	DCRTPoly c2 = ptElem;

	c2.SetFormat(EVALUATION);

	std::vector<DCRTPoly> cNew;

	cNew.push_back((c1[0] + c2));

	for (size_t i = 1; i < c1.size(); i++)
		cNew.push_back(std::move(c1[i]));

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth(ciphertext->GetDepth());
	newCiphertext->SetLevel(ciphertext->GetLevel());
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(
	ConstCiphertext<DCRTPoly> ciphertext,
	DCRTPoly ptElem, usint ptDepth) const
{
	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(ciphertext->GetCryptoParameters());
	const auto p = cryptoParams->GetPlaintextModulus();

	// Bring to same depth if not already same
	if (ptDepth < ciphertext->GetDepth()) {
		// Find out how many levels to scale plaintext up.
		size_t depthDiff = ciphertext->GetDepth() - ptDepth;

		DCRTPoly ptElemClone = ptElem.Clone();

		// Get moduli chain to create CRT representation of powP
		usint numTowers = ciphertext->GetElements()[0].GetNumOfElements();
		vector<DCRTPoly::Integer> moduli(numTowers);
		for (usint i=0; i<numTowers; i++)
			moduli[i] = ciphertext->GetElements()[0].GetElementAtIndex(i).GetModulus();

		// Create CRT representation of powP
		double powP = pow(2,p);
		DCRTPoly::Integer intPowP = std::llround(powP);
		std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
		// Compute powP^depthDiff in CRT
		auto currPowP = crtPowP;
		for (usint j=1; j<depthDiff; j++)
			currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);

		// Update ptElem with scaled up element
		ptElem = ptElemClone.Times(currPowP);
	} else if (ptDepth > ciphertext->GetDepth())
		PALISADE_THROW(not_available_error, "LPAlgorithmSHECKKS<DCRTPoly>::EvalSub " \
				"- plaintext cannot be encoded at a larger depth than that of the ciphertext.");

	DCRTPoly c2 = ptElem;

	c2.SetFormat(EVALUATION);

	std::vector<DCRTPoly> cNew;

	cNew.push_back((c1[0] - c2));

	for (size_t i = 1; i < c1.size(); i++)
		cNew.push_back(std::move(c1[i]));

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth(ciphertext->GetDepth());
	newCiphertext->SetLevel(ciphertext->GetLevel());
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

	return newCiphertext;

}


template <>
vector<shared_ptr<ConstCiphertext<DCRTPoly>>> LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const
{
	auto cc = ciphertext1->GetCryptoContext();
	auto towers1 = ciphertext1->GetElements()[0].GetNumOfElements();
	auto towers2 = ciphertext2->GetElements()[0].GetNumOfElements();

	vector<shared_ptr<ConstCiphertext<DCRTPoly>>> ct(2);

	if ( towers1 != towers2 ) {
		int towerDiff = towers1 - towers2;

		if ( towerDiff < 0 ) {
			// First ciphertext remains same
			ct[0] = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);

			// Level reduce the second ciphertext
			towerDiff = - towerDiff;

			auto algo = cc->GetEncryptionAlgorithm();

			auto reducedCt = algo->LevelReduceInternal(ciphertext2, nullptr, towerDiff);
			ct[1] = make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);
		} else {
			// Second ciphertext remains same
			ct[1] = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);

			// Level reduce the first ciphertext
			auto algo = cc->GetEncryptionAlgorithm();
			auto reducedCt = algo->LevelReduceInternal(ciphertext1, nullptr, towerDiff);
			ct[0] = make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);
		}
	} else {
		ct[0] = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);
		ct[1] = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);
	}

	return ct;
}


template <>
pair<shared_ptr<ConstCiphertext<DCRTPoly>>, DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(
	ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const
{
	DCRTPoly ptElem = plaintext->GetElement<DCRTPoly>();
	auto cc = ciphertext->GetCryptoContext();
	auto towers1 = ciphertext->GetElements()[0].GetNumOfElements();
	auto towers2 = ptElem.GetNumOfElements();

	pair<shared_ptr<ConstCiphertext<DCRTPoly>>, DCRTPoly> resPair;

	if ( towers1 != towers2 ) {
		int towerDiff = towers1 - towers2;

		if ( towerDiff < 0 ) {
			// Ciphertext remains same
			resPair.first = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext);

			// Level reduce the plaintext
			towerDiff = - towerDiff;
			ptElem.DropLastElements(towerDiff);
			resPair.second = ptElem;
		} else {
			// Plaintext remains same
			resPair.second = ptElem;

			// Level reduce the ciphertext
			auto algo = cc->GetEncryptionAlgorithm();
			auto reducedCt = algo->LevelReduceInternal(ciphertext, nullptr, towerDiff);
			resPair.first = make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);
		}
	} else {
		resPair.first = make_shared<ConstCiphertext<DCRTPoly>>(ciphertext);
		resPair.second = ptElem;
	}

	return resPair;
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddApprox(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const {

	if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
		PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
	}

	// Automatic lever-reduce
	auto ct = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext1, ciphertext2);
	return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddMutable(
	Ciphertext<DCRTPoly> &ciphertext1,
	Ciphertext<DCRTPoly> &ciphertext2) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
				ciphertext1->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();
		auto algo = cc->GetEncryptionAlgorithm();

		if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
			// ciphertext1 gets adjusted
			if (ciphertext1->GetDepth() > 1)
				ciphertext1 = algo->ModReduceInternal(ciphertext1);

			// Adjust only if levels are still different, or if their
			// depths are different (ciphertext2 is always expected to be depth 1 here)
			if ( ciphertext1->GetLevel() < ciphertext2->GetLevel() ) {
				if (ciphertext2->GetDepth() == 1)
					ciphertext1 = AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
				else
					ciphertext1 = AdjustLevelWithoutRescale(ciphertext1, ciphertext2->GetLevel());
			} else if (ciphertext2->GetDepth() != ciphertext1->GetDepth() ) {
				ciphertext1 = EvalMult(ciphertext1, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCore(ciphertext1, ciphertext2);
		} else if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
			// ciphertext2 gets adjusted
			if (ciphertext2->GetDepth() > 1)
				ciphertext2 = algo->ModReduceInternal(ciphertext2);

			// Adjust only if levels are still different, or if their
			// depths are different (ciphertext2 is always expected to be depth 1 here)
			if ( ciphertext2->GetLevel() < ciphertext1->GetLevel() ) {
				if (ciphertext1->GetDepth() == 1)
					ciphertext2 = AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
				else
					ciphertext2 = AdjustLevelWithoutRescale(ciphertext2, ciphertext1->GetLevel());
			} else if (ciphertext1->GetDepth() != ciphertext2->GetDepth() ) {
				ciphertext2 = EvalMult(ciphertext2, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCore(ciphertext1, ciphertext2);
		} else { // No need for adjustment - levels are equal
			// If depths are not equal, bring the ciphertext which
			// is of depth 1 to 2.
			if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
				if (ciphertext1->GetDepth() == 1)
					ciphertext1 = EvalMultMutable(ciphertext1, 1.0);
				else
					ciphertext2 = EvalMultMutable(ciphertext2, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCore(ciphertext1, ciphertext2);
		}

	} else { // Approximate rescaling
		// Mutable methods are intended only for EXACTRESCALE, which
		// performs rescaling autmotically.
		return EvalAddApprox(ciphertext1, ciphertext2);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
				ciphertext1->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
		Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

		return EvalAddMutable(c1, c2);

	} else { // Approximate rescaling
		return EvalAddApprox(ciphertext1, ciphertext2);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd(
	ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		if ( plaintext->GetDepth() != ciphertext->GetDepth() ||
				plaintext->GetLevel() != ciphertext->GetLevel()	) {
			// TODO - it's not efficient to re-make the plaintexts
			// Allow for rescaling of plaintexts, and the ability to
			// increase the towers of a plaintext to get better performance.
			// Also refactor after fixing this to avoid duplication of
			// AutomaticLevelReduce and EvalAddCorePlaintext code below.
			CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

			auto values = plaintext->GetCKKSPackedValue();
			Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(), ciphertext->GetLevel());

			auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, ptx);

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, ptx->GetDepth());
		}

		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		return cRes;

	} else { // APPROXRESCALE
		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddMutable(
	Ciphertext<DCRTPoly> &ciphertext,
	Plaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
					ciphertext->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		TimeVar t;
		TIC(t);

		if ( plaintext->GetDepth() != ciphertext->GetDepth() ||
				plaintext->GetLevel() != ciphertext->GetLevel()	) {
			// TODO - it's not efficient to re-make the plaintexts
			// Allow for rescaling of plaintexts, and the ability to
			// increase the towers of a plaintext to get better performance.
			// Also refactor after fixing this to avoid duplication of
			// AutomaticLevelReduce and EvalAddCorePlaintext code below.
			CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

			auto values = plaintext->GetCKKSPackedValue();
			Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(), ciphertext->GetLevel());

			auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, ptx);

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, ptx->GetDepth());
		}

		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		double time = TOC(t);
		cerr << "EvalAddMutable(ptx), " << time << endl;

		return cRes;

	} else { // APPROXRESCALE
		TimeVar t;
		TIC(t);

		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		double time = TOC(t);
		cerr << "EvalAddApprox(ptx), " << time << endl;

		return cRes;
	}
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubApprox(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const {

	if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
		PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
	}

	// Automatic lever-reduce
	auto ct = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext1, ciphertext2);
	return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubMutable(
	Ciphertext<DCRTPoly> &ciphertext1,
	Ciphertext<DCRTPoly> &ciphertext2) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext1->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {

		CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();
		auto algo = cc->GetEncryptionAlgorithm();

		if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
			// ciphertext1 gets adjusted
			if (ciphertext1->GetDepth() > 1)
				ciphertext1 = algo->ModReduceInternal(ciphertext1);

			// Adjust only if levels are still different
			if ( ciphertext1->GetLevel() < ciphertext2->GetLevel() ) {
				if (ciphertext2->GetDepth() == 1)
					ciphertext1 = AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
				else
					ciphertext1 = AdjustLevelWithoutRescale(ciphertext1, ciphertext2->GetLevel());
			} else if (ciphertext2->GetDepth() != ciphertext1->GetDepth() ) {
				ciphertext1 = EvalMult(ciphertext1, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCore(ciphertext1, ciphertext2);
		} else if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
			// ciphertext2 gets adjusted
			if (ciphertext2->GetDepth() > 1)
				ciphertext2 = algo->ModReduceInternal(ciphertext2);

			// Adjust only if levels are still different
			if ( ciphertext2->GetLevel() < ciphertext1->GetLevel() ) {
				if (ciphertext1->GetDepth() == 1)
					ciphertext2 = AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
				else
					ciphertext2 = AdjustLevelWithoutRescale(ciphertext2, ciphertext1->GetLevel());
			} else if (ciphertext1->GetDepth() != ciphertext2->GetDepth() ) {
				ciphertext2 = EvalMult(ciphertext2, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCore(ciphertext1, ciphertext2);
		} else { // No need for adjustment - levels are equal
			// If depths are not equal, bring the ciphertext which
			// is of depth 1 to 2.
			if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
				if (ciphertext1->GetDepth() == 1)
					ciphertext1 = EvalMultMutable(ciphertext1, 1.0);
				else
					ciphertext2 = EvalMultMutable(ciphertext2, 1.0);
			}

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCore(ciphertext1, ciphertext2);
		}

	} else { // Approximate rescaling
		// Mutable methods are intended only for EXACTRESCALE, which
		// performs rescaling autmotically.
		return EvalSubApprox(ciphertext1, ciphertext2);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
				ciphertext1->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
		Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

		return EvalSubMutable(c1, c2);

	} else { // Approximate rescaling
		return EvalSubApprox(ciphertext1, ciphertext2);
	}
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
	ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		if ( plaintext->GetDepth() != ciphertext->GetDepth() ||
				plaintext->GetLevel() != ciphertext->GetLevel() ) {
			// TODO - it's not efficient to re-make the plaintexts
			// Allow for rescaling of plaintexts, and the ability to
			// increase the towers of a plaintext to get better performance.
			// Also refactor after fixing this to avoid duplication of
			// AutomaticLevelReduce and EvalSubCorePlaintext code below.

			CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

			auto values = plaintext->GetCKKSPackedValue();
			Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(), ciphertext->GetLevel());

			auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, ptx);

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, ptx->GetDepth());
		}
		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		return cRes;
	} else { //APPROXRESCALE
		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());
	}
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubMutable(
	Ciphertext<DCRTPoly> &ciphertext,
	Plaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		TimeVar t;
		TIC(t);

		if ( plaintext->GetDepth() != ciphertext->GetDepth() ||
				plaintext->GetLevel() != ciphertext->GetLevel() ) {
			// TODO - it's not efficient to re-make the plaintexts
			// Allow for rescaling of plaintexts, and the ability to
			// increase the towers of a plaintext to get better performance.
			// Also refactor after fixing this to avoid duplication of
			// AutomaticLevelReduce and EvalSubCorePlaintext code below.

			CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

			auto values = plaintext->GetCKKSPackedValue();
			Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(), ciphertext->GetLevel());

			auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, ptx);

			return LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, ptx->GetDepth());
		}
		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		double time = TOC(t);
		cerr << "EvalSubMutable(ptx), " << time << endl;

		return cRes;
	} else { //APPROXRESCALE
		TimeVar t;
		TIC(t);

		// Automatic lever-reduce
		auto inPair = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext, plaintext);

		auto cRes = LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(*(inPair.first), inPair.second, plaintext->GetDepth());

		double time = TOC(t);
		cerr << "EvalSubApprox(ptx), " << time << endl;

		return cRes;

	}
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const {

	// Automatic lever-reduce
	auto ct = LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(ciphertext1, ciphertext2);
	return LPAlgorithmSHECKKS<DCRTPoly>::EvalMultCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
	Ciphertext<DCRTPoly> &ciphertext1,
	Ciphertext<DCRTPoly> &ciphertext2) const
{

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext1->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {

		CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();

		auto algo = cc->GetEncryptionAlgorithm();

		// First bring both inputs to depth 1 (by rescaling)
		if ( ciphertext1->GetDepth() > 1 )
			ciphertext1 = algo->ModReduceInternal(ciphertext1);
		if ( ciphertext2->GetDepth() > 1 )
			ciphertext2 = algo->ModReduceInternal(ciphertext2);

		if ( ciphertext1->GetLevel() < ciphertext2->GetLevel() ) {
			AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
		} else if ( ciphertext1->GetLevel() > ciphertext2->GetLevel() ) {
			AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
		}

		return LPAlgorithmSHECKKS<DCRTPoly>::EvalMultCore(ciphertext1, ciphertext2);

	} else { // Approximate rescaling
		// Mutable methods are intended only for EXACTRESCALE, which
		// performs rescaling autmotically.
		return EvalMultApprox(ciphertext1, ciphertext2);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
	ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
				ciphertext1->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
		Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

		return EvalMultMutable(c1, c2);

	} else { // Approximate rescaling
		return EvalMultApprox(ciphertext1, ciphertext2);
	}
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
	ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();

	DCRTPoly c2 = plaintext->GetElement<DCRTPoly>();

	if (c2.GetParams()->GetParams().size() >= c1[0].GetParams()->GetParams().size()) {
		size_t towersToDrop = c2.GetParams()->GetParams().size() - c1[0].GetParams()->GetParams().size();
		c2.DropLastElements(towersToDrop);
	} else {
		PALISADE_THROW(not_available_error, "In APPROXRESCALE EvalMult, ciphertext cannot have more towers than the plaintext");
	}

	c2.SetFormat(EVALUATION);

	std::vector<DCRTPoly> cNew;

	for (size_t i = 0; i < c1.size(); i++)
		cNew.push_back((c1[i] * c2));

	newCiphertext->SetElements(std::move(cNew));

	newCiphertext->SetDepth(ciphertext->GetDepth() + plaintext->GetDepth());
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor() * plaintext->GetScalingFactor());
	newCiphertext->SetLevel(ciphertext->GetLevel());

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
	Ciphertext<DCRTPoly> &ciphertext,
	ConstPlaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {

		CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
		auto algo = cc->GetEncryptionAlgorithm();

		// First bring input to depth 1 (by rescaling)
		if ( ciphertext->GetDepth() > 1 )
			ciphertext = algo->ModReduceInternal(ciphertext);

		DCRTPoly c2;
		double ptxSF = 1.0;
		uint32_t ptxDepth = 1;
		std::vector<DCRTPoly> cNew;

		if ( plaintext->GetDepth() != ciphertext->GetDepth() ||
				plaintext->GetLevel() != ciphertext->GetLevel()) {
			// TODO - it's not efficient to re-make the plaintexts
			// Allow for rescaling of plaintexts, and the ability to
			// increase the towers of a plaintext to get better performance.

			vector<complex<double>> values = plaintext->GetCKKSPackedValue();

			Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(), ciphertext->GetLevel());

			c2 = ptx->GetElement<DCRTPoly>();
			ptxSF = ptx->GetScalingFactor();
			ptxDepth = ptx->GetDepth();

		} else {

			c2 = plaintext->GetElement<DCRTPoly>();
			ptxSF = plaintext->GetScalingFactor();
			ptxDepth = plaintext->GetDepth();

		}

		const std::vector<DCRTPoly> &c1 = ciphertext->GetElements();
		c2.SetFormat(EVALUATION);

		for (size_t i = 0; i < c1.size(); i++)
			cNew.push_back((c1[i] * c2));

		Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

		newCiphertext->SetElements(std::move(cNew));
		newCiphertext->SetDepth( ciphertext->GetDepth() + ptxDepth );
		newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ptxSF);
		newCiphertext->SetLevel(ciphertext->GetLevel());

		return newCiphertext;
	} else {
		return EvalMultApprox(ciphertext, plaintext);
	}

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
	ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	// In the case of EXACT RNS rescaling, we automatically rescale ciphertexts that
	// are not at the same level
	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		// We'll need to modify the input ciphertext, so
		// we create copies.
		Ciphertext<DCRTPoly> ctx = ciphertext->Clone();

		return EvalMultMutable(ctx, plaintext);
	} else {
		return EvalMultApprox(ciphertext, plaintext);
	}
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSumInternalMutable(
	vector<Ciphertext<DCRTPoly>> ciphertexts,
	vector<double> constants) const
{
	uint32_t n = ciphertexts.size();

	if (n != constants.size() || n == 0)
		PALISADE_THROW(math_error, "LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSum input vector sizes do not match.");

	Ciphertext<DCRTPoly> weightedSum;

	for (uint32_t i=0; i<n; i++) {

		const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertexts[i]->GetCryptoParameters());

		double adjustedConstant = 1.0;

		if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
			uint32_t numTowers = ciphertexts[i]->GetElements()[0].GetNumOfElements();
			double adjFactor = 1.0;
			double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers-1]->GetModulus().ConvertToDouble();
			double targetSF = cryptoParams->GetScalingFactorOfLevel(ciphertexts[i]->GetLevel()+1);
			double sourceSF = cryptoParams->GetScalingFactorOfLevel(ciphertexts[i]->GetLevel());
			adjFactor = (targetSF/sourceSF)*(targetSF/sourceSF)*(modToDrop/sourceSF);

			adjustedConstant = adjFactor * constants[i];

			if ( i==0 && ciphertexts[i]->GetDepth()==1 ) {
				auto tmp = EvalMultMutable(ciphertexts[i], 1.0);
				weightedSum = EvalMultApprox(tmp, adjustedConstant);
			} else if ( i==0 && ciphertexts[i]->GetDepth()==2 ) {
				weightedSum = EvalMultApprox(ciphertexts[i], adjustedConstant);
			} else if ( i>0 && ciphertexts[i]->GetDepth()==1 ) {
				auto tmp = EvalMultMutable(ciphertexts[i], 1.0);
				auto tmp2 = EvalMultApprox(tmp, adjustedConstant);
				weightedSum = EvalAddApprox(weightedSum, tmp2);
			} else {
				auto tmp = EvalMultApprox(ciphertexts[i], adjustedConstant);
				weightedSum = EvalAddApprox(weightedSum, tmp);
			}

		} else { // APPROXRESCALE
			adjustedConstant = constants[i];

			if (i==0)
				weightedSum = EvalMultApprox(ciphertexts[i], adjustedConstant);
			else
				weightedSum = EvalAddApprox(weightedSum, EvalMultApprox(ciphertexts[i], adjustedConstant));
		}
	}

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(weightedSum->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		CryptoContext<DCRTPoly> cc = weightedSum->GetCryptoContext();

		auto algo = cc->GetEncryptionAlgorithm();

		while ( weightedSum->GetDepth() > 2 ) {
			weightedSum = algo->ModReduceInternal(weightedSum);
		}

		double sf = cryptoParams->GetScalingFactorOfLevel(weightedSum->GetLevel());
		double d = weightedSum->GetDepth();
		weightedSum->SetScalingFactor(pow(sf,d));
	}

	return weightedSum;

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSumMutable(
		vector<Ciphertext<DCRTPoly>> ciphertexts,
		vector<double> constants) const
{
	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertexts[0]->GetCryptoParameters());

	if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE ) {
		// Check to see if input ciphertexts are of same level
		// and adjust if needed to the max level among them
		uint32_t minLevel = ciphertexts[0]->GetLevel();
		uint32_t maxLevel = minLevel;
		for (uint32_t i=1; i<ciphertexts.size(); i++) {
			if ( ciphertexts[i]->GetLevel() > maxLevel )
				maxLevel = ciphertexts[i]->GetLevel();
			if ( ciphertexts[i]->GetLevel() < minLevel )
				minLevel = ciphertexts[i]->GetLevel();
		}

		if (maxLevel != minLevel) {
			// Not all inputs are of same level, and all should be brought to maxLevel
			for (uint32_t i=0; i<ciphertexts.size(); i++) {
				if ( ciphertexts[i]->GetLevel() != maxLevel) {
					CryptoContext<DCRTPoly> cc = ciphertexts[i]->GetCryptoContext();

					auto algo = cc->GetEncryptionAlgorithm();

					if ( ciphertexts[i]->GetDepth() == 2 ) {
						ciphertexts[i] = algo->ModReduceInternal(ciphertexts[i]);
					}

					// Here, cts are all depth 1 and we adjust them to the correct
					// level (i.e., maxLevel, and they become depth 2).
					if (ciphertexts[i]->GetLevel() != maxLevel) {
						AdjustLevelWithoutRescale(ciphertexts[i], maxLevel);
					}
				}
			}

			return EvalLinearWSumInternalMutable(ciphertexts, constants);

		} else {
			// All inputs are of same level, go ahead with rest of logic
			return EvalLinearWSumInternalMutable(ciphertexts, constants);
		}
	} else {
		return EvalLinearWSumInternalMutable(ciphertexts, constants);
	}
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSum(
		vector<Ciphertext<DCRTPoly>> ciphertexts,
		vector<double> constants) const {

	vector<Ciphertext<DCRTPoly>> cts(ciphertexts.size());

	for (uint32_t i=0; i<ciphertexts.size(); i++) {
		cts[i] = ciphertexts[i]->Clone();
	}

	return EvalLinearWSumMutable(cts, constants);
}



template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultAndRelinearize(ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek[0]->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();
	newCiphertext->SetDepth(cipherText->GetDepth());

	std::vector<DCRTPoly> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	DCRTPoly ct0(c[0]);
	DCRTPoly ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	usint depth = cipherText->GetElements().size() - 1;

	DCRTPoly zero = cipherText->GetElements()[0].CloneParametersOnly();
	zero.SetValuesToZero();

	for(size_t j = 0; j<=depth-2; j++){
		size_t index = depth-2-j;

		LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

		// Create a ciphertext with 3 components (0, 0, c[index+2])
		// so KeySwitch returns only the switched parts of c[index+2]
		vector<DCRTPoly> tmp(3);
		tmp[0] = zero;
		tmp[1] = tmp[0];
		tmp[2] = c[index+2];
		Ciphertext<DCRTPoly> cTmp = cipherText->CloneEmpty();
		cTmp->SetElements(tmp);
		cTmp->SetDepth(cipherText->GetDepth());
		cTmp->SetLevel(cipherText->GetLevel());
		cTmp->SetScalingFactor(cipherText->GetScalingFactor());

		Ciphertext<DCRTPoly> cTmp2 = KeySwitch(evalKey, cTmp);

		ct0 += cTmp2->GetElements()[0];
		ct1 += cTmp2->GetElements()[1];
	}

	newCiphertext->SetElements({ ct0, ct1 });

	newCiphertext->SetDepth(cipherText->GetDepth());
	newCiphertext->SetScalingFactor(cipherText->GetScalingFactor());
	newCiphertext->SetLevel(cipherText->GetLevel());

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::Relinearize(ConstCiphertext<DCRTPoly> cipherText, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek[0]->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();
	newCiphertext->SetDepth(cipherText->GetDepth());

	std::vector<DCRTPoly> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	DCRTPoly ct0(c[0]);
	DCRTPoly ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	usint depth = cipherText->GetElements().size() - 1;

	DCRTPoly zero = cipherText->GetElements()[0].CloneParametersOnly();
	zero.SetValuesToZero();

	for(size_t j = 0; j<=depth-2; j++){
		size_t index = depth-2-j;

		LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

		// Create a ciphertext with 3 components (0, 0, c[index+2])
		// so KeySwitch returns only the switched parts of c[index+2]
		vector<DCRTPoly> tmp(3);
		tmp[0] = zero;
		tmp[1] = tmp[0];
		tmp[2] = c[index+2];
		Ciphertext<DCRTPoly> cTmp = cipherText->CloneEmpty();
		cTmp->SetElements(tmp);
		cTmp->SetDepth(cipherText->GetDepth());
		cTmp->SetLevel(cipherText->GetLevel());
		cTmp->SetScalingFactor(cipherText->GetScalingFactor());

		Ciphertext<DCRTPoly> cTmp2 = KeySwitch(evalKey, cTmp);

		ct0 += cTmp2->GetElements()[0];
		ct1 += cTmp2->GetElements()[1];
	}

	newCiphertext->SetElements({ ct0, ct1 });
	newCiphertext->SetLevel(cipherText->GetLevel());
	newCiphertext->SetScalingFactor(cipherText->GetScalingFactor());

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptLead(const LPPrivateKey<DCRTPoly> privateKey,
		ConstCiphertext<DCRTPoly> ciphertext) const
{

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = privateKey->GetCryptoParameters();
		const std::vector<DCRTPoly> &c = ciphertext->GetElements();

		LPPrivateKey<DCRTPoly> sk(privateKey);

		size_t towersToDrop = sk->GetPrivateElement().GetParams()->GetParams().size() - c[0].GetParams()->GetParams().size();

		auto s(sk->GetPrivateElement());
		s.DropLastElements(towersToDrop);

		DCRTPoly b = c[0] + s*c[1];

		Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
		newCiphertext->SetDepth(ciphertext->GetDepth());
		newCiphertext->SetLevel(ciphertext->GetLevel());
		newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());
		newCiphertext->SetElements({ b });

		return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptMain(const LPPrivateKey<DCRTPoly> privateKey,
		ConstCiphertext<DCRTPoly> ciphertext) const
{
		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = privateKey->GetCryptoParameters();
		const std::vector<DCRTPoly> &c = ciphertext->GetElements();

		LPPrivateKey<DCRTPoly> sk(privateKey);

		size_t towersToDrop = sk->GetPrivateElement().GetParams()->GetParams().size() - c[0].GetParams()->GetParams().size();

		auto s(sk->GetPrivateElement());
		s.DropLastElements(towersToDrop);

		DCRTPoly b = s*c[1];

		Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
		newCiphertext->SetDepth(ciphertext->GetDepth());
		newCiphertext->SetLevel(ciphertext->GetLevel());
		newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());
		newCiphertext->SetElements({ b });

		return newCiphertext;
}


template <>
DecryptResult LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptFusion(const vector<Ciphertext<DCRTPoly>>& ciphertextVec,
		Poly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	//const auto p = cryptoParams->GetPlaintextModulus();

	const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
	DCRTPoly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	b.SwitchFormat();

	*plaintext = b.CRTInterpolate();

	return DecryptResult(plaintext->GetLength());

}


template<>
shared_ptr<vector<DCRTPoly>> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeBV(
		ConstCiphertext<DCRTPoly> ciphertext
		) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());
	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	const vector<DCRTPoly> &c = ciphertext->GetElements();
	shared_ptr<vector<DCRTPoly>> digitDecomp(new vector<DCRTPoly>(c[1].CRTDecompose(relinWindow)));

	return digitDecomp;
}

template<>
shared_ptr<vector<DCRTPoly>> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeGHS(
		ConstCiphertext<DCRTPoly> ciphertext
		) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	const vector<DCRTPoly> &c = ciphertext->GetElements();

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();

	DCRTPoly cTmp(c[1]);

	cTmp.SetFormat(Format::COEFFICIENT);

	DCRTPoly pPartExtC = cTmp.ApproxSwitchCRTBasis(paramsQ, paramsP,
			cryptoParamsLWE->GetQHatInvModQTable()[cipherTowers-1],
			cryptoParamsLWE->GetQHatInvModQPreconTable()[cipherTowers-1],
			cryptoParamsLWE->GetQHatModPTable()[cipherTowers-1],
			cryptoParamsLWE->GetModBarretPreconPTable());
	pPartExtC.SetFormat(Format::EVALUATION);

	DCRTPoly expandedC(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);
	for (usint i=0; i<expandedC.GetNumOfElements(); i++) {
		if (i < cipherTowers)
			expandedC.SetElementAtIndex(i, c[1].GetElementAtIndex(i));
		else
			expandedC.SetElementAtIndex(i, pPartExtC.GetElementAtIndex(i-cipherTowers));
	}

	vector<DCRTPoly> result(1);
	result[0] = expandedC;

	shared_ptr<vector<DCRTPoly>> resultPtr = make_shared<vector<DCRTPoly>>(result);

	return resultPtr;
}

template<>
shared_ptr<vector<DCRTPoly>> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeHybrid(
		ConstCiphertext<DCRTPoly> ciphertext
		) const {


	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	DCRTPoly ct0;
	DCRTPoly ct1;

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();

	DCRTPoly cTmp = c[1].Clone();

	uint32_t l = cipherTowers - 1;
	uint32_t alpha = cryptoParamsLWE->GetNumberOfTowersPerDigit();
	uint32_t beta = ceil(((double)(l+1))/alpha); // The number of digits of the current ciphertext
	if (beta > cryptoParamsLWE->GetNumberOfQPartitions())
		beta = cryptoParamsLWE->GetNumberOfQPartitions();

	vector<DCRTPoly> digitsCTmp(beta);

	// Digit decomposition
	// Zero-padding and split
	uint32_t numTowersLastDigit = cryptoParamsLWE->GetQPartition(beta-1)->GetParams().size();
	for (uint32_t j=0; j<beta; j++) {
		if (j == beta-1) {
			auto part = cryptoParamsLWE->GetQPartition(j);
			part->GetParams();

			numTowersLastDigit = cipherTowers - alpha*j;

			vector<NativeInteger> moduli(numTowersLastDigit);
			vector<NativeInteger> roots(numTowersLastDigit);

			for (uint32_t i=0; i<numTowersLastDigit; i++) {
				moduli[i] = part->GetParams()[i]->GetModulus();
				roots[i] = part->GetParams()[i]->GetRootOfUnity();
			}

			auto params = DCRTPoly::Params(part->GetCyclotomicOrder(),
										moduli, roots, {}, {}, 0);

			digitsCTmp[j] = DCRTPoly(std::make_shared<typename DCRTPoly::Params>(params), EVALUATION, true);

		} else
			digitsCTmp[j] = DCRTPoly(cryptoParamsLWE->GetQPartition(j), Format::EVALUATION, true);

		uint32_t iters = (j == beta-1) ? numTowersLastDigit : alpha;
		for (uint32_t i=0; i<iters; i++) {
			if (j*alpha + i <= l) {
				auto tmp = cTmp.GetElementAtIndex(j*alpha+i);
				digitsCTmp[j].SetElementAtIndex(i, tmp);
			}
		}
	}
	// RNS decompose
	for (uint32_t j=0; j<beta; j++) {
		for (uint32_t i=0; i<alpha; i++) {
			if (j*alpha + i <= l) {
				auto tmp = digitsCTmp[j].GetElementAtIndex(i).Times(cryptoParamsLWE->GetQHatInvModqTable()[j][j*alpha+i]);
				digitsCTmp[j].SetElementAtIndex(i, tmp);
			}
		}
	}

	vector<DCRTPoly> pPartExtC(digitsCTmp.size());
	vector<DCRTPoly> expandedC(digitsCTmp.size());
	for (uint32_t j=0; j<digitsCTmp.size(); j++) {
		auto tmpDigit = digitsCTmp[j].Clone();

		tmpDigit.SetFormat(Format::COEFFICIENT);

		const shared_ptr<typename DCRTPoly::Params> params = cryptoParamsLWE->GetComplementaryPartition(cipherTowers-1, j);

		pPartExtC[j] = tmpDigit.ApproxSwitchCRTBasis(cryptoParamsLWE->GetQPartition(j), params, //paramsP,
				cryptoParamsLWE->GetPartitionQHatInvModQTable(j)[digitsCTmp[j].GetNumOfElements()-1],
				cryptoParamsLWE->GetPartitionQHatInvModQPreconTable(j)[digitsCTmp[j].GetNumOfElements()-1],
				cryptoParamsLWE->GetPartitionQHatModPTable(cipherTowers-1)[j],
				cryptoParamsLWE->GetPartitionPrecon(cipherTowers-1)[j]);

		pPartExtC[j].SetFormat(Format::EVALUATION);

		expandedC[j] = DCRTPoly(cTmp.GetExtendedCRTBasis(paramsP), Format::EVALUATION, true);
		for (usint i=0; i<cipherTowers; i++) {
			if (i/alpha == j)
				expandedC[j].SetElementAtIndex(i, digitsCTmp[j].GetElementAtIndex(i % alpha));
			else {
				if (i/alpha < j) {
					expandedC[j].SetElementAtIndex(i, pPartExtC[j].GetElementAtIndex(i));
				} else {
					expandedC[j].SetElementAtIndex(i, pPartExtC[j].GetElementAtIndex(i - alpha));
				}
			}
		}

		for (usint i=0; i<paramsP->GetParams().size(); i++) {
			expandedC[j].SetElementAtIndex(i+cipherTowers, pPartExtC[j].GetElementAtIndex(i + params->GetParams().size() - paramsP->GetParams().size()));
		}
	}

	vector<DCRTPoly> result(expandedC.size());
	for (uint32_t i=0; i<expandedC.size(); i++) {
		result[i] = expandedC[i];
	}

	shared_ptr<vector<DCRTPoly>> resultPtr = make_shared<vector<DCRTPoly>>(result);

	return resultPtr;
}


template<>
shared_ptr<vector<DCRTPoly>> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecompute(
		ConstCiphertext<DCRTPoly> ciphertext
		) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	if (cryptoParamsLWE->GetKeySwitchTechnique() == BV) {
		return EvalFastRotationPrecomputeBV(ciphertext);
	} else if (cryptoParamsLWE->GetKeySwitchTechnique() == GHS) {
		return EvalFastRotationPrecomputeGHS(ciphertext);
	} else { // Hybrid key switching
		return EvalFastRotationPrecomputeHybrid(ciphertext);
	}

}


template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationHybrid(
		ConstCiphertext<DCRTPoly> ciphertext,
		const usint index,
		const usint m,
		const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
		LPEvalKey<DCRTPoly> evalKey
		) const {

	// Find the automorphism index that corresponds to rotation index index.
	usint autoIndex = FindAutomorphismIndex2nComplex(index,m);

	// Apply the automorphism to the first component of the ciphertext.
	DCRTPoly psi_c0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));

	std::vector<DCRTPoly> c(2);

	c[0] = psi_c0;
	c[1] = ciphertext->GetElements()[1].Clone();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(evalKey->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	std::vector<DCRTPoly> b = evalKey->GetBVector();
	std::vector<DCRTPoly> a = evalKey->GetAVector();

	DCRTPoly ct0;
	DCRTPoly ct1;

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();
	size_t towersToSkip = cryptoParamsLWE->GetElementParams()->GetParams().size() - cipherTowers;

	DCRTPoly cTmp, cOrig;

	cOrig = c[1];
	cTmp = c[1].Clone();

	DCRTPoly cTilda0((*expandedCiphertext)[0].GetParams(), Format::EVALUATION, true);
	DCRTPoly cTilda1((*expandedCiphertext)[0].GetParams(), Format::EVALUATION, true);

	for (uint32_t j=0; j<expandedCiphertext->size(); j++) {
		DCRTPoly expandedC((*expandedCiphertext)[j].AutomorphismTransform(autoIndex));

		for (usint i=0; i<expandedC.GetNumOfElements(); i++) {
			usint idx = ( i < cipherTowers ) ? i : i + towersToSkip;
			cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + expandedC.GetElementAtIndex(i) * b[j].GetElementAtIndex(idx));
			cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + expandedC.GetElementAtIndex(i) * a[j].GetElementAtIndex(idx));
		}
	}

	cTilda0.SetFormat(Format::COEFFICIENT);
	cTilda1.SetFormat(Format::COEFFICIENT);

	DCRTPoly cHat0 = cTilda0.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	DCRTPoly cHat1 = cTilda1.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	cHat0.SetFormat(Format::EVALUATION);
	cHat1.SetFormat(Format::EVALUATION);

	ct0 = c[0] + cHat0;
	ct1 = cHat1;

	newCiphertext->SetElements({ ct0, ct1 });

	newCiphertext->SetDepth(ciphertext->GetDepth());
	newCiphertext->SetLevel(ciphertext->GetLevel());
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

	return newCiphertext;
}



template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationGHS(
		ConstCiphertext<DCRTPoly> ciphertext,
		const usint index,
		const usint m,
		const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
		LPEvalKey<DCRTPoly> evalKey
		) const {


	// Find the automorphism index that corresponds to rotation index index.
	usint autoIndex = FindAutomorphismIndex2nComplex(index,m);

	// Apply the automorphism to the first component of the ciphertext.
	DCRTPoly psi_c0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));

	std::vector<DCRTPoly> c(2);

	c[0] = psi_c0;
	c[1] = ciphertext->GetElements()[1].Clone();

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(evalKey->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();

	std::vector<DCRTPoly> b = evalKey->GetBVector();
	std::vector<DCRTPoly> a = evalKey->GetAVector();

	DCRTPoly ct0;
	DCRTPoly ct1;

	const shared_ptr<typename DCRTPoly::Params> paramsQ = c[0].GetParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();

	size_t cipherTowers = c[0].GetParams()->GetParams().size();
	size_t towersToSkip = cryptoParamsLWE->GetElementParams()->GetParams().size() - cipherTowers;

	DCRTPoly cTmp, cOrig;

	cOrig = c[1];
	cTmp = c[1].Clone();

	// Applying the automorphism to the expanded ciphertext.
	DCRTPoly expandedC((*expandedCiphertext)[0].AutomorphismTransform(autoIndex));
	// expandedC is expected to already be in EVAL format. We're doing this to be on the safe side.
	expandedC.SetFormat(EVALUATION);

	DCRTPoly cTilda0(expandedC.GetParams(), Format::EVALUATION, true);
	DCRTPoly cTilda1(expandedC.GetParams(), Format::EVALUATION, true);

	for (usint i=0; i<expandedC.GetNumOfElements(); i++) {
		DCRTPoly::PolyType a_i;
		DCRTPoly::PolyType b_i;
		auto raisedC_i = expandedC.GetElementAtIndex(i);
		// The following skips the switch key elements that are missing from the ciphertext
		if ( i < cipherTowers ) {
			a_i = a[0].GetElementAtIndex(i);
			b_i = b[0].GetElementAtIndex(i);
		} else {
			a_i = a[0].GetElementAtIndex(i + towersToSkip);
			b_i = b[0].GetElementAtIndex(i + towersToSkip);
		}

		cTilda0.SetElementAtIndex(i, raisedC_i * b_i);
		cTilda1.SetElementAtIndex(i, raisedC_i * a_i);
	}

	cTilda0.SetFormat(Format::COEFFICIENT);
	cTilda1.SetFormat(Format::COEFFICIENT);

	DCRTPoly cHat0 = cTilda0.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	DCRTPoly cHat1 = cTilda1.ApproxModDown(paramsQ, paramsP,
			cryptoParamsLWE->GetPInvModQTable(),
			cryptoParamsLWE->GetPInvModQPreconTable(),
			cryptoParamsLWE->GetPHatInvModPTable(),
			cryptoParamsLWE->GetPHatInvModPPreconTable(),
			cryptoParamsLWE->GetPHatModQTable(),
			cryptoParamsLWE->GetModBarretPreconQTable());

	cHat0.SetFormat(Format::EVALUATION);
	cHat1.SetFormat(Format::EVALUATION);

	ct0 = c[0] + cHat0;
	ct1 = cHat1;

	newCiphertext->SetElements({ ct0, ct1 });

	newCiphertext->SetDepth(ciphertext->GetDepth());
	newCiphertext->SetLevel(ciphertext->GetLevel());
	newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

	return newCiphertext;
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationBV(
		ConstCiphertext<DCRTPoly> ciphertext,
		const usint index,
		const usint m,
		const shared_ptr<vector<DCRTPoly>> digits,
		LPEvalKey<DCRTPoly> evalKey
		) const {
	/*
	 * This method performs a rotation using the algorithm for hoisted
	 * automorphisms from paper by Halevi and Shoup, "Faster Homomorphic
	 * linear transformations in HELib.", link:
	 * https://eprint.iacr.org/2018/244.
	 *
	 * Overview:
	 * 1. Break into digits (done by EvalFastRotationPrecompute)
	 * 2. Automorphism step
	 * 3. Key switching step
	 *
	 */

	Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	// Find the automorphism index that corresponds to rotation index index.
	usint autoIndex = FindAutomorphismIndex2nComplex(index,m);

	// Get the parts of the automorphism key
	std::vector<DCRTPoly> b = evalKey->GetBVector();
	std::vector<DCRTPoly> a = evalKey->GetAVector();

	// Drop the unnecessary moduli to get better performance.
	auto bTowers = b[0].GetParams()->GetParams().size();
	auto cTowers = c[0].GetParams()->GetParams().size();
	size_t towersToDrop = bTowers - cTowers;
	for (size_t k = 0; k < b.size(); k++) {
		a[k].DropLastElements(towersToDrop);
		b[k].DropLastElements(towersToDrop);
	}

	// Create a copy of the input digit decomposition to avoid
	// changing the input.
	std::vector<DCRTPoly> digitsCopy(*digits);


	/* (2) Apply the automorphism on the digits and the first
	 * component of the input ciphertext p0.
	 * p'_0 = psi(p0)
	 * q'_k = psi(q_k), where q_k are the digits.
	 */
	for (size_t i=0; i < digitsCopy.size(); i++) {
		digitsCopy[i] = digitsCopy[i].AutomorphismTransform(autoIndex);
	}
	DCRTPoly p0Prime(c[0].AutomorphismTransform(autoIndex));
	DCRTPoly p1DoublePrime;

	/* (3) Do key switching on intermediate ciphertext tmp = (p'_0, p'_1),
	 * where p'_1 = Sum_k( q'_k * D_k ), where D_k is the decomposition
	 * constants.
	 *
	 * p''_0 = Sum_k( q'_k * A_k ), for all k.
	 * p''_1 = Sum_k( q'_k * B_k ), for all k.
	 */
	p1DoublePrime = digitsCopy[0] * a[0];
	auto p0DoublePrime = digitsCopy[0] * b[0];

	for (usint i = 1; i < digitsCopy.size(); ++i)
	{
		p0DoublePrime += digitsCopy[i] * b[i];
		p1DoublePrime += digitsCopy[i] * a[i];
	}

	/* Ciphertext c_out = (p'_0 + p''_0, p''_1) is the result of the
	 * automorphism.
	 */
	result->SetElements({ p0Prime + p0DoublePrime, p1DoublePrime });
	result->SetDepth(ciphertext->GetDepth());
	result->SetLevel(ciphertext->GetLevel());
	result->SetScalingFactor(ciphertext->GetScalingFactor());

	return result;
}


template<>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotation(
		ConstCiphertext<DCRTPoly> ciphertext,
		const usint index,
		const usint m,
		const shared_ptr<vector<DCRTPoly>> precomp
		) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
				std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ciphertext->GetCryptoParameters());

	// Return unchanged if no rotation is required
	if (index == 0) {
		CiphertextImpl<DCRTPoly> res(*(ciphertext.get()));
		return std::make_shared<CiphertextImpl<DCRTPoly>>( res );
	}

	// Find the automorphism index that corresponds to rotation index index.
	usint autoIndex = FindAutomorphismIndex2nComplex(index,m);

	// Retrieve the automorphism key that corresponds to the auto index.
	auto autok = ciphertext->GetCryptoContext()->
			GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag()).
			find(autoIndex)->second;

	if (cryptoParamsLWE->GetKeySwitchTechnique() == BV) {
		return EvalFastRotationBV(ciphertext, index, m, precomp, autok);
	} else if (cryptoParamsLWE->GetKeySwitchTechnique() == GHS) {
		return EvalFastRotationGHS(ciphertext, index, m, precomp, autok);
	} else { // Hybrid key switching
		return EvalFastRotationHybrid(ciphertext, index, m, precomp, autok);
	}

}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGenBV(const LPPublicKey<DCRTPoly> newPK,
		const LPPrivateKey<DCRTPoly> origPrivateKey) const {

	// Get crypto context of new public key.
	auto cc = newPK->GetCryptoContext();

	// Create an evaluation key that will contain all the re-encryption key elements.
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newPK->GetCryptoParameters());
	const shared_ptr<DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

	const DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	DCRTPoly::DugType dug;
	DCRTPoly::TugType tug;

	const DCRTPoly &oldKey = origPrivateKey->GetPrivateElement();

	std::vector<DCRTPoly> evalKeyElements;
	std::vector<DCRTPoly> evalKeyElementsGenerated;

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	const DCRTPoly &p0 = newPK->GetPublicElements().at(0);
	const DCRTPoly &p1 = newPK->GetPublicElements().at(1);

	for (usint i = 0; i < oldKey.GetNumOfElements(); i++)
	{

		if (relinWindow>0)
		{
			vector<DCRTPoly::PolyType> decomposedKeyElements = oldKey.GetElementAtIndex(i).PowersOfBase(relinWindow);

			for (size_t k = 0; k < decomposedKeyElements.size(); k++)
			{

				// Creates an element with all zeroes
				DCRTPoly filtered(elementParams,EVALUATION,true);

				filtered.SetElementAtIndex(i,decomposedKeyElements[k]);

				DCRTPoly u;

				if (cryptoParamsLWE->GetMode() == RLWE)
					u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
				else
					u = DCRTPoly(tug, elementParams, Format::EVALUATION);

				DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
				DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

				DCRTPoly c0(elementParams);
				DCRTPoly c1(elementParams);

				c0 = p0*u + e1 + filtered;

				c1 = p1*u + e2;

				DCRTPoly a(dug, elementParams, Format::EVALUATION);
				evalKeyElementsGenerated.push_back(c1);

				DCRTPoly e(dgg, elementParams, Format::EVALUATION);
				evalKeyElements.push_back(c0);
			}
		}
		else
		{

			// Creates an element with all zeroes
			DCRTPoly filtered(elementParams,EVALUATION,true);

			filtered.SetElementAtIndex(i,oldKey.GetElementAtIndex(i));

			DCRTPoly u;

			if (cryptoParamsLWE->GetMode() == RLWE)
				u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
			else
				u = DCRTPoly(tug, elementParams, Format::EVALUATION);

			DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
			DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

			DCRTPoly c0(elementParams);
			DCRTPoly c1(elementParams);

			c0 = p0*u + e1 + filtered;

			c1 = p1*u + e2;

			DCRTPoly a(dug, elementParams, Format::EVALUATION);
			evalKeyElementsGenerated.push_back(c1);

			DCRTPoly e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements.push_back(c0);
		}

	}

	ek->SetAVector(std::move(evalKeyElementsGenerated));
	ek->SetBVector(std::move(evalKeyElements));

	return ek;

}


template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGenGHS(
		const LPPublicKey<DCRTPoly> newPublicKey,
		const LPPrivateKey<DCRTPoly> originalPrivateKey) const {

	auto cc = newPublicKey->GetCryptoContext();
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newPublicKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> paramsQ = cryptoParamsLWE->GetElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsP = cryptoParamsLWE->GetAuxElementParams();
	const shared_ptr<typename DCRTPoly::Params> paramsQP = cryptoParamsLWE->GetExtendedElementParams();

	DCRTPoly s1 = originalPrivateKey->GetPrivateElement();
	DCRTPoly pk0 = newPublicKey->GetPublicElements()[0].Clone();
	DCRTPoly pk1 = newPublicKey->GetPublicElements()[1].Clone();

	const DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	DCRTPoly::TugType tug;

	DCRTPoly v;
	if (cryptoParamsLWE->GetMode() == RLWE)
		v = DCRTPoly(dgg, paramsQP, Format::EVALUATION);
	else
		v = DCRTPoly(tug, paramsQP, Format::EVALUATION);

	const DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
	const DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

	DCRTPoly a(paramsQP, Format::EVALUATION, true);
	DCRTPoly b(paramsQP, Format::EVALUATION, true);

	vector<NativeInteger> PModQj = cryptoParamsLWE->GetPModQTable();

	for (usint i=0; i<paramsQP->GetParams().size(); i++) {
		auto v_i = v.GetElementAtIndex(i);
		auto e0_i = e0.GetElementAtIndex(i);
		auto e1_i = e1.GetElementAtIndex(i);
		auto pk0_i = pk0.GetElementAtIndex(i);
		auto pk1_i = pk1.GetElementAtIndex(i);

		if (i < paramsQ->GetParams().size()) { // The part with basis Q
			auto s1_i = s1.GetElementAtIndex(i);
			b.SetElementAtIndex(i, v_i * pk0_i + PModQj[i] * s1_i + e0_i);
		} else { // The part with basis P
			b.SetElementAtIndex(i, v_i * pk0_i + e0_i);
		}
		a.SetElementAtIndex(i, v_i * pk1_i + e1_i);
	}

	vector<DCRTPoly> av(1);
	av[0] = a;
	vector<DCRTPoly> bv(1);
	bv[0] = b;

	ek->SetAVector(std::move(av));
	ek->SetBVector(std::move(bv));

	return ek;
}


template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGen(const LPPublicKey<DCRTPoly> newPK,
		const LPPrivateKey<DCRTPoly> origPrivateKey) const {

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(newPK->GetCryptoParameters());

	if (cryptoParamsLWE->GetKeySwitchTechnique() == BV) {
		return ReKeyGenBV(newPK, origPrivateKey);
	} else if (cryptoParamsLWE->GetKeySwitchTechnique() == GHS) {
		std::string errMsg =
				"ReKeyGen - Proxy re-encryption not supported when using GHS key switching.";
		PALISADE_THROW(not_available_error, errMsg);
	} else { // Hybrid
		std::string errMsg =
				"ReKeyGen - Proxy re-encryption not supported when using HYBRID key switching.";
		PALISADE_THROW(not_available_error, errMsg);
	}

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReEncrypt(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> ciphertext,
	const LPPublicKey<DCRTPoly> publicKey) const
{

	const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
					std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(ek->GetCryptoParameters());

	if ( cryptoParamsLWE->GetKeySwitchTechnique() != BV ) {
		std::string errMsg =
				"ReEncrypt - Proxy re-encryption is only supported when using BV key switching.";
		PALISADE_THROW(not_available_error, errMsg);
	}

	if (publicKey == nullptr) { // Sender PK is not provided - CPA-secure PRE
		return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
	} else { // Sender PK provided - HRA-secure PRE
		// Get crypto and elements parameters
		const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

		const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
		typename DCRTPoly::TugType tug;

		PlaintextEncodings encType = ciphertext->GetEncodingType();

		Ciphertext<DCRTPoly> zeroCiphertext(new CiphertextImpl<DCRTPoly>(publicKey));
		zeroCiphertext->SetEncodingType(encType);

		const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
		const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

		DCRTPoly u;

		if (cryptoParamsLWE->GetMode() == RLWE)
			u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
		else
			u = DCRTPoly(tug, elementParams, Format::EVALUATION);

		DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
		DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

		DCRTPoly c0 = p0*u + e1;
		DCRTPoly c1 = p1*u + e2;

		zeroCiphertext->SetElements({ c0, c1 });

		// Add the encryption of zero for re-randomization purposes
		auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(ciphertext, zeroCiphertext);

		return ciphertext->GetCryptoContext()->KeySwitch(ek, c);

	}

}

}
