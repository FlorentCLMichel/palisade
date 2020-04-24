/*
* @file bfvrnsB-impl.cpp - template instantiations and methods for the BFVrnsB scheme
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

#include "cryptocontext.h"
#include "bfvrnsB.cpp"

//#define USE_KARATSUBA

namespace lbcrypto {

#define NOPOLY \
		std::string errMsg = "BFVrnsB does not support Poly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY \
		std::string errMsg = "BFVrnsB does not support NativePoly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB() : m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(shared_ptr<typename Poly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(shared_ptr<typename NativePoly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(shared_ptr<typename Poly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(shared_ptr<typename NativePoly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrnsB<Poly>::PrecomputeCRTTables(){
	NOPOLY
}

template <>
bool LPCryptoParametersBFVrnsB<NativePoly>::PrecomputeCRTTables(){
	NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<Poly>::LPPublicKeyEncryptionSchemeBFVrnsB(){
	NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<NativePoly>::LPPublicKeyEncryptionSchemeBFVrnsB(){
	NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t n) const
{
	NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<NativePoly>::ParamsGen(shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t n) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(const LPPublicKey<NativePoly> publicKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
		ConstCiphertext<Poly> ciphertext,
		NativePoly *plaintext) const
{
	NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
		ConstCiphertext<NativePoly> ciphertext,
		NativePoly *plaintext) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(const LPPrivateKey<Poly> privateKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(const LPPrivateKey<NativePoly> privateKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMult(ConstCiphertext<Poly> ciphertext1,
	ConstCiphertext<Poly> ciphertext2) const {
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMult(ConstCiphertext<NativePoly> ciphertext1,
	ConstCiphertext<NativePoly> ciphertext2) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalAdd(ConstCiphertext<Poly> ct,
		ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalAdd(ConstCiphertext<NativePoly> ct,
		ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalSub(ConstCiphertext<Poly> ct,
	ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalSub(ConstCiphertext<NativePoly> ct,
	ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrnsB<Poly>::KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
	const LPPrivateKey<Poly> newPrivateKey) const {
	NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitchGen(const LPPrivateKey<NativePoly> originalPrivateKey,
	const LPPrivateKey<NativePoly> newPrivateKey) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::KeySwitch(const LPEvalKey<Poly> keySwitchHint,
	ConstCiphertext<Poly> cipherText) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitch(const LPEvalKey<NativePoly> keySwitchHint,
	ConstCiphertext<NativePoly> cipherText) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMultAndRelinearize(ConstCiphertext<Poly> ct1,
	ConstCiphertext<Poly> ct, const vector<LPEvalKey<Poly>> &ek) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMultAndRelinearize(ConstCiphertext<NativePoly> ct1,
	ConstCiphertext<NativePoly> ct, const vector<LPEvalKey<NativePoly>> &ek) const{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<Poly>::MultipartyDecryptFusion(const vector<Ciphertext<Poly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<NativePoly>::MultipartyDecryptFusion(const vector<Ciphertext<NativePoly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NONATIVEPOLY
}

template class LPCryptoParametersBFVrnsB<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<Poly>;
template class LPAlgorithmBFVrnsB<Poly>;
template class LPAlgorithmSHEBFVrnsB<Poly>;
template class LPAlgorithmMultipartyBFVrnsB<Poly>;
template class LPAlgorithmParamsGenBFVrnsB<Poly>;

template class LPCryptoParametersBFVrnsB<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<NativePoly>;
template class LPAlgorithmBFVrnsB<NativePoly>;
template class LPAlgorithmSHEBFVrnsB<NativePoly>;
template class LPAlgorithmMultipartyBFVrnsB<NativePoly>;
template class LPAlgorithmParamsGenBFVrnsB<NativePoly>;

#undef NOPOLY
#undef NONATIVEPOLY

// Precomputation of CRT tables encryption, decryption, and homomorphic multiplication
template <>
bool LPCryptoParametersBFVrnsB<DCRTPoly>::PrecomputeCRTTables(){

	// read values for the CRT basis

	size_t size = GetElementParams()->GetParams().size();
	auto n = GetElementParams()->GetRingDimension();

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456"); // 2^128
	const BigInteger TwoPower64("18446744073709551616"); // 2^64

	m_qModuli.resize(size);
	for (size_t i = 0; i < size; i++){
		moduli[i] = GetElementParams()->GetParams()[i]->GetModulus();
		roots[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
		m_qModuli[i] = moduli[i];
	}

	//compute the CRT delta table floor(Q/p) mod qi - used for encryption

	const BigInteger modulusQ = GetElementParams()->GetModulus();

	const BigInteger deltaBig = modulusQ.DividedBy(GetPlaintextModulus());

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	m_qModulimu.resize(size);
	for (uint32_t i = 0; i< m_qModulimu.size(); i++ )
	{
		BigInteger mu = BarrettBase128Bit/BigInteger(m_qModuli[i]);
		uint64_t val[2];
		val[0] = (mu % TwoPower64).ConvertToInt();
		val[1] = mu.RShift(64).ConvertToInt();

		memcpy(&m_qModulimu[i], val, sizeof(DoubleNativeInt));
	}

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots,2*n,moduli);

	// Compute Bajard's et al. RNS variant lookup tables

	// Populate EvalMulrns tables
	// find the a suitable size of B
	m_numq = size;

	// find m_tilde [we need to ensure that m_tilde is < Bsk moduli to avoid one extra modulo in Small_Montgomery_Reduction]
	m_mtilde = PreviousPrime<NativeInteger>(moduli[m_numq-1], 2 * n);

	BigInteger t = BigInteger(GetPlaintextModulus());
	BigInteger q(GetElementParams()->GetModulus());

	BigInteger B = 1;
	BigInteger maxConvolutionValue = BigInteger(4) * BigInteger(n) * q * q * t;

	m_BModuli.push_back( PreviousPrime<NativeInteger>(m_mtilde, 2 * n) );
	m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_BModuli[0]) );
	B = B * BigInteger(m_BModuli[0]);

	int i = 1; // we already added one prime
	while ( q*B < maxConvolutionValue )
	{
		m_BModuli.push_back( PreviousPrime<NativeInteger>(m_BModuli[i-1], 2 * n) );
		m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_BModuli[i]) );

		B = B * BigInteger(m_BModuli[i]);
		i++;
	}

	m_numB = i;

	// find msk
	m_msk = PreviousPrime<NativeInteger>(m_BModuli[m_numB-1], 2 * n);
	m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_msk) );

	m_BskModuli = m_BModuli;
	m_BskModuli.push_back( m_msk );

	m_BskmtildeModuli = m_BskModuli;

	m_paramsBsk = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, m_BskModuli, m_BskRoots));

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(m_BskRoots, 2 * n, m_BskModuli);

	// finally add m_tilde as last modulus in the chain
	m_BskmtildeModuli.push_back( m_mtilde );

	// populate Barrett constant for m_BskmtildeModuli
	m_BskmtildeModulimu.resize( m_BskmtildeModuli.size() );
	for (uint32_t i = 0; i< m_BskmtildeModulimu.size(); i++ )
	{
		BigInteger mu = BarrettBase128Bit/BigInteger(m_BskmtildeModuli[i]);
		uint64_t val[2];
		val[0] = (mu % TwoPower64).ConvertToInt();
		val[1] = mu.RShift(64).ConvertToInt();

		memcpy(&m_BskmtildeModulimu[i], val, sizeof(DoubleNativeInt));
	}

	// Populate Barrett constants for BskModuli
	m_BskModulimu.resize(m_BskModuli.size());
	for (uint32_t i = 0; i < m_numB + 1; i++)
		m_BskModulimu[i] = m_BskmtildeModulimu[i]; // mtilde is last (ignored)


	// Populate (q/qi)^-1 mod qi
	m_qDivqiModqiTable.resize(m_numq);
	for (uint32_t i = 0; i < m_qDivqiModqiTable.size() ; i++ )
	{
		BigInteger qDivqi;
		qDivqi = q.DividedBy(moduli[i]) ;
		qDivqi = qDivqi.Mod(moduli[i]);
		qDivqi = qDivqi.ModInverse( moduli[i] );
		m_qDivqiModqiTable[i] = qDivqi.ConvertToInt();
	}

	// Populate t*(q/qi)^-1 mod qi
	m_tqDivqiModqiTable.resize(m_numq);
	m_tqDivqiModqiPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_tqDivqiModqiTable.size() ; i++ )
	{
		BigInteger tqDivqi;
		tqDivqi = q.DividedBy(moduli[i]) ;
		tqDivqi = tqDivqi.Mod(moduli[i]);
		tqDivqi = tqDivqi.ModInverse( moduli[i] );
		tqDivqi = tqDivqi.ModMul( t.ConvertToInt() , moduli[i] );
		m_tqDivqiModqiTable[i] = tqDivqi.ConvertToInt();
		m_tqDivqiModqiPreconTable[i] = m_tqDivqiModqiTable[i].PrepModMulConst( moduli[i] );
	}

	// Populate q/qi mod Bj table where Bj \in {Bsk U mtilde}
	m_qDivqiModBskmtildeTable.resize(m_numq);
	for (uint32_t i = 0; i < m_qDivqiModBskmtildeTable.size(); i++)
	{
		m_qDivqiModBskmtildeTable[i].resize( m_numB + 2);

		BigInteger qDivqi = q.DividedBy(moduli[i]);
		for (uint32_t j = 0; j < m_qDivqiModBskmtildeTable[i].size(); j++)
		{
			BigInteger qDivqiModBj = qDivqi.Mod(m_BskmtildeModuli[j]);
			m_qDivqiModBskmtildeTable[i][j] = qDivqiModBj.ConvertToInt();
		}
	}

	// Populate mtilde*(q/qi)^-1 mod qi table
	m_mtildeqDivqiTable.resize(m_numq);
	m_mtildeqDivqiPreconTable.resize(m_numq);

	BigInteger bmtilde(m_mtilde);
	for (uint32_t i = 0; i < m_mtildeqDivqiTable.size() ; i++ )
	{
		BigInteger qDivqi = q.DividedBy(moduli[i]);
		qDivqi = qDivqi.Mod(moduli[i]);
		qDivqi = qDivqi.ModInverse( moduli[i] );
		qDivqi = qDivqi * bmtilde;
		qDivqi = qDivqi.Mod(moduli[i]);
		m_mtildeqDivqiTable[i] = qDivqi.ConvertToInt();
		m_mtildeqDivqiPreconTable[i] = m_mtildeqDivqiTable[i].PrepModMulConst( moduli[i] );
	}

	// Populate -1/q mod mtilde
	BigInteger negqInvModmtilde = (BigInteger(m_mtilde-1) * q.ModInverse(m_mtilde));
	negqInvModmtilde = negqInvModmtilde.Mod(m_mtilde);
	m_negqInvModmtilde = negqInvModmtilde.ConvertToInt();
	m_negqInvModmtildePrecon = m_negqInvModmtilde.PrepModMulConst(m_mtilde);

	// Populate q mod Bski
	m_qModBskiTable.resize(m_numB + 1);
	m_qModBskiPreconTable.resize(m_numB + 1);

	for (uint32_t i = 0; i < m_qModBskiTable.size(); i++)
	{
		BigInteger qModBski = q.Mod(m_BskModuli[i]);
		m_qModBskiTable[i] = qModBski.ConvertToInt();
		m_qModBskiPreconTable[i] = m_qModBskiTable[i].PrepModMulConst(m_BskModuli[i]);
	}

	// Populate mtilde^-1 mod Bski
	m_mtildeInvModBskiTable.resize( m_numB + 1 );
	m_mtildeInvModBskiPreconTable.resize( m_numB + 1 );
	for (uint32_t i = 0; i < m_mtildeInvModBskiTable.size(); i++)
	{
		BigInteger mtildeInvModBski = m_mtilde % m_BskModuli[i];
		mtildeInvModBski = mtildeInvModBski.ModInverse(m_BskModuli[i]);
		m_mtildeInvModBskiTable[i] = mtildeInvModBski.ConvertToInt();
		m_mtildeInvModBskiPreconTable[i] = m_mtildeInvModBskiTable[i].PrepModMulConst(m_BskModuli[i]);
	}

	// Populate q^-1 mod Bski
	m_qInvModBskiTable.resize(m_numB + 1);
	m_qInvModBskiPreconTable.resize(m_numB + 1);

	for (uint32_t i = 0; i < m_qInvModBskiTable.size(); i++)
	{
		BigInteger qInvModBski = q.ModInverse(m_BskModuli[i]);
		m_qInvModBskiTable[i] = qInvModBski.ConvertToInt();
		m_qInvModBskiPreconTable[i] = m_qInvModBskiTable[i].PrepModMulConst( m_BskModuli[i] );
	}

	// Populate (B/Bi)^-1 mod Bi
	m_BDivBiModBiTable.resize(m_numB);
	m_BDivBiModBiPreconTable.resize(m_numB);

	for (uint32_t i = 0; i < m_BDivBiModBiTable.size(); i++)
	{
		BigInteger BDivBi;
		BDivBi = B.DividedBy(m_BModuli[i]) ;
		BDivBi = BDivBi.Mod(m_BModuli[i]);
		BDivBi = BDivBi.ModInverse( m_BModuli[i] );
		m_BDivBiModBiTable[i] = BDivBi.ConvertToInt();
		m_BDivBiModBiPreconTable[i] = m_BDivBiModBiTable[i].PrepModMulConst(m_BModuli[i]);
	}

	// Populate B/Bi mod qj table (Matrix) where Bj \in {q}
	m_BDivBiModqTable.resize(m_numB);
	for (uint32_t i = 0; i < m_BDivBiModqTable.size(); i++)
	{
		m_BDivBiModqTable[i].resize(m_numq);
		BigInteger BDivBi = B.DividedBy(m_BModuli[i]);
		for (uint32_t j = 0; j<m_BDivBiModqTable[i].size(); j++)
		{
			BigInteger BDivBiModqj = BDivBi.Mod(moduli[j]);
			m_BDivBiModqTable[i][j] = BDivBiModqj.ConvertToInt();
		}
	}

	// Populate B/Bi mod msk
	m_BDivBiModmskTable.resize(m_numB);
	for (uint32_t i = 0; i < m_BDivBiModmskTable.size(); i++)
	{
		BigInteger BDivBi = B.DividedBy(m_BModuli[i]);
		m_BDivBiModmskTable[i] = (BDivBi.Mod(m_msk)).ConvertToInt();
	}

	// Populate B^-1 mod msk
	m_BInvModmsk = (B.ModInverse(m_msk)).ConvertToInt();
	m_BInvModmskPrecon = m_BInvModmsk.PrepModMulConst( m_msk );

	// Populate B mod qi
	m_BModqiTable.resize(m_numq);
	m_BModqiPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_BModqiTable.size(); i++)
	{
		m_BModqiTable[i] = (B.Mod( moduli[i] )).ConvertToInt();
		m_BModqiPreconTable[i] = m_BModqiTable[i].PrepModMulConst( moduli[i] );
	}

	// Populate Decrns lookup tables
	// choose gamma
	m_gamma = PreviousPrime<NativeInteger>(m_mtilde, 2 * n);

	m_gammaInvModt = m_gamma.ModInverse(t.ConvertToInt());
	m_gammaInvModtPrecon = m_gammaInvModt.PrepModMulConst( t.ConvertToInt() );

	BigInteger negqModt = ((t-BigInteger(1)) * q.ModInverse(t));
	BigInteger negqModgamma = (BigInteger(m_gamma-1) * q.ModInverse(m_gamma));
	m_negqInvModtgammaTable.resize(2);
	m_negqInvModtgammaPreconTable.resize(2);

	m_negqInvModtgammaTable[0] = negqModt.Mod(t).ConvertToInt();
	m_negqInvModtgammaPreconTable[0] = m_negqInvModtgammaTable[0].PrepModMulConst( t.ConvertToInt() );

	m_negqInvModtgammaTable[1] = negqModgamma.Mod(m_gamma).ConvertToInt();
	m_negqInvModtgammaPreconTable[1] = m_negqInvModtgammaTable[1].PrepModMulConst(m_gamma);

	// Populate q/qi mod mj table where mj \in {t U gamma}
	m_qDivqiModtgammaTable.resize(m_numq);
	m_qDivqiModtgammaPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_qDivqiModtgammaTable.size(); i++)
	{
		m_qDivqiModtgammaTable[i].resize(2);
		m_qDivqiModtgammaPreconTable[i].resize(2);

		BigInteger qDivqi = q.DividedBy(moduli[i]);

		BigInteger qDivqiModt = qDivqi.Mod(t);
		m_qDivqiModtgammaTable[i][0] = qDivqiModt.ConvertToInt();
		m_qDivqiModtgammaPreconTable[i][0] = m_qDivqiModtgammaTable[i][0].PrepModMulConst( t.ConvertToInt() );

		BigInteger qDivqiModgamma = qDivqi.Mod(m_gamma);
		m_qDivqiModtgammaTable[i][1] = qDivqiModgamma.ConvertToInt();
		m_qDivqiModtgammaPreconTable[i][1] = m_qDivqiModtgammaTable[i][1].PrepModMulConst( m_gamma );

	}

	// populate (t*gamma*q/qi)^-1 mod qi
	m_tgammaqDivqiModqiTable.resize( m_numq );
	m_tgammaqDivqiModqiPreconTable.resize(m_numq);

	BigInteger bmgamma(m_gamma);
	for (uint32_t i = 0; i < m_tgammaqDivqiModqiTable.size(); i++)
	{
		BigInteger qDivqi = q.DividedBy(moduli[i]);
		BigInteger imod( moduli[i] );
		qDivqi = qDivqi.ModInverse( moduli[i] );
		BigInteger gammaqDivqi = (qDivqi*bmgamma) % imod;
		BigInteger tgammaqDivqi = (gammaqDivqi*t) % imod;
		m_tgammaqDivqiModqiTable[i] = tgammaqDivqi.ConvertToInt();
		m_tgammaqDivqiModqiPreconTable[i] = m_tgammaqDivqiModqiTable[i].PrepModMulConst( moduli[i] );
	}

	return true;
}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrnsB<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t nCustom) const
{
#ifdef NO_EXTENDEDDOUBLE
    PALISADE_THROW(not_available_error, "BFVrnsB is not available on this architecture");
	return (0);
#else
	if (!cryptoParams)
		PALISADE_THROW(not_available_error, "No crypto parameters are supplied to BFVrnsB ParamsGen");

	if ((dcrtBits < 30) || (dcrtBits > 60))
		PALISADE_THROW(math_error, "BFVrnsB.ParamsGen: Number of bits in CRT moduli should be in the range from 30 to 60");

#ifdef NO_QUADMATH
	if (dcrtBits >= 58)
	  	PALISADE_THROW(math_error, "BFVrnsB.ParamsGen: Number of bits in CRT moduli should be in < 58 for this architecture");

#endif
	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsBFVrnsB = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(cryptoParams);

	ExtendedDouble sigma = ExtendedDouble(cryptoParamsBFVrnsB->GetDistributionParameter());
	ExtendedDouble alpha = ExtendedDouble(cryptoParamsBFVrnsB->GetAssuranceMeasure());
	ExtendedDouble hermiteFactor = ExtendedDouble(cryptoParamsBFVrnsB->GetSecurityLevel());
	ExtendedDouble p = ExtendedDouble(cryptoParamsBFVrnsB->GetPlaintextModulus());
	uint32_t relinWindow = cryptoParamsBFVrnsB->GetRelinWindow();
	SecurityLevel stdLevel = cryptoParamsBFVrnsB->GetStdLevel();

	//Bound of the Gaussian error polynomial
	ExtendedDouble Berr = sigma*ext_double::sqrt(alpha);

	//Bound of the key polynomial
	ExtendedDouble Bkey;

	DistributionType distType;

	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsBFVrnsB->GetMode() == RLWE) {
		Bkey = sigma*ext_double::sqrt(alpha);
		distType = HEStd_error;
	}
	else
	{
		Bkey = 1;
		distType = HEStd_ternary;
	}

	//expansion factor delta
	// We use the worst-case bound as the central limit theorem cannot be applied in this case
	auto delta = [](uint32_t n) -> ExtendedDouble { return ExtendedDouble(2*sqrt(n)); };

	auto Vnorm = [&](uint32_t n) -> ExtendedDouble { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](ExtendedDouble q) -> ExtendedDouble {
		if (stdLevel == HEStd_NotSet) {
			return ext_double::log(q / sigma) / (ExtendedDouble(4) * ext_double::log(hermiteFactor));
		}
		else
		{
			return (ExtendedDouble)StdLatticeParm::FindRingDim(distType,stdLevel,
					ext_double::to_long(ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2))));
		}
	};

	//initial values
	uint32_t n;

	if (nCustom > 0)
		n = nCustom;
	else
		n = 512;

	ExtendedDouble q = ExtendedDouble(0);

	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qBFV = [&](uint32_t n) -> ExtendedDouble { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qBFV(n);

		if ((nRLWE(q) > n) && (nCustom > 0))
			PALISADE_THROW(config_error,"Ring dimension n specified by the user does not meet the security requirement. Please increase it.");

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qBFV(n);
		}

		// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

		int32_t k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));

		ExtendedDouble qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);

		while (nRLWE(qCeil) > n) {
			n = 2 * n;
			q = qBFV(n);
			k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));
			qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);
		}

	}
	// this case supports automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		ExtendedDouble w;
		if (relinWindow == 0)
			w = pow(2, dcrtBits);
		else
			w = pow(2, relinWindow);

		//Correctness constraint
		auto qBFV = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*
				(ext_double::floor(ext_double::log(qPrev) / ExtendedDouble(log(2)*dcrtBits)) + 1)*w*Berr) + p);  };

		//initial values
		ExtendedDouble qPrev = ExtendedDouble(1e6);
		q = qBFV(n, qPrev);
		qPrev = q;

		if ((nRLWE(q) > n) && (nCustom > 0))
			PALISADE_THROW(config_error,"Ring dimension n specified by the user does not meet the security requirement. Please increase it.");

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theoretically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (ext_double::fabs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

			// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

			int32_t k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));

			ExtendedDouble qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);
			qPrev = qCeil;

			while (nRLWE(qCeil) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));
				qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);
				qPrev = qCeil;
			}

		}

	}
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		ExtendedDouble w;
		if (relinWindow == 0)
			w = pow(2, dcrtBits);
		else
			w = pow(2, relinWindow);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> ExtendedDouble { return 4 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> ExtendedDouble { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return delta(n)*delta(n)*Bkey*(Bkey + p*p)
				+ delta(n)*(ext_double::floor(ext_double::log(qPrev) / ExtendedDouble(log(2)*dcrtBits)) + 1)*w*Berr;  };

		//main correctness constraint
		auto qBFV = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return p*(2 *
				(ext_double::power(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*ext_double::power(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		ExtendedDouble qPrev = ExtendedDouble(1e6);
		q = qBFV(n, qPrev);
		qPrev = q;

		if ((nRLWE(q) > n) && (nCustom > 0))
			PALISADE_THROW(config_error,"Ring dimension n specified by the user does not meet the security requirement. Please increase it.");

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theoretically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (ext_double::fabs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

			// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

			int32_t k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));

			ExtendedDouble qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);
			qPrev = qCeil;

			while (nRLWE(qCeil) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				k = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));
				qCeil = ext_double::power((ExtendedDouble)2,k*dcrtBits);
				qPrev = qCeil;
			}

		}

	}

	size_t size = ext_double::to_long(ext_double::ceil((ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2)) + ExtendedDouble(1.0)) / (ExtendedDouble)dcrtBits));

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	//makes sure the first integer is less than 2^60-1 to take advantage of NTL optimizations
	NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);

	moduli[0] = PreviousPrime<NativeInteger>(firstInteger, 2 * n);
	roots[0] = RootOfUnity<NativeInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size; i++)
	{
		moduli[i] = PreviousPrime<NativeInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<NativeInteger>(2 * n, moduli[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots,2*n,moduli);

	cryptoParamsBFVrnsB->SetElementParams(params);

	// if no batch size was specified, we set batchSize = n by default (for full packing)
	const EncodingParams encodingParams = cryptoParamsBFVrnsB->GetEncodingParams();
	if (encodingParams->GetBatchSize() == 0)
	{
		uint32_t batchSize = n;
		EncodingParams encodingParamsNew(new EncodingParamsImpl(encodingParams->GetPlaintextModulus(),batchSize));
		cryptoParamsBFVrnsB->SetEncodingParams(encodingParamsNew);
	}

	return cryptoParamsBFVrnsB->PrecomputeCRTTables();
#endif //ifdef NO_EXTENDEDDOUBLE
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsB<DCRTPoly>::Encrypt(const LPPublicKey<DCRTPoly> publicKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(publicKey) );

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SetFormat(Format::EVALUATION);

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::TugType tug;

	const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
	const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

	DCRTPoly u;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
	else
		u = DCRTPoly(tug, elementParams, Format::EVALUATION);

	DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
	DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(elementParams);
	DCRTPoly c1(elementParams);

	c0 = p0*u + e1 + ptxt.Times(deltaTable);

	c1 = p1*u + e2;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

 template <>
DecryptResult LPAlgorithmBFVrnsB<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
		ConstCiphertext<DCRTPoly> ciphertext,
		NativePoly *plaintext) const
{
	//TimeVar t_total;

	//TIC(t_total);

	 const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsBFVrnsB =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrnsB->GetElementParams();

	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly sPower = s;

	DCRTPoly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	DCRTPoly cTemp;
	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	// Converts back to coefficient representation
	b.SwitchFormat();

	auto &t = cryptoParamsBFVrnsB->GetPlaintextModulus();

	// Invoke BFVrnsB DecRNS

	const std::vector<NativeInteger> &paramsqModuliTable = cryptoParamsBFVrnsB->GetDCRTParamsqModuli();
	const NativeInteger &paramsgamma = cryptoParamsBFVrnsB->GetDCRTParamsgamma();
	const NativeInteger &paramsgammaInvModt = cryptoParamsBFVrnsB->GetDCRTParamsgammaInvModt();
	const NativeInteger &paramsgammaInvModtPrecon = cryptoParamsBFVrnsB->GetDCRTParamsgammaInvModtPrecon();
	const std::vector<NativeInteger> &paramsnegqInvModtgammaTable = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModtgammaTable();
	const std::vector<NativeInteger> &paramsnegqInvModtgammaPreconTable = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModtgammaPreconTable();
	const std::vector<NativeInteger> &paramstgammaqDivqiModqiTable = cryptoParamsBFVrnsB->GetDCRTParamstgammaqDivqiModqiTable();
	const std::vector<NativeInteger> &paramstgammaqDivqiModqiPreconTable = cryptoParamsBFVrnsB->GetDCRTParamstgammaqDivqiModqiPreconTable();
	const std::vector<std::vector<NativeInteger>> &paramsqDivqiModtgammaTable = cryptoParamsBFVrnsB->GetDCRTParamsqDivqiModtgammaTable();
	const std::vector<std::vector<NativeInteger>> &paramsqDivqiModtgammaPreconTable = cryptoParamsBFVrnsB->GetDCRTParamsqDivqiModtgammaPreconTable();

	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(paramsqModuliTable,
			paramsgamma,
			t,
			paramsgammaInvModt,
			paramsgammaInvModtPrecon,
			paramsnegqInvModtgammaTable,
			paramsnegqInvModtgammaPreconTable,
			paramstgammaqDivqiModqiTable,
			paramstgammaqDivqiModqiPreconTable,
			paramsqDivqiModtgammaTable,
			paramsqDivqiModtgammaPreconTable);

	//std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" << std::endl;

	return DecryptResult(plaintext->GetLength());

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsB<DCRTPoly>::Encrypt(const LPPrivateKey<DCRTPoly> privateKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(privateKey) );

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(privateKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	DCRTPoly a(dug, elementParams, Format::EVALUATION);
	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly e(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(a*s + e + ptxt.Times(deltaTable));
	DCRTPoly c1(elementParams, Format::EVALUATION, true);
	c1 -= a;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext,
		ConstPlaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	const DCRTPoly& ptElement = plaintext->GetElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] + ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalSub(ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] - ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFVrnsB::EvalMult crypto parameters are not the same";
		PALISADE_THROW(config_error, errMsg);
	}

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsBFVrnsB =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());

	//Get the ciphertext elements
	std::vector<DCRTPoly> cipherText1Elements = ciphertext1->GetElements();
	std::vector<DCRTPoly> cipherText2Elements = ciphertext2->GetElements();

	size_t cipherText1ElementsSize = cipherText1Elements.size();
	size_t cipherText2ElementsSize = cipherText2Elements.size();
	size_t cipherTextRElementsSize = cipherText1ElementsSize + cipherText2ElementsSize - 1;

	std::vector<DCRTPoly> c(cipherTextRElementsSize);

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrnsB->GetElementParams();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsBsk = cryptoParamsBFVrnsB->GetDCRTParamsBsk();
	const std::vector<NativeInteger> &paramsqModuli = cryptoParamsBFVrnsB->GetDCRTParamsqModuli();
	const std::vector<DoubleNativeInt> &paramsqModulimu = cryptoParamsBFVrnsB->GetDCRTParamsqModulimu();
	const std::vector<NativeInteger> &paramsBskModuli = cryptoParamsBFVrnsB->GetDCRTParamsBskModuli();
	const std::vector<DoubleNativeInt> &paramsBskModulimu = cryptoParamsBFVrnsB->GetDCRTParamsBskModulimu();
	const std::vector<NativeInteger> &paramsBskmtildeModuli = cryptoParamsBFVrnsB->GetDCRTParamsBskmtildeModuli();
	const std::vector<DoubleNativeInt> &paramsBskmtildeModulimu = cryptoParamsBFVrnsB->GetDCRTParamsBskmtildeModulimu();
	const std::vector<NativeInteger> &paramsmtildeqDivqiModqi = cryptoParamsBFVrnsB->GetDCRTParamsmtildeqDivqiModqi();
	const std::vector<NativeInteger> &paramsmtildeqDivqiModqiPrecon = cryptoParamsBFVrnsB->GetDCRTParamsmtildeqDivqiModqiPrecon();
	const std::vector<std::vector<NativeInteger>> &paramsqDivqiModBskmtilde = cryptoParamsBFVrnsB->GetDCRTParamsqDivqiModBskmtilde();
	const std::vector<NativeInteger> &paramsqModBski = cryptoParamsBFVrnsB->GetDCRTParamsqModBski();
	const std::vector<NativeInteger> &paramsqModBskiPrecon = cryptoParamsBFVrnsB->GetDCRTParamsqModBskiPrecon();
	const NativeInteger &paramsnegqInvModmtilde = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModmtilde();
	const NativeInteger &paramsnegqInvModmtildePrecon = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModmtildePrecon();
	const std::vector<NativeInteger> &paramsmtildeInvModBskiTable = cryptoParamsBFVrnsB->GetDCRTParamsmtildeInvModBskiTable();
	const std::vector<NativeInteger> &paramsmtildeInvModBskiPreconTable = cryptoParamsBFVrnsB->GetDCRTParamsmtildeInvModBskiPreconTable();

	// Expands the CRT basis to q*Bsk; Outputs the polynomials in coeff representation

	for(size_t i=0; i<cipherText1ElementsSize; i++)
	{
		cipherText1Elements[i].FastBaseConvqToBskMontgomery(paramsBsk,
				paramsqModuli,
				paramsBskmtildeModuli,
				paramsBskmtildeModulimu,
				paramsmtildeqDivqiModqi,
				paramsmtildeqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqModBski,
				paramsqModBskiPrecon,
				paramsnegqInvModmtilde,
				paramsnegqInvModmtildePrecon,
				paramsmtildeInvModBskiTable,
				paramsmtildeInvModBskiPreconTable);
		if (cipherText1Elements[i].GetFormat() == COEFFICIENT) {
			cipherText1Elements[i].SwitchFormat();
		}
	}

	for(size_t i=0; i<cipherText2ElementsSize; i++)
	{
		cipherText2Elements[i].FastBaseConvqToBskMontgomery(paramsBsk,
				paramsqModuli,
				paramsBskmtildeModuli,
				paramsBskmtildeModulimu,
				paramsmtildeqDivqiModqi,
				paramsmtildeqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqModBski,
				paramsqModBskiPrecon,
				paramsnegqInvModmtilde,
				paramsnegqInvModmtildePrecon,
				paramsmtildeInvModBskiTable,
				paramsmtildeInvModBskiPreconTable);
		if (cipherText2Elements[i].GetFormat() == COEFFICIENT) {
			cipherText2Elements[i].SwitchFormat();
		}
	}

	// Performs the multiplication itself

#ifdef USE_KARATSUBA

	if (cipherText1ElementsSize == 2 && cipherText2ElementsSize == 2) // size of each ciphertxt = 2, use Karatsuba
	{

		c[0] = cipherText1Elements[0] * cipherText2Elements[0]; // a
		c[2] = cipherText1Elements[1] * cipherText2Elements[1]; // b

		c[1] = cipherText1Elements[0] + cipherText1Elements[1];
		c[1] *= (cipherText2Elements[0] + cipherText2Elements[1]);
		c[1] -= c[2];
		c[1] -= c[0];

	}
	else // if size of any of the ciphertexts > 2
	{
		bool *isFirstAdd = new bool[cipherTextRElementsSize];
		std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

		for(size_t i=0; i<cipherText1ElementsSize; i++){
			for(size_t j=0; j<cipherText2ElementsSize; j++){

				if(isFirstAdd[i+j] == true){
					c[i+j] = cipherText1Elements[i] * cipherText2Elements[j];
					isFirstAdd[i+j] = false;
				}
				else{
					c[i+j] += cipherText1Elements[i] * cipherText2Elements[j];
				}
			}
		}

		delete []isFirstAdd;
	}

#else
	bool *isFirstAdd = new bool[cipherTextRElementsSize];
	std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

	for(size_t i=0; i<cipherText1ElementsSize; i++){
		for(size_t j=0; j<cipherText2ElementsSize; j++){

			if(isFirstAdd[i+j] == true){
				c[i+j] = cipherText1Elements[i] * cipherText2Elements[j];
				isFirstAdd[i+j] = false;
			}
			else{
				c[i+j] += cipherText1Elements[i] * cipherText2Elements[j];
			}
		}
	}

	delete []isFirstAdd;
#endif

	// perfrom RNS approximate Flooring
	const NativeInteger &paramsPlaintextModulus = cryptoParamsBFVrnsB->GetPlaintextModulus();
	const std::vector<NativeInteger> &paramstqDivqiModqi = cryptoParamsBFVrnsB->GetDCRTParamstqDivqiModqiTable();
	const std::vector<NativeInteger> &paramstqDivqiModqiPrecon = cryptoParamsBFVrnsB->GetDCRTParamstqDivqiModqiPreconTable();
	const std::vector<NativeInteger> &paramsqInvModBi = cryptoParamsBFVrnsB->GetDCRTParamsqInvModBiTable();
	const std::vector<NativeInteger> &paramsqInvModBiPrecon = cryptoParamsBFVrnsB->GetDCRTParamsqInvModBiPreconTable();

	// perform FastBaseConvSK
	const std::vector<NativeInteger> &paramsBDivBiModBi = cryptoParamsBFVrnsB->GetBDivBiModBi();
	const std::vector<NativeInteger> &paramsBDivBiModBiPrecon = cryptoParamsBFVrnsB->GetBDivBiModBiPrecon();
	const std::vector<NativeInteger> &paramsBDivBiModmsk = cryptoParamsBFVrnsB->GetBDivBiModmsk();
	const NativeInteger &paramsBInvModmsk = cryptoParamsBFVrnsB->GetBInvModmsk();
	const NativeInteger &paramsBInvModmskPrecon = cryptoParamsBFVrnsB->GetBInvModmskPrecon();
	const std::vector<std::vector<NativeInteger>> &paramsBDivBiModqj = cryptoParamsBFVrnsB->GetBDivBiModqj();
	const std::vector<NativeInteger> &paramsBModqi = cryptoParamsBFVrnsB->GetBModqi();
	const std::vector<NativeInteger> &paramsBModqiPrecon = cryptoParamsBFVrnsB->GetBModqiPrecon();

	for(size_t i=0; i<cipherTextRElementsSize; i++){
		//converts to coefficient representation before rounding
		c[i].SwitchFormat();
		// Performs the scaling by t/q followed by rounding; the result is in the CRT basis Bsk
		c[i].FastRNSFloorq(paramsPlaintextModulus,
				paramsqModuli,
				paramsBskModuli,
				paramsBskModulimu,
				paramstqDivqiModqi,
				paramstqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqInvModBi,
				paramsqInvModBiPrecon);
		// Converts from the CRT basis Bsk to q
		c[i].FastBaseConvSK(paramsqModuli,
				paramsqModulimu,
				paramsBskModuli,
				paramsBskModulimu,
				paramsBDivBiModBi,
				paramsBDivBiModBiPrecon,
				paramsBDivBiModmsk,
				paramsBInvModmsk,
				paramsBInvModmskPrecon,
				paramsBDivBiModqj,
				paramsBModqi,
				paramsBModqiPrecon);
	}

	newCiphertext->SetElements(c);
	newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

	return newCiphertext;

}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::KeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	LPEvalKey<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const DCRTPoly &s = newPrivateKey->GetPrivateElement();

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const DCRTPoly &oldKey = originalPrivateKey->GetPrivateElement();

	std::vector<DCRTPoly> evalKeyElements;
	std::vector<DCRTPoly> evalKeyElementsGenerated;

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	for (usint i = 0; i < oldKey.GetNumOfElements(); i++)
	{

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
				evalKeyElementsGenerated.push_back(a);

				// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
				DCRTPoly e(dgg, elementParams, Format::EVALUATION);
				evalKeyElements.push_back(filtered - (a*s + e));
			}
		}
		else
		{

			// Creates an element with all zeroes
			DCRTPoly filtered(elementParams,EVALUATION,true);

			filtered.SetElementAtIndex(i,oldKey.GetElementAtIndex(i));

			// Generate a_i vectors
			DCRTPoly a(dug, elementParams, Format::EVALUATION);
			evalKeyElementsGenerated.push_back(a);

			// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
			DCRTPoly e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements.push_back(filtered - (a*s + e));
		}

	}

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::KeySwitch(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	const std::vector<DCRTPoly> &b = evalKey->GetAVector();
	const std::vector<DCRTPoly> &a = evalKey->GetBVector();

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<DCRTPoly> digitsC2;

	DCRTPoly ct0(c[0]);

	//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
	if (c.size() > 2)
		ct0.SwitchFormat();

	DCRTPoly ct1;

	if (c.size() == 2) //case of automorphism
	{
		digitsC2 = c[1].CRTDecompose(relinWindow);
		ct1 = digitsC2[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC2 = c[2].CRTDecompose(relinWindow);
		ct1 = c[1];
		//Convert ct1 to evaluation representation
		ct1.SwitchFormat();
		ct1 += digitsC2[0] * a[0];

	}

	ct0 += digitsC2[0] * b[0];

	for (usint i = 1; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalMultAndRelinearize(ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ek[0]->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	std::vector<DCRTPoly> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	DCRTPoly ct0(c[0]);
	DCRTPoly ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	for(size_t j = 0; j<=cipherText->GetDepth()-2; j++){
		size_t index = cipherText->GetDepth()-2-j;
		LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

		const std::vector<DCRTPoly> &b = evalKey->GetAVector();
		const std::vector<DCRTPoly> &a = evalKey->GetBVector();

		std::vector<DCRTPoly> digitsC2 = c[index+2].CRTDecompose();

		for (usint i = 0; i < digitsC2.size(); ++i){
			ct0 += digitsC2[i] * b[i];
			ct1 += digitsC2[i] * a[i];
		}
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;

}


template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBFVrnsB<DCRTPoly>::ReKeyGen(const LPPublicKey<DCRTPoly> newPK,
		const LPPrivateKey<DCRTPoly> origPrivateKey) const {

	// Get crypto context of new public key.
	auto cc = newPK->GetCryptoContext();

	// Create an evaluation key that will contain all the re-encryption key elements.
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(newPK->GetCryptoParameters());
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

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmPREBFVrnsB<DCRTPoly>::ReEncrypt(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> ciphertext,
	const LPPublicKey<DCRTPoly> publicKey) const
{
	if (publicKey == nullptr) { // Sender PK is not provided - CPA-secure PRE
		return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
	} else { // Sender PK provided - HRA-secure PRE

		const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsLWE =
						std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ek->GetCryptoParameters());

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

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<DCRTPoly>::MultipartyDecryptFusion(const vector<Ciphertext<DCRTPoly>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParametersBFVrnsB<DCRTPoly>> cryptoParamsBFVrnsB =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(ciphertextVec[0]->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrnsB->GetElementParams();

	const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
	DCRTPoly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	auto &t = cryptoParamsBFVrnsB->GetPlaintextModulus();

	// Invoke BFVrnsB DecRNS

	const std::vector<NativeInteger> &paramsqModuliTable = cryptoParamsBFVrnsB->GetDCRTParamsqModuli();
	const NativeInteger &paramsgamma = cryptoParamsBFVrnsB->GetDCRTParamsgamma();
	const NativeInteger &paramsgammaInvModt = cryptoParamsBFVrnsB->GetDCRTParamsgammaInvModt();
	const NativeInteger &paramsgammaInvModtPrecon = cryptoParamsBFVrnsB->GetDCRTParamsgammaInvModtPrecon();
	const std::vector<NativeInteger> &paramsnegqInvModtgammaTable = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModtgammaTable();
	const std::vector<NativeInteger> &paramsnegqInvModtgammaPreconTable = cryptoParamsBFVrnsB->GetDCRTParamsnegqInvModtgammaPreconTable();
	const std::vector<NativeInteger> &paramstgammaqDivqiModqiTable = cryptoParamsBFVrnsB->GetDCRTParamstgammaqDivqiModqiTable();
	const std::vector<NativeInteger> &paramstgammaqDivqiModqiPreconTable = cryptoParamsBFVrnsB->GetDCRTParamstgammaqDivqiModqiPreconTable();
	const std::vector<std::vector<NativeInteger>> &paramsqDivqiModtgammaTable = cryptoParamsBFVrnsB->GetDCRTParamsqDivqiModtgammaTable();
	const std::vector<std::vector<NativeInteger>> &paramsqDivqiModtgammaPreconTable = cryptoParamsBFVrnsB->GetDCRTParamsqDivqiModtgammaPreconTable();

	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(paramsqModuliTable,
			paramsgamma,
			t,
			paramsgammaInvModt,
			paramsgammaInvModtPrecon,
			paramsnegqInvModtgammaTable,
			paramsnegqInvModtgammaPreconTable,
			paramstgammaqDivqiModqiTable,
			paramstgammaqDivqiModqiPreconTable,
			paramsqDivqiModtgammaTable,
			paramsqDivqiModtgammaPreconTable);


	return DecryptResult(plaintext->GetLength());

}


template class LPCryptoParametersBFVrnsB<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<DCRTPoly>;
template class LPAlgorithmBFVrnsB<DCRTPoly>;
template class LPAlgorithmSHEBFVrnsB<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrnsB<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrnsB<DCRTPoly>;

}
