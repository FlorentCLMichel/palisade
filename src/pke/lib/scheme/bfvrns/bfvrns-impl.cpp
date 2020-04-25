/*
* @file bfvrns-impl.cpp - template instantiations and methods for the BFVrns scheme
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
#include "bfvrns.cpp"

namespace lbcrypto {

#define NOPOLY \
		std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY \
		std::string errMsg = "BFVrns does not support NativePoly. Use DCRTPoly instead."; \
		PALISADE_THROW(not_implemented_error, errMsg);

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(shared_ptr<typename NativePoly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(shared_ptr<typename NativePoly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrns<Poly>::PrecomputeCRTTables(){
	NOPOLY
}

template <>
bool LPCryptoParametersBFVrns<NativePoly>::PrecomputeCRTTables(){
	NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<Poly>::LPPublicKeyEncryptionSchemeBFVrns(){
	NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<NativePoly>::LPPublicKeyEncryptionSchemeBFVrns(){
	NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t n) const
{
	NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<NativePoly>::ParamsGen(shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t n) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(const LPPublicKey<NativePoly> publicKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
		ConstCiphertext<Poly> ciphertext,
		NativePoly *plaintext) const
{
	NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
		ConstCiphertext<NativePoly> ciphertext,
		NativePoly *plaintext) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(const LPPrivateKey<Poly> privateKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(const LPPrivateKey<NativePoly> privateKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMult(ConstCiphertext<Poly> ciphertext1,
	ConstCiphertext<Poly> ciphertext2) const {
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMult(ConstCiphertext<NativePoly> ciphertext1,
	ConstCiphertext<NativePoly> ciphertext2) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalAdd(ConstCiphertext<Poly> ct,
		ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalAdd(ConstCiphertext<NativePoly> ct,
		ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalSub(ConstCiphertext<Poly> ct,
	ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalSub(ConstCiphertext<NativePoly> ct,
	ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrns<Poly>::KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
	const LPPrivateKey<Poly> newPrivateKey) const {
	NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::KeySwitchGen(const LPPrivateKey<NativePoly> originalPrivateKey,
	const LPPrivateKey<NativePoly> newPrivateKey) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::KeySwitch(const LPEvalKey<Poly> keySwitchHint,
	ConstCiphertext<Poly> cipherText) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::KeySwitch(const LPEvalKey<NativePoly> keySwitchHint,
	ConstCiphertext<NativePoly> cipherText) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMultAndRelinearize(ConstCiphertext<Poly> ct1,
	ConstCiphertext<Poly> ct, const vector<LPEvalKey<Poly>> &ek) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMultAndRelinearize(ConstCiphertext<NativePoly> ct1,
	ConstCiphertext<NativePoly> ct, const vector<LPEvalKey<NativePoly>> &ek) const{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<Poly>::MultipartyDecryptFusion(const vector<Ciphertext<Poly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<NativePoly>::MultipartyDecryptFusion(const vector<Ciphertext<NativePoly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmMultipartyBFVrns<Poly>::MultiKeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey, const LPPrivateKey<Poly> newPrivateKey,
	const LPEvalKey<Poly> ek) const {
	NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmMultipartyBFVrns<NativePoly>::MultiKeySwitchGen(const LPPrivateKey<NativePoly> originalPrivateKey, const LPPrivateKey<NativePoly> newPrivateKey,
	const LPEvalKey<NativePoly> ek) const {
	NONATIVEPOLY
}

template class LPCryptoParametersBFVrns<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrns<Poly>;
template class LPAlgorithmBFVrns<Poly>;
template class LPAlgorithmPREBFVrns<Poly>;
template class LPAlgorithmSHEBFVrns<Poly>;
template class LPAlgorithmMultipartyBFVrns<Poly>;
template class LPAlgorithmParamsGenBFVrns<Poly>;

template class LPCryptoParametersBFVrns<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<NativePoly>;
template class LPAlgorithmBFVrns<NativePoly>;
template class LPAlgorithmPREBFVrns<NativePoly>;
template class LPAlgorithmSHEBFVrns<NativePoly>;
template class LPAlgorithmMultipartyBFVrns<NativePoly>;
template class LPAlgorithmParamsGenBFVrns<NativePoly>;

#undef NOPOLY
#undef NONATIVEPOLY

// Precomputation of CRT tables encryption, decryption, and homomorphic multiplication
template <>
bool LPCryptoParametersBFVrns<DCRTPoly>::PrecomputeCRTTables(){

	// read values for the CRT basis

	size_t size = GetElementParams()->GetParams().size();
	size_t n = GetElementParams()->GetRingDimension();

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);
	for (size_t i = 0; i < size; i++){
		moduli[i] = GetElementParams()->GetParams()[i]->GetModulus();
		roots[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
	}

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots,2*n,moduli);

	// computes the auxiliary CRT basis S=s1*s2*..sn used in homomorphic multiplication

	size_t sizeS = size + 1;

	vector<NativeInteger> moduliS(sizeS);
	vector<NativeInteger> rootsS(sizeS);

	moduliS[0] = PreviousPrime<NativeInteger>(moduli[size-1], 2 * n);
	rootsS[0] = RootOfUnity<NativeInteger>(2 * n, moduliS[0]);

	for (size_t i = 1; i < sizeS; i++)
	{
		moduliS[i] = PreviousPrime<NativeInteger>(moduliS[i-1], 2 * n);
		rootsS[i] = RootOfUnity<NativeInteger>(2 * n, moduliS[i]);
	}

	m_paramsS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliS, rootsS));

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsS,2*n,moduliS);

	// stores the parameters for the auxiliary expanded CRT basis Q*S = v1*v2*...*vn used in homomorphic multiplication

	vector<NativeInteger> moduliExpanded(size + sizeS);
	vector<NativeInteger> rootsExpanded(size + sizeS);

	// populate moduli for CRT basis Q
	for (size_t i = 0; i < size; i++ ) {
		moduliExpanded[i] = moduli[i];
		rootsExpanded[i] = roots[i];
	}

	// populate moduli for CRT basis S
	for (size_t i = 0; i < sizeS; i++ ) {
		moduliExpanded[size + i] = moduliS[i];
		rootsExpanded[size + i] = rootsS[i];
	}

	m_paramsQS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliExpanded, rootsExpanded));

	const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456"); // 2^128
	const BigInteger TwoPower64("18446744073709551616"); // 2^64

	// Precomputations for Barrett modulo reduction
	m_qModulimu.resize(size);
	for (uint32_t i = 0; i< moduli.size(); i++ )
	{
		BigInteger mu = BarrettBase128Bit/BigInteger(moduli[i]);
		uint64_t val[2];
		val[0] = (mu % TwoPower64).ConvertToInt();
		val[1] = mu.RShift(64).ConvertToInt();

		memcpy(&m_qModulimu[i], val, sizeof(DoubleNativeInt));
	}

	// Precomputations for Barrett modulo reduction
	m_sModulimu.resize(sizeS);
	for (uint32_t i = 0; i< moduliS.size(); i++ )
	{
		BigInteger mu = BarrettBase128Bit/BigInteger(moduliS[i]);
		uint64_t val[2];
		val[0] = (mu % TwoPower64).ConvertToInt();
		val[1] = mu.RShift(64).ConvertToInt();

		memcpy(&m_sModulimu[i], val, sizeof(DoubleNativeInt));
	}

	const BigInteger modulusQ = GetElementParams()->GetModulus();

	if (moduli[0].GetMSB() < 45)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<double> CRTDecryptionFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus())).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionFloatTable[i] = (double)numerator/(double)denominator;
		}
		m_CRTDecryptionFloatTable = CRTDecryptionFloatTable;
	}
	else if (moduli[0].GetMSB() < 58)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<long double> CRTDecryptionExtFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus())).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionExtFloatTable[i] = (long double)numerator/(long double)denominator;
		}
		m_CRTDecryptionExtFloatTable = CRTDecryptionExtFloatTable;
	}
	else
	{
#ifndef NO_QUADMATH	  
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<QuadFloat> CRTDecryptionQuadFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus())).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionQuadFloatTable[i] = ext_double::quadFloatFromInt64(numerator)/ext_double::quadFloatFromInt64(denominator);
		}
		m_CRTDecryptionQuadFloatTable = CRTDecryptionQuadFloatTable;
#else
		PALISADE_THROW(math_error, "BFVrns.PrecomputeCRTTables: Number of bits in CRT moduli should be in < 58 for this architecture");

#endif
	}

	//compute the table of integer factors floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p - used in decryption

	std::vector<NativeInteger> qDecryptionInt(size);
	std::vector<NativeInteger> qDecryptionIntPrecon(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*BigInteger(GetPlaintextModulus())/qi;
		qDecryptionInt[vi] = quotient.Mod(GetPlaintextModulus()).ConvertToInt();
		qDecryptionIntPrecon[vi] = qDecryptionInt[vi].PrepModMulConst(GetPlaintextModulus());
	}

	m_CRTDecryptionIntTable = qDecryptionInt;
	m_CRTDecryptionIntPreconTable = qDecryptionIntPrecon;

	//compute the CRT delta table floor(Q/p) mod qi - used for encryption

	const BigInteger deltaBig = modulusQ.DividedBy(GetPlaintextModulus());

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	//compute the (Q/qi)^{-1} mod qi table - used for homomorphic multiplication and key switching

	std::vector<NativeInteger> qInv(size);
	std::vector<NativeInteger> qInvPrecon(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		qInv[vi] = divBy.ModInverse(qi).Mod(qi).ConvertToInt();
		qInvPrecon[vi] = qInv[vi].PrepModMulConst(qi.ConvertToInt());
	}

	m_CRTInverseTable = qInv;
	m_CRTInversePreconTable = qInvPrecon;

	// compute the (Q/qi) mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> qDivqiModsi(sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduli[vIndex].ConvertToInt());
			BigInteger divBy = modulusQ / qi;
			qDivqiModsi[newvIndex].push_back(divBy.Mod(si).ConvertToInt());
		}
	}

	m_CRTqDivqiModsiTable = qDivqiModsi;

	// compute the Q mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> qModsi(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		qModsi[vi] = modulusQ.Mod(si).ConvertToInt();
	}

	m_CRTqModsiTable = qModsi;

	// compute the [p*S*(Q*S/vi)^{-1}]_vi / vi table - used for homomorphic multiplication

	std::vector<long double> precomputedDCRTMultFloatTable(size);

	const BigInteger modulusS = m_paramsS->GetModulus();
	const BigInteger modulusQS = m_paramsQS->GetModulus();

	const BigInteger modulusP( GetPlaintextModulus() );

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduliExpanded[i].ConvertToInt());
		precomputedDCRTMultFloatTable[i] =
				(long double)((modulusQS.DividedBy(qi)).ModInverse(qi)*modulusS*modulusP).Mod(qi).ConvertToInt()/(long double)qi.ConvertToInt();
	}

	m_CRTMultFloatTable = precomputedDCRTMultFloatTable;

	// compute the floor[p*S*[(Q*S/vi)^{-1}]_vi/vi] mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> multInt(size+1);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduliExpanded[vIndex].ConvertToInt());
			BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(qi)).ModInverse(qi));
			BigInteger divBy = num / qi;
			multInt[vIndex].push_back(divBy.Mod(si).ConvertToInt());
		}

		BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(si)).ModInverse(si));
		BigInteger divBy = num / si;
		multInt[size].push_back(divBy.Mod(si).ConvertToInt());
	}

	m_CRTMultIntTable = multInt;

	// compute the (S/si)^{-1} mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> sInv(sizeS);
	std::vector<NativeInteger> sInvPrecon(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		BigInteger divBy = modulusS / si;
		sInv[vi] = divBy.ModInverse(si).Mod(si).ConvertToInt();
		sInvPrecon[vi] = sInv[vi].PrepModMulConst(si.ConvertToInt());
	}

	m_CRTSInverseTable = sInv;
	m_CRTSInversePreconTable = sInvPrecon;

	// compute (S/si) mod qi table - used for homomorphic multiplication
	std::vector<std::vector<NativeInteger>> sDivsiModqi(size);
	for( usint newvIndex = 0 ; newvIndex < size; newvIndex++ ) {
		BigInteger qi = BigInteger(moduli[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < sizeS; vIndex++ ) {
			BigInteger si = BigInteger(moduliS[vIndex].ConvertToInt());
			BigInteger divBy = modulusS / si;
			sDivsiModqi[newvIndex].push_back(divBy.Mod(qi).ConvertToInt());
		}
	}

	m_CRTsDivsiModqiTable = sDivsiModqi;

	// compute S mod qi table - used for homomorphic multiplication
	std::vector<NativeInteger> sModqi(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		sModqi[vi] = modulusS.Mod(qi).ConvertToInt();
	}

	m_CRTsModqiTable = sModqi;

	return true;

}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrns<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits, uint32_t nCustom) const
{

#ifdef NO_EXTENDEDDOUBLE
      PALISADE_THROW(not_available_error, "BFVrns is not available on this architecture");
	return (0);
#else


	if (!cryptoParams)
		PALISADE_THROW(not_available_error, "No crypto parameters are supplied to BFVrns ParamsGen");

	if ((dcrtBits < 30) || (dcrtBits > 60))
		PALISADE_THROW(math_error, "BFVrns.ParamsGen: Number of bits in CRT moduli should be in the range from 30 to 60");

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoParams);

	ExtendedDouble sigma = ExtendedDouble(cryptoParamsBFVrns->GetDistributionParameter());
	ExtendedDouble alpha = ExtendedDouble(cryptoParamsBFVrns->GetAssuranceMeasure());
	ExtendedDouble hermiteFactor = ExtendedDouble(cryptoParamsBFVrns->GetSecurityLevel());
	ExtendedDouble p = ExtendedDouble(cryptoParamsBFVrns->GetPlaintextModulus());
	uint32_t relinWindow = cryptoParamsBFVrns->GetRelinWindow();
	SecurityLevel stdLevel = cryptoParamsBFVrns->GetStdLevel();

	//Bound of the Gaussian error polynomial
	ExtendedDouble Berr = sigma*ext_double::sqrt(alpha);

	//Bound of the key polynomial
	ExtendedDouble Bkey;

	DistributionType distType;

	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsBFVrns->GetMode() == RLWE) {
		Bkey = sigma*ext_double::sqrt(alpha);
		distType = HEStd_error;
	}
	else
	{
		Bkey = 1;
		distType = HEStd_ternary;
	}

	//expansion factor delta
	auto delta = [](uint32_t n) -> ExtendedDouble { return ExtendedDouble(2*sqrt(n)); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> ExtendedDouble { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](ExtendedDouble q) -> ExtendedDouble {
		if (stdLevel == HEStd_NotSet) {
			return ext_double::log(q / sigma) / (ExtendedDouble(4) * ext_double::log(hermiteFactor));
		}
		else
		{
			return (ExtendedDouble)StdLatticeParm::FindRingDim(distType,stdLevel,ext_double::to_long(ext_double::ceil(ext_double::log(q)/(ExtendedDouble)log(2))));
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
		auto qBFV = [&](uint32_t n) -> ExtendedDouble { return p*(4*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

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
		auto qBFV = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return p*(4*(Vnorm(n) + keySwitchCount*delta(n)*
				(ext_double::floor(ext_double::log(qPrev) / (ExtendedDouble(log(2)*dcrtBits))) + 1)*w*Berr) + p);  };

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
		auto epsilon1 = [&](uint32_t n) -> ExtendedDouble { return 5 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> ExtendedDouble { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return delta(n)*delta(n)*Bkey*((1+0.5)*Bkey + p*p)
				+ delta(n)*(ext_double::floor(ext_double::log(qPrev) / ExtendedDouble(log(2)*dcrtBits)) + 1)*w*Berr;  };

		//main correctness constraint
		auto qBFV = [&](uint32_t n, ExtendedDouble qPrev) -> ExtendedDouble { return p*(4 * (ext_double::power(C1(n), evalMultCount)*Vnorm(n)
				+ evalMultCount*ext_double::power(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

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

	cryptoParamsBFVrns->SetElementParams(params);

	// if no batch size was specified, we set batchSize = n by default (for full packing)
	const EncodingParams encodingParams = cryptoParamsBFVrns->GetEncodingParams();
	if (encodingParams->GetBatchSize() == 0)
	{
		uint32_t batchSize = n;
		EncodingParams encodingParamsNew(new EncodingParamsImpl(encodingParams->GetPlaintextModulus(),batchSize));
		cryptoParamsBFVrns->SetEncodingParams(encodingParamsNew);
	}

	return cryptoParamsBFVrns->PrecomputeCRTTables();
#endif // infdef NO_EXTENDEDDOUBLE
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(const LPPublicKey<DCRTPoly> publicKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(publicKey) );

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(publicKey->GetCryptoParameters());

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
DecryptResult LPAlgorithmBFVrns<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
		ConstCiphertext<DCRTPoly> ciphertext,
		NativePoly *plaintext) const
{
	//TimeVar t_total;

	//TIC(t_total);

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

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

	auto &p = cryptoParams->GetPlaintextModulus();

	const std::vector<double> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
	const std::vector<long double> &lyamExtTable = cryptoParams->GetCRTDecryptionExtFloatTable();
#ifndef NO_QUADMATH
	const std::vector<QuadFloat> &lyamQuadTable = cryptoParams->GetCRTDecryptionQuadFloatTable();
#endif
	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();
	const std::vector<NativeInteger> &invPreconTable = cryptoParams->GetCRTDecryptionIntPreconTable();

	// this is the resulting vector of coefficients;
#ifndef NO_QUADMATH
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
#else
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable,lyamExtTable);
#endif
	//std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" << std::endl;

	return DecryptResult(plaintext->GetLength());

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(const LPPrivateKey<DCRTPoly> privateKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(privateKey) );

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(privateKey->GetCryptoParameters());

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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext,
		ConstPlaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	const DCRTPoly& ptElement = plaintext->GetElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] + ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalSub(ConstCiphertext<DCRTPoly> ciphertext,
	ConstPlaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] - ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
		PALISADE_THROW(config_error, errMsg);
	}

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());

	//Get the ciphertext elements
	std::vector<DCRTPoly> cipherText1Elements = ciphertext1->GetElements();
	std::vector<DCRTPoly> cipherText2Elements = ciphertext2->GetElements();

	size_t cipherText1ElementsSize = cipherText1Elements.size();
	size_t cipherText2ElementsSize = cipherText2Elements.size();
	size_t cipherTextRElementsSize = cipherText1ElementsSize + cipherText2ElementsSize - 1;

	std::vector<DCRTPoly> c(cipherTextRElementsSize);

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrns->GetElementParams();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	// Expands the CRT basis to Q*S; Outputs the polynomials in EVALUATION representation


	for(size_t i=0; i<cipherText1ElementsSize; i++)
		cipherText1Elements[i].ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
				cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable(),
				cryptoParamsBFVrns->GetDCRTParamsSModulimu(),cryptoParamsBFVrns->GetCRTInversePreconTable());

	for(size_t i=0; i<cipherText2ElementsSize; i++)
		cipherText2Elements[i].ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
				cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable(),
				cryptoParamsBFVrns->GetDCRTParamsSModulimu(),cryptoParamsBFVrns->GetCRTInversePreconTable());

	// Performs the multiplication itself
	// Karatsuba technique is currently slower so it is commented out
	/*if (cipherText1ElementsSize == 2 && cipherText2ElementsSize == 2) // size of each ciphertxt = 2, use Karatsuba
	{

		c[0] = cipherText1Elements[0] * cipherText2Elements[0]; // a
		c[2] = cipherText1Elements[1] * cipherText2Elements[1]; // b

		c[1] = cipherText1Elements[0] + cipherText1Elements[1];
		c[1] *= (cipherText2Elements[0] + cipherText2Elements[1]);
		c[1] -= c[2];
		c[1] -= c[0];

	}
	else // if size of any of the ciphertexts > 2
	{*/

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
	//};

	for(size_t i=0; i<cipherTextRElementsSize; i++){
		//converts to coefficient representation before rounding
		c[i].SwitchFormat();
		// Performs the scaling by p/q followed by rounding; the result is in the CRT basis S
		c[i] = c[i].ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable(),
				cryptoParamsBFVrns->GetDCRTParamsSModulimu());
		// Converts from the CRT basis S to Q
		c[i] = c[i].SwitchCRTBasis(elementParams, cryptoParamsBFVrns->GetCRTSInverseTable(),
					cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable(),
					cryptoParamsBFVrns->GetDCRTParamsQModulimu(),cryptoParamsBFVrns->GetCRTSInversePreconTable());
	}

	newCiphertext->SetElements(c);
	newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

	return newCiphertext;

}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	LPEvalKey<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
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
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyBFVrns<DCRTPoly>::MultiKeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey, const LPPrivateKey<DCRTPoly> newPrivateKey,
	const LPEvalKey<DCRTPoly> ek) const {

	LPEvalKeyRelin<DCRTPoly> keySwitchHintRelin(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();

	//Getting a reference to the polynomials of new private key.
	const DCRTPoly &sNew = newPrivateKey->GetPrivateElement();

	//Getting a reference to the polynomials of original private key.
	const DCRTPoly &s = originalPrivateKey->GetPrivateElement();

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	std::vector<DCRTPoly> evalKeyElements;
	std::vector<DCRTPoly> evalKeyElementsGenerated;

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	const std::vector<DCRTPoly> &a = ek->GetBVector();

	for (usint i = 0; i < s.GetNumOfElements(); i++)
	{

		if (relinWindow>0)
		{
			vector<typename DCRTPoly::PolyType> decomposedKeyElements = s.GetElementAtIndex(i).PowersOfBase(relinWindow);

			for (size_t k = 0; k < decomposedKeyElements.size(); k++)
			{

				// Creates an element with all zeroes
				DCRTPoly filtered(elementParams,EVALUATION,true);

				filtered.SetElementAtIndex(i,decomposedKeyElements[k]);

				// Generate a_i vectors
				evalKeyElementsGenerated.push_back(a[i*decomposedKeyElements.size()+k]);

				// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
				DCRTPoly e(dgg, elementParams, Format::EVALUATION);
				evalKeyElements.push_back(filtered - (a[i*decomposedKeyElements.size()+k]*sNew + e));
			}
		}
		else
		{
			// Creates an element with all zeroes
			DCRTPoly filtered(elementParams,EVALUATION,true);

			filtered.SetElementAtIndex(i,s.GetElementAtIndex(i));

			// Generate a_i vectors
			evalKeyElementsGenerated.push_back(a[i]);

			// Generate  [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi) - (a_i * s + e)
			DCRTPoly e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements.push_back(filtered - (a[i]*sNew + e));
		}

	}

	keySwitchHintRelin->SetAVector(std::move(evalKeyElements));
	keySwitchHintRelin->SetBVector(std::move(evalKeyElementsGenerated));

	return keySwitchHintRelin;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitch(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ek->GetCryptoParameters());

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

	if (c.size() == 2) //case of automorphism or PRE
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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMultAndRelinearize(ConstCiphertext<DCRTPoly> ciphertext1,
	ConstCiphertext<DCRTPoly> ciphertext2, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ek[0]->GetCryptoParameters());

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
LPEvalKey<DCRTPoly> LPAlgorithmPREBFVrns<DCRTPoly>::ReKeyGen(const LPPublicKey<DCRTPoly> newPK,
		const LPPrivateKey<DCRTPoly> origPrivateKey) const {

	// Get crypto context of new public key.
	auto cc = newPK->GetCryptoContext();

	// Create an evaluation key that will contain all the re-encryption key elements.
	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(cc));

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(newPK->GetCryptoParameters());
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
Ciphertext<DCRTPoly> LPAlgorithmPREBFVrns<DCRTPoly>::ReEncrypt(const LPEvalKey<DCRTPoly> ek,
	ConstCiphertext<DCRTPoly> ciphertext,
	const LPPublicKey<DCRTPoly> publicKey) const
{

	if (publicKey == nullptr) { // Sender PK is not provided - CPA-secure PRE
		return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
	} else { // Sender PK provided - HRA-secure PRE

		const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
						std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ek->GetCryptoParameters());

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
DecryptResult LPAlgorithmMultipartyBFVrns<DCRTPoly>::MultipartyDecryptFusion(const vector<Ciphertext<DCRTPoly>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertextVec[0]->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	const auto &p = cryptoParams->GetPlaintextModulus();

	const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
	DCRTPoly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	const std::vector<double> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
	const std::vector<long double> &lyamExtTable = cryptoParams->GetCRTDecryptionExtFloatTable();
#ifndef NO_QUADMATH
	const std::vector<QuadFloat> &lyamQuadTable = cryptoParams->GetCRTDecryptionQuadFloatTable();
#endif
	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();
	const std::vector<NativeInteger> &invPreconTable = cryptoParams->GetCRTDecryptionIntPreconTable();

	// this is the resulting vector of coefficients;
#ifndef NO_QUADMATH
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
#else
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable,lyamExtTable);
#endif
	return DecryptResult(plaintext->GetLength());

}

template class LPCryptoParametersBFVrns<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<DCRTPoly>;
template class LPAlgorithmBFVrns<DCRTPoly>;
template class LPAlgorithmPREBFVrns<DCRTPoly>;
template class LPAlgorithmSHEBFVrns<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrns<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrns<DCRTPoly>;

}
