/*
 * @file 
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

#include "include/gtest/gtest.h"
#include "UnitTestSer.h"

#include "scheme/bgv/bgv-ser.h"
#include "pubkeylp-ser.h"
#include "ciphertext-ser.h"

using namespace std;
using namespace lbcrypto;

class UTPKESer : public ::testing::Test {
protected:
	void SetUp() {
	}

	void TearDown() {
		CryptoContextImpl<Poly>::ClearEvalMultKeys();
		CryptoContextImpl<Poly>::ClearEvalSumKeys();
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
		CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

CryptoContext<Poly> GenerateTestCryptoContext(const string& parmsetName) {
	PlaintextModulus modulusP(256);
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(parmsetName,
			EncodingParams(new EncodingParamsImpl(modulusP,8)));
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

CryptoContext<DCRTPoly> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	CryptoContext<DCRTPoly> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

template<typename T>
void UnitTestContext(CryptoContext<T> cc) {
	UnitTestContextWithSertype(cc, SerType::JSON, "json");
	UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
}

TEST_F(UTPKESer, BGV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("BGV2");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, BGV_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BGV2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

// USE BGV AS A REPRESENTITIVE CONTEXT
template<typename ST>
void Test_keys_and_ciphertext(const ST& sertype)
{
	DEBUG_FLAG(false);

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextImpl<Poly>::ClearEvalAutomorphismKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	// generate a context with encoding params
	usint m = 22;
	PlaintextModulus p = 2333;
	BigInteger modulusP(p);
	BigInteger modulusQ("1267650600228229401496703214121");
	BigInteger squareRootOfRoot("498618454049802547396506932253");
	BigInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev, OPTIMIZED);

	cc->Enable(ENCRYPTION|SHE);

	DEBUG("step 0");
	{
		stringstream s;
		Serial::Serialize(cc, s, sertype);
		ASSERT_TRUE( CryptoContextFactory<Poly>::GetContextCount() == 1 );
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		ASSERT_TRUE( CryptoContextFactory<Poly>::GetContextCount() == 0 );
		cc.reset();
		Serial::Deserialize(cc, s, sertype);

		ASSERT_TRUE( cc.get() != nullptr ) << "Deser failed";
		ASSERT_TRUE( CryptoContextFactory<Poly>::GetContextCount() == 1 );
	}

	CryptoContext<Poly> cc2 = GenerateTestCryptoContext("BGV4");

	LPKeyPair<Poly> kp = cc->KeyGen();
	LPKeyPair<Poly> kpnew;

	DEBUG("step 1");
	{
		stringstream s;
		Serial::Serialize(kp.publicKey, s, sertype);
		Serial::Deserialize(kpnew.publicKey, s, sertype);
		EXPECT_EQ( *kp.publicKey, *kpnew.publicKey ) << "Public key mismatch after ser/deser";
	}
	DEBUG("step 2");
	{
		stringstream s;
		Serial::Serialize(kp.secretKey, s, sertype);
		Serial::Deserialize(kpnew.secretKey, s, sertype);
		EXPECT_EQ( *kp.secretKey, *kpnew.secretKey ) << "Secret key mismatch after ser/deser";
	}
	DEBUG("step 3");
	vector<int64_t> vals = { 1,3,5,7,9,2,4,6,8,11 };
	Plaintext plaintextShort = cc->MakeCoefPackedPlaintext( vals );
	Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

	DEBUG("step 4");
	Ciphertext<Poly> newC;
	{
		stringstream s;
		Serial::Serialize(ciphertext, s, sertype);
		Serial::Deserialize(newC, s, sertype);
		EXPECT_EQ( *ciphertext, *newC ) << "Ciphertext mismatch";
	}

	DEBUG("step 5");
	Plaintext plaintextShortNew;
	cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);
	EXPECT_EQ(*plaintextShortNew, *plaintextShort) << "Decrypt of deserialized failed";

	DEBUG("step 6");
	LPKeyPair<Poly> kp2 = cc->KeyGen();
	LPKeyPair<Poly> kp3 = cc2->KeyGen();

	cc->EvalMultKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp2.secretKey);
	cc2->EvalMultKeyGen(kp3.secretKey);
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalSumKeyGen(kp2.secretKey);

	DEBUG("step 7");
	// serialize a bunch of mult keys
	stringstream ser0;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalMultKey(ser0, sertype, kp.secretKey->GetKeyTag()), true ) << "single eval mult key ser fails";
	stringstream ser2a;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalMultKey(ser2a, sertype, cc), true ) << "context 1 eval mult key ser fails";
	stringstream ser2b;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalMultKey(ser2b, sertype, cc2), true ) << "context 2 eval mult key ser fails";
	stringstream ser3;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalMultKey(ser3, sertype), true ) << "all context eval mult key ser fails";

	DEBUG("step 8");
	// serialize a bunch of sum keys
	stringstream aser0;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalSumKey(aser0, sertype, kp.secretKey->GetKeyTag()), true ) << "single eval sum key ser fails";
	stringstream aser2a;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalSumKey(aser2a, sertype, cc), true ) << "single ctx eval sum key ser fails";
	stringstream aser2b;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalSumKey(aser2b, sertype, cc2), false ) << "single ctx eval sum key ser fails";
	stringstream aser3;
	EXPECT_EQ( CryptoContextImpl<Poly>::SerializeEvalSumKey(aser3, sertype), true ) << "all eval sum key ser fails";

	DEBUG("step 9");
	cc.reset();
	cc2.reset();

	// test mult deserialize
	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 0) << "after release" << endl;

	vector<LPEvalKey<Poly>> evalMultKeys;
	CryptoContextImpl<Poly>::DeserializeEvalMultKey(ser0, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-key deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalMultKeys().size(), 1U) << "one-key deser, keys";

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalMultKey(ser2a, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalMultKeys().size(), 2U) << "one-ctx deser, keys";

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalMultKey(ser2b, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser2, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalMultKeys().size(), 1U) << "one-ctx deser2, keys";

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalMultKey(ser3, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 2) << "all-key deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalMultKeys().size(), 3U) << "all-key deser, keys";

	DEBUG("step 10");
	// test sum deserialize

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalSumKey(aser0, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-key deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalSumKeys().size(), 1U) << "one-key deser, keys";

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalSumKey(aser2a, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalSumKeys().size(), 2U) << "one-ctx deser, keys";

	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();

	CryptoContextImpl<Poly>::DeserializeEvalSumKey(aser3, sertype);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "all-key deser, context";
	EXPECT_EQ(CryptoContextImpl<Poly>::GetAllEvalSumKeys().size(), 2U) << "all-key deser, keys";

	// FIXME add tests to delete one context worth of keys, or a single key

	// ending cleanup
	CryptoContextImpl<Poly>::ClearEvalMultKeys();
	CryptoContextImpl<Poly>::ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
}

TEST_F(UTPKESer, Keys_and_ciphertext_json) {
	Test_keys_and_ciphertext(SerType::JSON);
}

TEST_F(UTPKESer, Keys_and_ciphertext_binary) {
	Test_keys_and_ciphertext(SerType::BINARY);
}
