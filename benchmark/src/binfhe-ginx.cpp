/*
 * @file binfhe : library benchmark routines for FHEW
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

/*
 * This file benchmarks FHEW gate evaluation operations
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

#include "binfhecontext.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;


/*
 * Context setup utility methods
 */

BinFHEContext
GenerateFHEWContext(BINFHEPARAMSET set) {

   	auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(set,GINX);

	return cc;
}

/*
 * FHEW benchmarks
 * The code can be later compressed taking the security level as an argument
 */

void FHEW_NOT_MEDIUM(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(MEDIUM);

	LWEPrivateKey sk = cc.KeyGen();

	LWECiphertext ct1 = cc.Encrypt(sk,1);

	while (state.KeepRunning()) {
		LWECiphertext ct11 = cc.EvalNOT(ct1);
	}
}

BENCHMARK(FHEW_NOT_MEDIUM)->Unit(benchmark::kMicrosecond);

// benchmark for binary gates, such as AND, OR, NAND, NOR
void FHEW_BINGATE_MEDIUM(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(MEDIUM);

	LWEPrivateKey sk = cc.KeyGen();

	cc.BTKeyGen(sk);

	LWECiphertext ct1 = cc.Encrypt(sk,1);
	LWECiphertext ct2 = cc.Encrypt(sk,1);

	while (state.KeepRunning()) {
		LWECiphertext ct11 = cc.EvalBinGate(AND,ct1,ct2);
	}
}

BENCHMARK(FHEW_BINGATE_MEDIUM)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

// benchmark for key switching
void FHEW_KEYSWITCH_MEDIUM(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(MEDIUM);

	LWEPrivateKey sk = cc.KeyGen();
	LWEPrivateKey skN = cc.KeyGenN();

	auto ctQN1 = cc.Encrypt(skN,1);
	auto keySwitchHint = cc.KeySwitchGen(sk,skN);

	while (state.KeepRunning()) {
		std::shared_ptr<LWECiphertextImpl> eQ1 = cc.GetLWEScheme()->KeySwitch(cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
	}
}

BENCHMARK(FHEW_KEYSWITCH_MEDIUM)->Unit(benchmark::kMicrosecond)->MinTime(1.0);

void FHEW_NOT_STD128(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(STD128);

	LWEPrivateKey sk = cc.KeyGen();

	LWECiphertext ct1 = cc.Encrypt(sk,1);

	while (state.KeepRunning()) {
		LWECiphertext ct11 = cc.EvalNOT(ct1);
	}
}

BENCHMARK(FHEW_NOT_STD128)->Unit(benchmark::kMicrosecond);

// benchmark for binary gates, such as AND, OR, NAND, NOR
void FHEW_BINGATE_STD128(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(STD128);

	LWEPrivateKey sk = cc.KeyGen();

	cc.BTKeyGen(sk);

	LWECiphertext ct1 = cc.Encrypt(sk,1);
	LWECiphertext ct2 = cc.Encrypt(sk,1);

	while (state.KeepRunning()) {
		LWECiphertext ct11 = cc.EvalBinGate(AND,ct1,ct2);
	}

}

BENCHMARK(FHEW_BINGATE_STD128)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

// benchmark for key switching
void FHEW_KEYSWITCH_STD128(benchmark::State& state) {

	BinFHEContext cc = GenerateFHEWContext(STD128);

	LWEPrivateKey sk = cc.KeyGen();
	LWEPrivateKey skN = cc.KeyGenN();

	auto ctQN1 = cc.Encrypt(skN,1);
	auto keySwitchHint = cc.KeySwitchGen(sk,skN);

	while (state.KeepRunning()) {
		std::shared_ptr<LWECiphertextImpl> eQ1 = cc.GetLWEScheme()->KeySwitch(cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
	}
}

BENCHMARK(FHEW_KEYSWITCH_STD128)->Unit(benchmark::kMicrosecond)->MinTime(1.0);

BENCHMARK_MAIN();
