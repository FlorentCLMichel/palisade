/**
 * @file binfhecontext.cpp - Implementation file for Boolean Circuit FHE context class
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
#include "binfhecontext.h"

namespace lbcrypto{
   
	void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger &q,
			const NativeInteger &Q, double std, uint32_t baseKS, uint32_t baseG, uint32_t baseR){
		shared_ptr<LWECryptoParams> lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(n, N, q, Q, std, baseKS));
		m_params = std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR);
	}

	void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set){
		shared_ptr<LWECryptoParams> lweparams;
		switch(set)
		{
		case TOY:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(64, 512, 256, FirstPrime<NativeInteger>(32, 1024), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		case MEDIUM:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(256, 1024, 256, FirstPrime<NativeInteger>(32, 2048), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		case STD128:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(512, 2048, 512, FirstPrime<NativeInteger>(49, 4096), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<25, 23);
			break;
		case STD192:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(512, 2048, 512, FirstPrime<NativeInteger>(32, 4096), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		case STD256:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(1024, 4096, 1024, FirstPrime<NativeInteger>(32, 8192), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		case STD128Q:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(512, 2048, 512, FirstPrime<NativeInteger>(49, 4096), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<25, 23);
			break;
		case STD192Q:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(1024, 2048, 1024, FirstPrime<NativeInteger>(32, 4096), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		case STD256Q:
			lweparams = std::make_shared<LWECryptoParams>(LWECryptoParams(1024, 4096, 1024, FirstPrime<NativeInteger>(32, 8192), 3.19, 25));
			m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1<<11, 23);
			break;
		default:
			std::string errMsg = "ERROR: No such parameter set exists for FHEW."; \
			throw std::runtime_error(errMsg);
		}
	}

	LWEPrivateKey BinFHEContext::KeyGen() const{
		return m_LWEscheme->KeyGen(m_params->GetLWEParams());
	}

	LWEPrivateKey  BinFHEContext::KeyGenN() const {
		return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
	}

	LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk, const LWEPlaintext &m) const {
		return m_LWEscheme->Encrypt(m_params->GetLWEParams(),sk,m);
	}

	void BinFHEContext::Decrypt(ConstLWEPrivateKey sk,
				ConstLWECiphertext ct, LWEPlaintext* result) const {
		return m_LWEscheme->Decrypt(m_params->GetLWEParams(),sk,ct,result);
	}

	std::shared_ptr<LWESwitchingKey> BinFHEContext::KeySwitchGen(ConstLWEPrivateKey sk,
			ConstLWEPrivateKey skN) const {
		return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(),sk,skN);
	}

	void BinFHEContext::BTKeyGen(ConstLWEPrivateKey sk) {
		m_BTKey = m_RingGSWscheme->KeyGen(m_params,m_LWEscheme,sk);
		return;
	}

	LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate,
			ConstLWECiphertext ct1, ConstLWECiphertext ct2) const{
		return m_RingGSWscheme->EvalBinGate(m_params,gate, m_BTKey, ct1, ct2, m_LWEscheme);
	}

	LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext ct) const {
		return m_RingGSWscheme->EvalNOT(m_params,ct);
	}

}
