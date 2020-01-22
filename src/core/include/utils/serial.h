/**
 * @file serial.h Serialization utilities.
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
#ifndef LBCRYPTO_SERIAL_H
#define LBCRYPTO_SERIAL_H

#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <iostream>

#ifndef CEREAL_RAPIDJSON_HAS_STDSTRING
#define CEREAL_RAPIDJSON_HAS_STDSTRING 1
#endif
#ifndef CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS
#define CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#endif
#define CEREAL_RAPIDJSON_HAS_CXX11_NOEXCEPT 0


#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include "cereal/cereal.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/map.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"

#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include "utils/sertype.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextImpl;

namespace Serial
{
	/**
	 * SerializeToString - serialize the object to a JSON string and return the string
	 * @param t - any serializable object
	 * @return JSON string
	 */
	template <typename T>
	inline static std::string SerializeToString(const std::shared_ptr<T> t) {
		std::stringstream s;
		{
			extern void Serialize(decltype(t), std::ostream&, SerType::SERJSON);
			Serialize(t, s, SerType::JSON);
		}
		return s.str();
	}

	/**
	 * SerializeToString - serialize the object to a JSON string and return the string
	 * @param t - any serializable object
	 * @return JSON string
	 */
	template <typename T>
	inline static std::string SerializeToString(const T& t) {
		std::stringstream s;
		{
			extern void Serialize(decltype(t), std::ostream&, SerType::SERJSON);
			Serialize(t, s, SerType::JSON);
		}
		return s.str();
	}

	/**
	 * Deserialize a CryptoContext as a special case
	 * @param obj - CryptoContext to deserialize into
	 * @param stream - Stream to deserialize from
	 * @param sertype - binary serialization
	 */
	template<typename T>
	static void
	Deserialize(std::shared_ptr<CryptoContextImpl<T>>& obj, std::istream& stream, const SerType::SERBINARY& st);

	/**
	 * Deserialize a CryptoContext as a special case
	 * @param obj - CryptoContext to deserialize into
	 * @param stream - Stream to deserialize from
	 * @param sertype - JSON serialization
	 */
	template<typename T>
	static void
	Deserialize(std::shared_ptr<CryptoContextImpl<T>>& obj, std::istream& stream, const SerType::SERJSON& ser);

	/**
	 * Serialize an object; uses the default serialization of BINARY
	 * @param obj - object to serialize
	 * @param stream - Stream to serialize to
	 */
	template<typename T>
	inline static void
	Serialize(const T& t, std::ostream& stream) {
		extern void Serialize(decltype(t), std::ostream&, const SerType::SERBINARY&);
		Serialize(t, stream, SerType::BINARY);
	}

	/**
	 * Deserialize an object; uses the default serialization of BINARY
	 * @param obj - object to deserialize into
	 * @param stream - Stream to deserialize from
	 */
	template<typename T>
	inline static void
	Deserialize(T& t, std::istream& stream) {
		extern void Serialize(decltype(t), std::ostream&, const SerType::SERBINARY&);
		Serialize(t, stream, SerType::BINARY);
	}
}

}

#endif
