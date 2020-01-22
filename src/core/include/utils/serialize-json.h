/**
 * @file serialize-json.h - include to enable json serialization
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
#ifndef LBCRYPTO_SERIALIZE_JSON_H
#define LBCRYPTO_SERIALIZE_JSON_H

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
#include "cereal/archives/json.hpp"
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

#include "utils/serial.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextImpl;

namespace Serial {

/**
 * Serialize an object
 * @param obj - object to serialize
 * @param stream - Stream to serialize to
 * @param sertype - type of serialization; default is BINARY
 */
template<typename T>
inline static void
Serialize(const T& obj, std::ostream& stream, const SerType::SERJSON& ser) {
	cereal::JSONOutputArchive archive( stream );
	archive( obj );
}

/**
 * Deserialize an object
 * @param obj - object to deserialize into
 * @param stream - Stream to deserialize from
 * @param sertype - type of serialization; default is BINARY
 */
template<typename T>
inline static void
Deserialize(T& obj, std::istream& stream, const SerType::SERJSON& ser) {
	cereal::JSONInputArchive archive( stream );
	archive( obj );
}

template <typename T>
inline static bool SerializeToFile(std::string filename, const T& obj, const SerType::SERJSON& sertype) {
	std::ofstream file(filename, std::ios::out|std::ios::binary);
	if( file.is_open() ) {
		Serial::Serialize(obj, file, sertype);
		file.close();
		return true;
	}
	return false;
}

template <typename T>
inline static bool DeserializeFromFile(std::string filename, T& obj, const SerType::SERJSON& sertype) {
	std::ifstream file(filename, std::ios::in|std::ios::binary);
	if( file.is_open() ) {
		Serial::Deserialize(obj, file, sertype);
		file.close();
		return true;
	}
	return false;
}

}

}
#endif
