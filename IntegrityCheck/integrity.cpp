#include "integrity.hpp"
#include <sstream>
#include <utility>

namespace sln {
	static Integrity::IntegrityResult CheckIntegrity(
		_In_ _Notnull_ uintptr_t address,
		_In_reads_bytes_(size) unsigned char* bytes,
		_In_ size_t size,
		_In_ Integrity::CheckType type
	) {
		size_t correctLength = 0;

		for (size_t i = 0; i < size; i++) {
			auto value = *reinterpret_cast<unsigned char*>(address + i);
			auto expected = bytes[i];

			if (value == expected) { correctLength++; continue; }

			return Integrity::IntegrityResult(
				type,
				reinterpret_cast<void*>(address + i),
				size,
				correctLength,
				false,
				value,
				expected
			);
		}

		return Integrity::IntegrityResult(type, reinterpret_cast<void*>(address), size, correctLength, true);
	}

	Integrity::IntegrityResult::IntegrityResult(
		_In_ CheckType type,
		_In_ _Notnull_ void* address,
		_In_ size_t length,
		_In_ size_t correctBytes,
		_In_ bool valid,
		_In_ unsigned char invalidByte,
		_In_ unsigned char expectedByte
	) : _type(type), _baseAddress(address), _totalLength(length), _correctLength(correctBytes), _valid(valid), _foundValue(invalidByte), _expectedValue(expectedByte) {}

	void* Integrity::IntegrityResult::Address() const
	{
		return _baseAddress;
	}

	size_t Integrity::IntegrityResult::Length() const
	{
		return _totalLength;
	}

	size_t Integrity::IntegrityResult::CorrectLength() const
	{
		return _correctLength;
	}

	bool Integrity::IntegrityResult::Valid() const
	{
		return _valid;
	}

	unsigned char Integrity::IntegrityResult::Expected() const
	{
		return _expectedValue;
	}

	unsigned char Integrity::IntegrityResult::Found() const
	{
		return _foundValue;
	}
	
	Integrity::CheckType Integrity::IntegrityResult::Type() const
	{
		return _type;
	}

	std::string Integrity::IntegrityResult::String() const
	{
		std::ostringstream stream;
		stream << std::boolalpha;

		stream << "IntegrityResult {\n";
		stream << "\taddress: 0x" << _baseAddress << ",\n";
		stream << "\toriginalLength: " << _totalLength << ",\n";
		stream << "\tactualLength: " << _correctLength << ",\n";
		stream << "\tvalid: " << _valid << ",\n";

		stream << std::hex;
		stream << "\texpectedValue: " << +(_expectedValue & 0xff) << ",\n";
		stream << "\tfoundValue: " << +(_foundValue & 0xff) << ",\n";
		stream << "\ttype: " << (_type == CheckType::FUNCTION ? "FUNCTION" : "HOOK") << "\n}";

		return stream.str();
	}
	
	Integrity::IntegrityResult Integrity::CheckHookIntegrity(_In_ _Notnull_ void* hook_address)
	{
		unsigned char bytes[4]{0xf1, 0xf1, 0xf1, 0xf1};

		auto result = CheckIntegrity(reinterpret_cast<uintptr_t>(hook_address), bytes, sizeof(bytes), Integrity::CheckType::HOOK);

		return result;
	}

	Integrity::IntegrityResult Integrity::CheckFunctionIntegrity(
		_In_ _Notnull_ void* function, 
		_In_reads_bytes_(size) unsigned char* bytes, 
		_In_ size_t size
	) {
		return CheckIntegrity(reinterpret_cast<uintptr_t>(function), bytes, size, CheckType::FUNCTION);
	}

	Integrity::IntegrityRequest::IntegrityRequest(
		_In_ CheckType type, 
		_In_ _Notnull_ void* address, 
		_In_ size_t size,
		_In_opt_ _Maybenull_ unsigned char* bytes
	) {
		this->_type = type;
		this->_address = address;
		this->_size = size;
		this->_bytes = bytes;
	}

	Integrity::IntegrityResult Integrity::IntegrityRequest::PerformCheck() {
		switch (_type) {
		case Integrity::FUNCTION:
			return Integrity::CheckFunctionIntegrity(_address, _bytes, _size);
		case Integrity::HOOK:
			return Integrity::CheckHookIntegrity(_address);
		default:
			std::unreachable();
		}
	}
}
