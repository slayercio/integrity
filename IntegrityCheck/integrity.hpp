#pragma once

#include <sal.h>
#include <vector>
#include <string>

namespace sln {
	class Integrity {
	public:
		struct IntegrityRequest;
		struct IntegrityResult;
	public:
		enum CheckType {
			FUNCTION,
			HOOK
		};

		struct IntegrityRequest {
		public:
			IntegrityRequest(
				_In_ CheckType type,
				_In_ _Notnull_ void* address,
				_In_ size_t size = 4,
				_In_opt_ _Maybenull_ unsigned char* bytes = nullptr
			);

			IntegrityResult PerformCheck();

		private:
			CheckType _type;
			void* _address;
			size_t _size;
			unsigned char* _bytes;
		};

		struct IntegrityResult {
		public:
			IntegrityResult(
				_In_ CheckType type,
				_In_ _Notnull_ void* address, 
				_In_ size_t length, 
				_In_ size_t correctBytes, 
				_In_ bool valid, 
				_In_ unsigned char invalidByte = 0, 
				_In_ unsigned char expectedByte = 0);

			void* Address() const;
			size_t Length() const;
			size_t CorrectLength() const;

			[[nodiscard("You should check if integrity is valid!")]] bool Valid() const;
			unsigned char Expected() const;
			unsigned char Found() const;
			CheckType Type() const;

			std::string String() const;

		private:
			void* _baseAddress;
			size_t _totalLength;
			size_t _correctLength;
		
			bool _valid;
			unsigned char _expectedValue;
			unsigned char _foundValue;

			CheckType _type;
		};

		static IntegrityResult CheckHookIntegrity(
			_In_ _Notnull_ void* hookAddress
		);

		static IntegrityResult CheckFunctionIntegrity(
			_In_ _Notnull_ void* functionAddress, 
			_In_reads_bytes_(size) unsigned char* bytes, 
			_In_ size_t size
		);


	};
}