#include "integrity_thread.hpp"
#include <memory>

#if defined(_MSC_VER) && (defined(_WIN64) || defined(_WIN32))
#include <Windows.h>
#endif

namespace sln {
	IntegrityThread::IntegrityThread(std::function<void(Integrity::IntegrityResult)> handler)
		: _handler(handler)
	{}

	void IntegrityThread::Start() {
		auto func = [self = shared_from_this()]() {
			while (self->_running) {
				std::scoped_lock lock(self->_requestsLock);

				for (auto& request : self->_requests) {
					auto result = request.PerformCheck();

					if (!result.Valid()) self->_handler(result);
				}
			}
		};

		this->_thread = std::thread(func);
	}

	void IntegrityThread::Stop()
	{
		_running = false;
	}

	void IntegrityThread::AddCheck(Integrity::IntegrityRequest req)
	{
		std::scoped_lock lock(this->_requestsLock);

		this->_requests.push_back(req);
	}

	bool IntegrityThread::IsRunning()
	{
#if defined(_MSC_VER) && defined(_WIN64)
		auto handle = reinterpret_cast<HANDLE>(Handle());

		auto result = WaitForSingleObject(handle, 10);

		if (result == WAIT_OBJECT_0)
			return false;

		return true;
#else
		return _thread.joinable();
#endif
	}

	std::thread::native_handle_type IntegrityThread::Handle()
	{
		return _thread.native_handle();
	}
}
