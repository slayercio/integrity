#pragma once

#include <vector>
#include <mutex>
#include <thread>
#include <functional>
#include "integrity.hpp"

namespace sln {
	class IntegrityThread : public std::enable_shared_from_this<IntegrityThread> {
	public:
		IntegrityThread(std::function<void(Integrity::IntegrityResult)> handler);
		void Start();
		void Stop();
		void AddCheck(Integrity::IntegrityRequest);
		bool IsRunning();

		std::thread::native_handle_type Handle();


	public:
		std::mutex _requestsLock;
		std::vector<Integrity::IntegrityRequest> _requests;
		std::thread _thread;
		std::function<void(Integrity::IntegrityResult)> _handler;

		std::atomic_bool _running = true;
	};
}