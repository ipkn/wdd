#include "stdafx.h"
#include "Trace.h"

void BaseTrace::Prepare(const std::wstring & path)
{
	std::wstring key(path);
	auto dirPath = path.substr(0, path.find_last_of(L"\\/"));
	if (dirPath.size() == path.size())
		dirPath = L".";
	if (key.rfind(L'\\') != key.npos)
	{
		key = key.substr(key.rfind(L'\\') + 1);
	}
	if (key.rfind(L'/') != key.npos)
	{
		key = key.substr(key.rfind(L'/') + 1);
	}
	if (key.substr(key.size() - 4, 4) == L".exe")
		key = key.substr(0, key.size() - 4);

	//_wchdir(dirPath.c_str());

	basePath_ = dirPath + L"\\.wdd\\" + key;

	_wmkdir((dirPath+L"\\.wdd").c_str());
	_wmkdir((dirPath+L"\\.wdd\\_symbols").c_str());
	_wmkdir(basePath_.c_str());

	// NOTE it would be better to clear the directory
}

void RecordTrace::Prepare(const std::wstring & exe_path)
{
	BaseTrace::Prepare(exe_path);

	trace_file_.open(basePath_ + L"\\trace", std::ios::binary | std::ios::out);
	trace_file_.write((char*)&TraceVersion, 4);
	uint32_t sz = sizeof(ThreadContext);
	trace_file_.write((char*)&sz, 4);
}

void ReplayTrace::Prepare(const std::wstring & exe_path)
{
	BaseTrace::Prepare(exe_path);
	trace_file_.open(basePath_ + L"\\trace", std::ios::binary | std::ios::in);
	if (!trace_file_)
	{
		std::cerr << "Fatal: Cannot find recorded trace file" << std::endl;
		throw std::runtime_error("Cannot find recorded trace file");
	}
	int version_stored;
	trace_file_.read((char*)&version_stored, 4);
	if (version_stored != TraceVersion)
	{
		std::cerr << "Fatal: Version mismatch (expected " << std::hex << TraceVersion << " actual " << version_stored << ")\n";
		throw std::runtime_error("Fatal: wdd trace version mismatch");
	}
	uint32_t sz;
	trace_file_.read((char*)&sz, 4);
	if (sz != sizeof(ThreadContext))
	{
		std::cerr << "Fatal: CONTEXT size mismatch (expected " << sizeof(ThreadContext) << " actual " << sz << ")\n";
		throw std::runtime_error("Fatal: CONTEXT size mismatch");
	}

	pos_last = (size_t)trace_file_.tellg();

	ReadNextFragment();
	//auto frag = GetFirstFragment();
	//frag.trace->as<ConfigTrace>()->
}

ReplayTrace::Fragment ReplayTrace::GetFirstFragment()
{
	auto it = buffers_.begin();
	return BufferToFragment(it->first, it->second);
}

bool ReplayTrace::ReadNextFragment()
{
	trace_file_.seekg(pos_last);
	size_t pos = (size_t)trace_file_.tellg();
	char has_ctx;
	trace_file_.read(&has_ctx, 1);
	if (!trace_file_)
		return false;
	//(pos+1)~
	if (has_ctx)
	{
		trace_file_.seekg(sizeof(ThreadContext), std::ios::cur);
	}
	uint32_t sz;
	trace_file_.read((char*)&sz, 4);

	size_t pos_next = (size_t)(trace_file_.tellg()) + sz;
	char* buffer = new char[pos_next - pos];
	trace_file_.seekg(pos);
	trace_file_.read(buffer, pos_next - pos);
	buffers_.emplace(pos, buffer);
	pos_last = pos_next;
	return true;
}

ReplayTrace::Fragment ReplayTrace::BufferToFragment(size_t pos, char * buffer)
{
	bool has_ctx = *buffer > 0;
	char* data = buffer + 1 + 4;
	if (has_ctx)
		data += sizeof(ThreadContext);
	uint32_t sz = *(uint32_t*)(data - 4);

	return Fragment{
		has_ctx ? (ThreadContext*)(buffer + 1) : nullptr,
		sz,
		(Trace*)data,
		pos,
		this
	};
}

ReplayTrace::Fragment ReplayTrace::PrevFragment(size_t pos)
{
	auto it = buffers_.find(pos);
	if (it != buffers_.begin())
		--it;
	else
		return{};
	return BufferToFragment(it->first, it->second);
}

ReplayTrace::Fragment ReplayTrace::NextFragment(size_t pos)
{
	auto it = buffers_.find(pos);
	++it;
	if (it == buffers_.end())
	{
		bool success = ReadNextFragment();
		if (!success)
			return{};
		it = buffers_.end();
		--it;
	}
	return BufferToFragment(it->first, it->second);
}

ReplayTrace::Fragment ReplayTrace::Fragment::Next()
{
	return parent->NextFragment(pos);
}

ReplayTrace::Fragment ReplayTrace::Fragment::Prev()
{
	return parent->PrevFragment(pos);
}

