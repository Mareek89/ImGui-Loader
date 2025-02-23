#pragma once

#include <random>
#include <fstream>
#include "driver comm/ntdll.h"

#include "xorstr.h"

namespace util
{
	inline std::string GetParent(const std::string& path)
	{
		if (path.empty())
			return path;

		auto idx = path.rfind('\\');
		if (idx == path.npos)
			idx = path.rfind('/');

		if (idx != path.npos)
			return path.substr(0, idx);
		else
			return path;
	}

	static std::string GetExeDirectory()
	{
		char imgName[MAX_PATH] = { 0 };
		DWORD len = ARRAYSIZE(imgName);

		GetModuleFileNameA(nullptr, imgName, len);

		return GetParent(imgName);
	}

	static bool readFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
	{
		std::ifstream file_ifstream(file_path, std::ios::binary);

		if (!file_ifstream)
			return false;

		out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
		file_ifstream.close();

		return true;
	}

	static std::string generate_random_string(const size_t length) {
		static std::string alpha_numeric_chars =
			xorstr_("0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz");

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<size_t> dis(0U, alpha_numeric_chars.size() - 1U);

		std::string random_string("", length);
		for (size_t i = 0; i < length; ++i) {
			random_string.at(i) = alpha_numeric_chars.at(dis(gen));
		}

		return random_string;
	}

	static _PEB* peb()
	{
		return reinterpret_cast<_PEB*>(__readgsqword(0x60));
	}

	static std::string wide_to_multibyte(const std::wstring& str) {
		std::string ret;
		size_t str_len;

		// check if not empty str
		if (str.empty())
			return{};

		// count size
		str_len = WideCharToMultiByte(CP_UTF8, 0, &str[0], str.size(), 0, 0, 0, 0);

		// setup return value
		ret.resize(str_len);

		// final conversion
		WideCharToMultiByte(CP_UTF8, 0, &str[0], str.size(), &ret[0], str_len, 0, 0);

		return ret;
	}

	static std::wstring multibyte_to_wide(const std::string& str) {
		size_t      size;
		std::wstring out;

		// get size
		size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.size() + 1, 0, 0);

		out.resize(size);

		// finally convert
		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.size() + 1, &out[0], size);

		return out;
	}
}

