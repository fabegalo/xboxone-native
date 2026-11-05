// SPDX-License-Identifier: BSD-3-Clause
#pragma once
#include "xboxone_native/bootstrap.h"

namespace xboxone::systemos {
void prepare_appmodel(const Profile&, Report&);
bool run_appmodel(const Profile&, Report&, std::uint32_t timeout_ms);
#ifdef _WIN32
// Shared by the backend and a no-deployment negative API regression.
bool request_packaged_activation(const std::string& aumid, const std::wstring& arguments, Report&);
#endif
} // namespace xboxone::systemos
