// SPDX-License-Identifier: BSD-3-Clause
// Real COM failure only; never registers a package or launches an installed app.
#include "appmodel_internal.h"
#include "appmodel_windows.h"
#include <iostream>
int main() {
    try {
        using namespace xboxone::appmodel::windows;
        Apartment apartment;
        GUID guid{};
        require(CoCreateGuid(&guid), "CoCreateGuid");
        wchar_t value[40]{};
        if (!StringFromGUID2(guid, value, 40)) return 1;
        std::string nonce;
        for (const auto c : utf8(value)) if (c != '{' && c != '}' && c != '-') nonce += c;
        const auto aumid = "XON.Missing." + nonce.substr(0, 24) + "_aaaaaaaaaaaaa!OwnedLifecycle";
        xboxone::systemos::Report report;
        const bool activated = xboxone::systemos::request_packaged_activation(aumid, L"", report);
        for (const auto& event : report.activation_events)
            std::cout << event.api << "; HRESULT=0x" << std::hex << event.result << '\n';
        if (activated || report.process_id || report.activation_events.empty()) return 1;
        // Require an actual failing API result; failure location stays visible.
        if (!(report.activation_events.back().result & 0x80000000U)) return 1;
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
