// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace xboxone::systemos {

enum class Origin { synthetic, original }; // Declaration, not publisher authentication.
enum class Role { executable, module, resource, container };
enum class Stage { empty, blocked, prepared, process_created, running, exited, timed_out, failed };
enum class ServiceKind { nt_kernel, xbox_device, xbox_broker, winrt_activation, compositor, storage };

struct Artifact {
    std::string id;
    std::string version; // Exact profile revision, no compatible-version fallback.
    std::filesystem::path path; // Absolute; input stays in place.
    std::string sha256;
    Role role = Role::resource;
    std::string provenance; // Required per file; caller-supplied access/source evidence.
};

struct ImportBinding {
    std::string requester;
    std::string library;
    // "host:kernel32" or "artifact:<exact manifest id>". Never auto-selected by name.
    std::string provider;
    std::string evidence; // Audited compatibility decision, not inferred from a DLL name.
};

struct ServiceRequirement {
    std::string id;
    ServiceKind kind = ServiceKind::xbox_broker;
    std::string evidence; // Actual observed dependency; no guessed services.
};

struct Profile {
    std::string id;
    std::string version;
    Origin origin = Origin::synthetic;
    std::string source_sha256; // Archive/source identity; not a second copy of it.
    std::string entry;
    std::vector<Artifact> artifacts;
    std::vector<ImportBinding> imports;
    std::vector<ServiceRequirement> services;
};

struct Diagnostic {
    std::string code;
    std::string subject;
    std::string detail;
};

struct Dependency {
    std::string requester;
    std::string library;
    std::string provider;
    std::string status;
};

struct Report {
    Stage stage = Stage::empty;
    std::string profile_id;
    std::string version;
    Origin origin = Origin::synthetic;
    std::string source_sha256;
    std::string entry_sha256;
    std::vector<Diagnostic> diagnostics;
    std::vector<Dependency> dependencies;
    std::uint32_t process_id = 0;
    bool primary_thread_resumed = false;
    std::uint32_t exit_code = 0;
    bool exit_code_available = false;
    // Exit is not proof of app initialization, authentic rendering or dashboard boot.
};

// A versioned, bounded UTF-8 text manifest. See docs/M1-STATUS.md for grammar.
bool read_profile(const std::filesystem::path& path, Profile& profile, std::string& error);
const char* stage_name(Stage stage) noexcept;

class Session {
public:
    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    // Hashes every artifact and audits imports/services without executing input.
    bool prepare(const Profile& profile);
    // One bounded run of an audited ordinary Win32 executable. The OS loader
    // owns mapping, relocation, imports, TLS/unwind and primary-thread startup.
    // Rechecks identity before launch. No shell, DLL injection, or alternate OS backend.
    bool run(std::uint32_t timeout_ms = 5000);
    [[nodiscard]] const Report& report() const noexcept { return report_; }

private:
    Profile profile_;
    Report report_;
};

} // namespace xboxone::systemos
