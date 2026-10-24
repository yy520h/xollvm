#include "runtime_admin.h"

#include "material_package.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>

namespace xovm::cloud_material {
namespace {
using Json = nlohmann::json;
using Bytes = std::vector<std::byte>;

BackendError invalidAdmin() { return BackendError{"invalid_admin_request"}; }

bool validHash(std::string_view value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

int base64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::variant<Bytes, BackendError> decodeBase64(std::string_view encoded, std::size_t maximum) {
    if (encoded.empty() || encoded.size() % 4 != 0 || encoded.size() > maximum * 4 / 3 + 4)
        return invalidAdmin();
    std::size_t padding = encoded.ends_with("==") ? 2 : encoded.ends_with('=') ? 1 : 0;
    if (padding > 2 || (padding == 0 ? encoded.find('=') != std::string_view::npos
                                     : encoded.find('=') != encoded.size() - padding))
        return invalidAdmin();
    Bytes result;
    result.reserve(encoded.size() / 4 * 3 - padding);
    for (std::size_t i = 0; i < encoded.size(); i += 4) {
        const int a = base64Value(encoded[i]);
        const int b = base64Value(encoded[i + 1]);
        const int c = encoded[i + 2] == '=' ? 0 : base64Value(encoded[i + 2]);
        const int d = encoded[i + 3] == '=' ? 0 : base64Value(encoded[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (encoded[i + 2] == '=' && encoded[i + 3] != '=') ||
            (encoded[i + 2] == '=' && (b & 15) != 0) ||
            (encoded[i + 3] == '=' && (c & 3) != 0)) return invalidAdmin();
        result.push_back(static_cast<std::byte>((a << 2) | (b >> 4)));
        if (encoded[i + 2] != '=') result.push_back(static_cast<std::byte>((b << 4) | (c >> 2)));
        if (encoded[i + 3] != '=') result.push_back(static_cast<std::byte>((c << 6) | d));
    }
    if (result.empty() || result.size() > maximum) return invalidAdmin();
    return result;
}

std::variant<Json, BackendError> decodeJsonObject(const Json &value, std::size_t maximum) {
    if (!value.is_string()) return invalidAdmin();
    auto decoded = decodeBase64(value.get_ref<const std::string &>(), maximum);
    if (const auto *error = std::get_if<BackendError>(&decoded)) return *error;
    const auto &bytes = std::get<Bytes>(decoded);
    const auto *begin = reinterpret_cast<const char *>(bytes.data());
    Json object;
    try {
        object = Json::parse(begin, begin + bytes.size());
    } catch (...) {
        return invalidAdmin();
    }
    if (!object.is_object()) return invalidAdmin();
    return object;
}

bool closed(const Json &value, std::initializer_list<const char *> fields) {
    if (!value.is_object() || value.size() != fields.size()) return false;
    return std::all_of(fields.begin(), fields.end(), [&](const char *field) {
        return value.contains(field);
    });
}

std::variant<std::string, BackendError> stringField(const Json &value, const char *field) {
    if (!value.contains(field) || !value.at(field).is_string()) return invalidAdmin();
    return value.at(field).get<std::string>();
}

} // namespace

RuntimeAdminHandlers::RuntimeAdminHandlers(SqliteBuildRepository &repository,
                                           SnapshotManager &snapshots,
                                           ValidationContext validation,
                                           Authorize authorize, Evidence evidence,
                                           ConfigurePolicy configurePolicy,
                                           AnonymousPolicy &policy)
    : repository_(repository), snapshots_(snapshots), validation_(std::move(validation)),
      authorize_(std::move(authorize)), evidence_(std::move(evidence)),
      configure_policy_(std::move(configurePolicy)), policy_(policy) {}

namespace {
bool refreshPolicy(const RuntimeAdminHandlers::ConfigurePolicy &configure,
                  SnapshotManager &snapshots, AnonymousPolicy &policy) {
    if (!configure) return true;
    AnonymousPolicy refreshed;
    std::string error;
    if (configure(*snapshots.acquire(), refreshed, error)) {
        policy.replaceWith(std::move(refreshed));
        return true;
    }
    snapshots.failClosed();
    return false;
}
}

std::variant<std::vector<std::byte>, BackendError> RuntimeAdminHandlers::handle(
    std::string_view path, std::span<const std::byte> body, const std::string &credential) {
    try {
        const std::string text(reinterpret_cast<const char *>(body.data()), body.size());
        const auto value = Json::parse(text);
        const bool import = path == "/v2/admin/builds/import";
        const bool revoke = path.ends_with("/revoke");
        const bool enable = path.ends_with("/enable");
        if ((!import && !revoke && !enable) || (import && (revoke || enable))) return invalidAdmin();
        std::string buildId;
        std::string artifactHash;
        if (import) {
            if (!closed(value, {"public_manifest_b64", "private_registration_b64",
                                "verifier_sidecars_b64", "final_artifact_hash"})) return invalidAdmin();
            auto artifact = stringField(value, "final_artifact_hash");
            if (const auto *error = std::get_if<BackendError>(&artifact)) return *error;
            artifactHash = std::get<std::string>(std::move(artifact));
            if (!validHash(artifactHash)) return invalidAdmin();
            auto publicManifest = decodeJsonObject(value.at("public_manifest_b64"),
                                                         kMaxPublicManifestBytes);
            auto privateRegistration = decodeJsonObject(value.at("private_registration_b64"),
                                                             kMaxPrivateRegistrationBytes);
            if (std::holds_alternative<BackendError>(publicManifest) ||
                std::holds_alternative<BackendError>(privateRegistration))
                return std::holds_alternative<BackendError>(publicManifest)
                    ? std::get<BackendError>(publicManifest) : std::get<BackendError>(privateRegistration);
            const auto &manifest = std::get<Json>(publicManifest);
            const auto &registration = std::get<Json>(privateRegistration);
            auto manifestBuild = stringField(manifest, "build_id");
            auto manifestSoftware = stringField(manifest, "software_id");
            if (std::holds_alternative<BackendError>(manifestBuild) ||
                std::holds_alternative<BackendError>(manifestSoftware)) return invalidAdmin();
            buildId = std::get<std::string>(manifestBuild);
            const auto softwareId = std::get<std::string>(manifestSoftware);
            if (!validHash(buildId) || softwareId.empty() || !registration.is_object()) return invalidAdmin();
            auto sidecars = decodeJsonObject(value.at("verifier_sidecars_b64"),
                                                  kMaxPrivateRegistrationBytes);
            if (const auto *error = std::get_if<BackendError>(&sidecars)) return *error;
            ImportRecord record;
            record.build_id = buildId;
            record.software_id = softwareId;
            auto publicDecoded = decodeBase64(value.at("public_manifest_b64").get<std::string>(),
                                              kMaxPublicManifestBytes);
            auto privateDecoded = decodeBase64(value.at("private_registration_b64").get<std::string>(),
                                               kMaxPrivateRegistrationBytes);
            if (const auto *error = std::get_if<BackendError>(&publicDecoded)) return *error;
            if (const auto *error = std::get_if<BackendError>(&privateDecoded)) return *error;
            record.public_manifest = std::get<Bytes>(std::move(publicDecoded));
            record.private_registration = std::get<Bytes>(std::move(privateDecoded));
            for (const auto &[region, encoded] : std::get<Json>(sidecars).items()) {
                if (!validHash(region) || !encoded.is_string()) return invalidAdmin();
                auto verifier = decodeBase64(encoded.get<std::string>(), kMaxCanonicalRegionBytes);
                if (const auto *error = std::get_if<BackendError>(&verifier)) return *error;
                record.verifier_sidecars.emplace(region, std::get<Bytes>(std::move(verifier)));
            }
            if (!authorize_) return BackendError{"admin_unavailable"};
            auto principal = authorize_("import", buildId, artifactHash, credential);
            if (const auto *error = std::get_if<BackendError>(&principal)) return *error;
            const auto &admin = std::get<AdminPrincipal>(principal);
            if (!repository_.importBuild(record, admin)) return BackendError{"admin_failed"};
            return Bytes{};
        }
        constexpr std::string_view prefix = "/v2/admin/builds/";
        const auto suffix = revoke ? std::string_view("/revoke") : std::string_view("/enable");
        if (!path.starts_with(prefix) || !path.ends_with(suffix) ||
            path.size() <= prefix.size() + suffix.size()) return invalidAdmin();
        buildId = std::string(path.substr(prefix.size(), path.size() - prefix.size() - suffix.size()));
        if (!validHash(buildId) || !value.is_object()) return invalidAdmin();
        if (revoke) {
            if (!closed(value, {})) return invalidAdmin();
            if (!authorize_) return BackendError{"admin_unavailable"};
            auto principal = authorize_("revoke", buildId, "", credential);
            if (const auto *error = std::get_if<BackendError>(&principal)) return *error;
            if (!repository_.revokeAndPublish(buildId, std::get<AdminPrincipal>(principal),
                                              snapshots_, validation_)) return BackendError{"admin_failed"};
            if (!refreshPolicy(configure_policy_, snapshots_, policy_))
                return BackendError{"policy_unavailable"};
            return Bytes{};
        }
        if (!closed(value, {"final_artifact_hash"}) || !value.at("final_artifact_hash").is_string())
            return invalidAdmin();
        artifactHash = value.at("final_artifact_hash").get<std::string>();
        if (!validHash(artifactHash) || !authorize_ || !evidence_) return invalidAdmin();
        auto principal = authorize_("enable", buildId, artifactHash, credential);
        if (const auto *error = std::get_if<BackendError>(&principal)) return *error;
        auto evidence = evidence_(buildId, artifactHash);
        if (const auto *error = std::get_if<BackendError>(&evidence)) return *error;
        if (!repository_.enableAndPublish(buildId, artifactHash, std::get<Bytes>(evidence),
                                          std::get<AdminPrincipal>(principal), snapshots_, validation_))
            return BackendError{"admin_failed"};
        if (!refreshPolicy(configure_policy_, snapshots_, policy_))
            return BackendError{"policy_unavailable"};
        return Bytes{};
    } catch (...) {
        return invalidAdmin();
    }
}

} // namespace xovm::cloud_material
