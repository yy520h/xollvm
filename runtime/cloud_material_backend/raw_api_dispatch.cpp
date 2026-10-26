#include "raw_api_dispatch.h"

#include "../cloud_material/dynamic_vm_schema.h"

#include <algorithm>
#include <array>

namespace xovm::cloud_material {
namespace {

constexpr size_t kMaxApiPayload = 64 * 1024;

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put32(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put64(std::vector<uint8_t> &out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(value >> shift));
}

void putBytes(std::vector<uint8_t> &out, std::span<const uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void putString(std::vector<uint8_t> &out, std::string_view value) {
    put16(out, static_cast<uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool take16(std::span<const uint8_t> bytes, size_t &offset, uint16_t &value) {
    if (bytes.size() - offset < 2) return false;
    value = static_cast<uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
    offset += 2;
    return true;
}

bool take32(std::span<const uint8_t> bytes, size_t &offset, uint32_t &value) {
    if (bytes.size() - offset < 4) return false;
    value = (static_cast<uint32_t>(bytes[offset]) << 24) |
            (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
            (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
            bytes[offset + 3];
    offset += 4;
    return true;
}

bool takeString(std::span<const uint8_t> bytes, size_t &offset, std::string &value,
                size_t max_size) {
    uint16_t size = 0;
    if (!take16(bytes, offset, size) || size == 0 || size > max_size || bytes.size() - offset < size)
        return false;
    value.assign(reinterpret_cast<const char *>(bytes.data() + offset), size);
    offset += size;
    return true;
}

std::vector<uint8_t> errorResponse(std::string_view code) {
    if (code.empty() || code.size() > 64) code = "invalid_error";
    std::vector<uint8_t> result;
    put16(result, 0xffff);
    putString(result, code);
    return result;
}

RawApiDispatchError dispatchError(std::string_view code) {
    if (code.empty() || code.size() > 64) return RawApiDispatchError{"internal_error"};
    return RawApiDispatchError{std::string(code)};
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> encodeAnnouncement(
    const std::variant<AnnouncementResponse, CloudApiError> &result) {
    if (const auto *error = std::get_if<CloudApiError>(&result)) return dispatchError(error->code);
    const auto &value = std::get<AnnouncementResponse>(result);
    if (value.announcement_id.empty() || value.announcement_id.size() > 64 || value.content.size() > 16 * 1024 ||
        value.signature.size() > 128) return RawApiDispatchError{"response_too_large"};
    std::vector<uint8_t> out; put16(out, 1); putString(out, value.announcement_id);
    put32(out, value.version); out.push_back(value.priority); put64(out, value.issued_at_ms);
    put64(out, value.expires_at_ms); putString(out, value.content); putBytes(out, value.signature);
    return out;
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> encodeUpdate(
    const std::variant<UpdateResponse, CloudApiError> &result) {
    if (const auto *error = std::get_if<CloudApiError>(&result)) return dispatchError(error->code);
    const auto &value = std::get<UpdateResponse>(result);
    if (value.version.empty() || value.version.size() > 64 || value.signature.size() > 128)
        return RawApiDispatchError{"response_too_large"};
    std::vector<uint8_t> out; put16(out, 2); putString(out, value.version); putBytes(out, value.artifact_hash);
    put64(out, value.size); put32(out, value.chunk_count); putBytes(out, value.signature); return out;
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> encodeWindow(
    const std::variant<xovm::material::WindowGrant, CloudApiError> &result) {
    if (const auto *error = std::get_if<CloudApiError>(&result)) return dispatchError(error->code);
    const auto encoded = xovm::material::encodeWindowGrant(std::get<xovm::material::WindowGrant>(result));
    if (encoded.empty() || encoded.size() > kMaxApiPayload) return RawApiDispatchError{"response_too_large"};
    return encoded;
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> encodeVariables(
    const std::variant<RemoteVariablesResponse, CloudApiError> &result) {
    if (const auto *error = std::get_if<CloudApiError>(&result)) return dispatchError(error->code);
    const auto &value = std::get<RemoteVariablesResponse>(result);
    if (value.canonical_variables.size() > 16 * 1024 || value.signature.size() > 128)
        return RawApiDispatchError{"response_too_large"};
    std::vector<uint8_t> out; put16(out, 4); put32(out, value.version); put64(out, value.expires_at_ms);
    put32(out, static_cast<uint32_t>(value.canonical_variables.size())); putBytes(out, value.canonical_variables);
    putBytes(out, value.signature); return out;
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> encodeLogin(
    const std::variant<LoginResponse, CloudApiError> &result) {
    if (const auto *error = std::get_if<CloudApiError>(&result)) return dispatchError(error->code);
    const auto &value = std::get<LoginResponse>(result);
    if (value.allowed_regions.size() > 64) return RawApiDispatchError{"response_too_large"};
    std::vector<uint8_t> out; put16(out, 5); putBytes(out, value.session_id);
    put64(out, value.expires_at_ms); put64(out, value.generation); put16(out, static_cast<uint16_t>(value.allowed_regions.size()));
    for (const auto &region : value.allowed_regions) {
        if (region.empty() || region.size() > 64) return RawApiDispatchError{"response_too_large"};
        putString(out, region);
    }
    return out;
}

std::variant<std::vector<uint8_t>, RawApiDispatchError> parseSingleString(
    std::span<const uint8_t> payload, std::string &value) {
    size_t offset = 0;
    if (!takeString(payload, offset, value, 64) || offset != payload.size())
        return RawApiDispatchError{"invalid_request"};
    return std::vector<uint8_t>{};
}

} // namespace

std::variant<std::vector<uint8_t>, RawApiDispatchError> RawApiDispatch::handle(
    const AuthenticatedRawContext &context,
    const xovm::material::RawFrameHeader &header,
    std::span<const uint8_t> payload) const {
    if (payload.size() > kMaxApiPayload) return dispatchError("request_too_large");
    switch (header.type) {
    case xovm::material::RawFrameType::Announcement:
        if (!payload.empty()) return dispatchError("invalid_request");
        return encodeAnnouncement(api_.announcement());
    case xovm::material::RawFrameType::Update: {
        std::string version;
        if (auto parsed = parseSingleString(payload, version); std::holds_alternative<RawApiDispatchError>(parsed))
            return dispatchError("invalid_request");
        return encodeUpdate(api_.update(version));
    }
    case xovm::material::RawFrameType::AlgorithmAcquire: {
        const auto request = xovm::material::decodeWindowAcquireRequest(payload);
        if (!request) return dispatchError("invalid_request");
        return encodeWindow(api_.algorithm(context, *request));
    }
    case xovm::material::RawFrameType::RemoteVariables: {
        std::string session;
        if (auto parsed = parseSingleString(payload, session); std::holds_alternative<RawApiDispatchError>(parsed))
            return dispatchError("invalid_request");
        return encodeVariables(api_.variables(session));
    }
    case xovm::material::RawFrameType::LoginAccount: {
        size_t offset = 0; std::string account; uint32_t proof_size = 0;
        if (!takeString(payload, offset, account, 128) || !take32(payload, offset, proof_size) ||
            proof_size > 4096 || payload.size() - offset != proof_size)
            return dispatchError("invalid_request");
        return encodeLogin(api_.accountLogin(account, payload.subspan(offset, proof_size)));
    }
    case xovm::material::RawFrameType::LoginCard: {
        size_t offset = 0; uint16_t card_size = 0; uint16_t binding_size = 0;
        if (!take16(payload, offset, card_size) || card_size == 0 || card_size > 256 ||
            payload.size() - offset < card_size)
            return dispatchError("invalid_request");
        const auto card = payload.subspan(offset, card_size);
        offset += card_size;
        if (!take16(payload, offset, binding_size) || binding_size == 0 || binding_size > 256 ||
            payload.size() - offset != binding_size)
            return dispatchError("invalid_request");
        const auto binding = payload.subspan(offset, binding_size);
        return encodeLogin(api_.cardLogin(card, binding));
    }
    default:
        return dispatchError("unknown_operation");
    }
}

std::vector<uint8_t> RawApiDispatch::encodeError(const RawApiDispatchError &error) {
    return errorResponse(error.code);
}

} // namespace xovm::cloud_material
