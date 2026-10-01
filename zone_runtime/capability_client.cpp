#include "capability_client.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>
#include <sys/stat.h>

namespace xollvm {
namespace {

using EvpKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

EvpKey readPublicKey(const std::string& pem) {
  if (pem.empty()) return {nullptr, EVP_PKEY_free};
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  if (!bio) return {nullptr, EVP_PKEY_free};
  return {PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
}

std::string responseBytes(const CapabilityResponse& response) {
  return canonicalizeCapabilityResponse(response);
}

bool verify(EVP_PKEY* key, const CapabilityResponse& response) {
  if (!key || response.signature.empty()) return false;
  const std::string& encoded = response.signature;
  std::vector<unsigned char> signature((encoded.size() / 4) * 3 + 3);
  int signatureLength = EVP_DecodeBlock(
      signature.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
      static_cast<int>(encoded.size()));
  if (signatureLength <= 0) return false;
  if (encoded.size() >= 1 && encoded[encoded.size() - 1] == '=') --signatureLength;
  if (encoded.size() >= 2 && encoded[encoded.size() - 2] == '=') --signatureLength;
  EvpMdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1)
    return false;
  return EVP_DigestVerify(ctx.get(), signature.data(), static_cast<size_t>(signatureLength),
                          reinterpret_cast<const unsigned char*>(responseBytes(response).data()),
                          responseBytes(response).size()) == 1;
}

}  // namespace

CapabilityClient::CapabilityClient(CapabilityClientConfig config)
    : config_(std::move(config)) {
  loadState();
}

bool CapabilityClient::verifySignature(const CapabilityResponse& response) const {
  EvpKey key = readPublicKey(config_.public_key_pem);
  return verify(key.get(), response);
}

bool CapabilityClient::writeState(const CapabilityResponse& response) {
  if (config_.state_path.empty()) return false;
  const std::string temporary = config_.state_path + ".tmp";
  {
    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    file << response.next_state << '\n' << response.operation << '\n'
         << response.expires_at << '\n';
    file.flush();
    if (!file) return false;
  }
  chmod(temporary.c_str(), 0600);
  if (std::rename(temporary.c_str(), config_.state_path.c_str()) != 0) {
    std::remove(temporary.c_str());
    return false;
  }
  state_ = response.next_state;
  response_ = response;
  return true;
}

bool CapabilityClient::loadState() {
  if (config_.state_path.empty()) return false;
  std::ifstream file(config_.state_path, std::ios::binary);
  std::string operation;
  uint64_t expires = 0;
  if (!file || !(file >> state_ >> operation >> expires) ||
      operation != config_.operation || expires < config_.server_time) {
    state_.clear();
    return false;
  }
  return true;
}

bool CapabilityClient::acceptResponse(const CapabilityResponse& response,
                                      const std::string& expected_request_hash,
                                      const std::string& expected_device_id_hash) {
  const uint64_t now = config_.server_time;
  if (!validateCapabilityResponse(response) || response.key_id != config_.key_id ||
      response.operation != config_.operation || response.request_hash != expected_request_hash ||
      (!expected_device_id_hash.empty() && response.device_id_hash != expected_device_id_hash) ||
      response.policy_version != config_.policy_version || !verifySignature(response) ||
      response.issued_at > now + config_.clock_skew_seconds ||
      response.expires_at + config_.clock_skew_seconds < now ||
      response.expires_at <= response.issued_at)
    return false;
  return writeState(response);
}

bool CapabilityClient::hasState() const { return !state_.empty(); }

const std::string& CapabilityClient::state() const { return state_; }

const CapabilityResponse& CapabilityClient::response() const { return response_; }

bool CapabilityClient::require(const std::string& operation, uint64_t now) const {
  return !state_.empty() && response_.operation == operation && response_.ok &&
         response_.issued_at <= now && now <= response_.expires_at;
}

bool CapabilityClient::signTestResponse(CapabilityResponse* response) {
  if (!response) return false;
  EvpKey key(nullptr, EVP_PKEY_free);
  EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!raw) return false;
  EVP_PKEY* generated = nullptr;
  if (EVP_PKEY_keygen_init(raw) != 1 || EVP_PKEY_keygen(raw, &generated) != 1) {
    EVP_PKEY_CTX_free(raw);
    return false;
  }
  key.reset(generated);
  EVP_PKEY_CTX_free(raw);
  std::unique_ptr<BIO, decltype(&BIO_free)> publicBio(BIO_new(BIO_s_mem()), BIO_free);
  if (!publicBio || PEM_write_bio_PUBKEY(publicBio.get(), key.get()) != 1) return false;
  char* publicData = nullptr;
  long publicLength = BIO_get_mem_data(publicBio.get(), &publicData);
  config_.public_key_pem.assign(publicData, static_cast<size_t>(publicLength));
  EvpMdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  size_t signatureLength = 0;
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
      EVP_DigestSign(ctx.get(), nullptr, &signatureLength,
                     reinterpret_cast<const unsigned char*>(responseBytes(*response).data()),
                     responseBytes(*response).size()) != 1)
    return false;
  std::string signature(signatureLength, '\0');
  if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(signature.data()),
                     &signatureLength,
                     reinterpret_cast<const unsigned char*>(responseBytes(*response).data()),
                     responseBytes(*response).size()) != 1)
    return false;
  signature.resize(signatureLength);
  std::string encoded((signatureLength + 2) / 3 * 4, '\0');
  const int encodedLength = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(encoded.data()),
      reinterpret_cast<const unsigned char*>(signature.data()),
      static_cast<int>(signatureLength));
  encoded.resize(encodedLength);
  response->signature = std::move(encoded);
  return true;
}

}  // namespace xollvm
