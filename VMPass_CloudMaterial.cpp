// ============================================================================
// VMPass_CloudMaterial.cpp — 云端动态VM窗口集成
//
// 此文件实现了VMPass与云端窗口提供商的集成：
//   - 在编译时生成窗口元数据
//   - 插入运行时窗口获取调用
//   - 集成ChaffScheduler和CloudProvider
// ============================================================================

#include "llvm/Transforms/Obfuscator/VMPass_CloudMaterial.h"
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SHA256.h"

#include <vector>
#include <string>

using namespace llvm;

// ============================================================================
// 窗口元数据生成
// ============================================================================

namespace {

// 计算窗口的密码学承诺
std::array<uint8_t, 32> computeWindowCommitment(const std::vector<uint8_t>& bytecode) {
  SHA256 hasher;
  hasher.update(llvm::ArrayRef<uint8_t>(bytecode.data(), bytecode.size()));

  std::array<uint8_t, 32> result;
  auto hash = hasher.final();
  std::copy(hash.begin(), hash.end(), result.begin());
  return result;
}

} // anonymous namespace

// ============================================================================
// CloudMaterialEmitter - 生成运行时调用代码
// ============================================================================

void CloudMaterialEmitter::emitWindowFetchCall(
    IRBuilder<>& Builder,
    Function* F,
    uint32_t window_id,
    uint32_t shard_id,
    const std::array<uint8_t, 32>& commitment) {

  LLVMContext& Ctx = F->getContext();
  Module* M = F->getParent();

  // 声明运行时函数: void* xovm_fetch_window(uint32_t, uint32_t, uint8_t*)
  PointerType* PtrTy = PointerType::getUnqual(Ctx);
  FunctionType* FetchType = FunctionType::get(
    PtrTy,  // 返回窗口指针
    {Builder.getInt32Ty(), Builder.getInt32Ty(), PtrTy},
    false
  );

  FunctionCallee FetchFunc = M->getOrInsertFunction(
    "xovm_fetch_window", FetchType
  );

  // 创建承诺hash的全局常量
  std::vector<Constant*> hashBytes;
  for (uint8_t byte : commitment) {
    hashBytes.push_back(Builder.getInt8(byte));
  }
  ArrayType* HashArrayTy = ArrayType::get(Builder.getInt8Ty(), 32);
  Constant* HashArray = ConstantArray::get(HashArrayTy, hashBytes);

  GlobalVariable* CommitmentGV = new GlobalVariable(
    *M, HashArrayTy, true, GlobalValue::PrivateLinkage,
    HashArray, "window_commitment"
  );

  // 插入调用
  Value* CommitmentPtr = Builder.CreateBitCast(
    CommitmentGV, PtrTy
  );

  Value* WindowPtr = Builder.CreateCall(
    FetchFunc,
    {Builder.getInt32(window_id),
     Builder.getInt32(shard_id),
     CommitmentPtr}
  );

  // 存储窗口指针供后续使用
  windowPtr = WindowPtr;
}

// 生成Chaff调度器初始化代码
void CloudMaterialEmitter::emitChaffSchedulerInit(
    IRBuilder<>& Builder,
    Module* M,
    uint32_t total_windows,
    uint32_t chaff_percentage) {

  // 声明: void xovm_init_chaff_scheduler(uint32_t, uint32_t)
  FunctionType* InitType = FunctionType::get(
    Builder.getVoidTy(),
    {Builder.getInt32Ty(), Builder.getInt32Ty()},
    false
  );

  FunctionCallee InitFunc = M->getOrInsertFunction(
    "xovm_init_chaff_scheduler", InitType
  );

  Builder.CreateCall(
    InitFunc,
    {Builder.getInt32(total_windows),
     Builder.getInt32(chaff_percentage)}
  );
}

// 生成窗口选择代码（真实窗口 vs Chaff）
Value* CloudMaterialEmitter::emitWindowSelection(
    IRBuilder<>& Builder,
    Module* M) {

  // 声明: uint32_t xovm_select_window()
  FunctionType* SelectType = FunctionType::get(
    Builder.getInt32Ty(),
    {},
    false
  );

  FunctionCallee SelectFunc = M->getOrInsertFunction(
    "xovm_select_window", SelectType
  );

  return Builder.CreateCall(SelectFunc);
}

// ============================================================================
// 窗口分割和元数据生成
// ============================================================================

std::vector<WindowMetadata> CloudMaterialEmitter::splitIntoWindows(
    const std::vector<uint8_t>& fullBytecode,
    uint32_t window_size,
    uint32_t chaff_percentage) {

  std::vector<WindowMetadata> windows;

  uint32_t num_real_windows = (fullBytecode.size() + window_size - 1) / window_size;
  uint32_t num_chaff_windows = (num_real_windows * chaff_percentage) / 100;
  uint32_t total_windows = num_real_windows + num_chaff_windows;

  // 分割真实窗口
  for (uint32_t i = 0; i < num_real_windows; ++i) {
    WindowMetadata window;
    window.window_id = i;
    window.shard_id = 0;  // 默认单分片
    window.is_chaff = false;

    size_t start = i * window_size;
    size_t end = std::min(start + window_size, fullBytecode.size());

    window.bytecode.assign(
      fullBytecode.begin() + start,
      fullBytecode.begin() + end
    );
    window.bytecode_size = window.bytecode.size();
    window.commitment_hash = computeWindowCommitment(window.bytecode);

    windows.push_back(window);
  }

  // 生成Chaff窗口（随机字节码）
  for (uint32_t i = 0; i < num_chaff_windows; ++i) {
    WindowMetadata window;
    window.window_id = num_real_windows + i;
    window.shard_id = 0;
    window.is_chaff = true;

    // 生成随机Chaff数据
    window.bytecode.resize(window_size);
    for (size_t j = 0; j < window_size; ++j) {
      window.bytecode[j] = rand() % 256;
    }
    window.bytecode_size = window.bytecode.size();
    window.commitment_hash = computeWindowCommitment(window.bytecode);

    windows.push_back(window);
  }

  return windows;
}

// ============================================================================
// 编译时配置生成
// ============================================================================

void CloudMaterialEmitter::generateRuntimeConfig(
    const std::vector<WindowMetadata>& windows,
    const std::string& output_path) {

  std::error_code EC;
  raw_fd_ostream Out(output_path, EC);
  if (EC) {
    errs() << "Failed to create config file: " << EC.message() << "\n";
    return;
  }

  // 生成JSON格式的配置
  Out << "{\n";
  Out << "  \"version\": \"1.0\",\n";
  Out << "  \"total_windows\": " << windows.size() << ",\n";
  Out << "  \"windows\": [\n";

  for (size_t i = 0; i < windows.size(); ++i) {
    const auto& w = windows[i];

    Out << "    {\n";
    Out << "      \"window_id\": " << w.window_id << ",\n";
    Out << "      \"shard_id\": " << w.shard_id << ",\n";
    Out << "      \"is_chaff\": " << (w.is_chaff ? "true" : "false") << ",\n";
    Out << "      \"bytecode_size\": " << w.bytecode_size << ",\n";
    Out << "      \"commitment\": \"";

    // 输出十六进制承诺
    for (uint8_t byte : w.commitment_hash) {
      Out << format("%02x", byte);
    }
    Out << "\"\n";
    Out << "    }";

    if (i < windows.size() - 1) {
      Out << ",";
    }
    Out << "\n";
  }

  Out << "  ]\n";
  Out << "}\n";
  Out.flush();
}

// ============================================================================
// VMPass集成接口
// ============================================================================

bool CloudMaterialEmitter::integrateWithVMPass(
    Function& F,
    const std::vector<uint8_t>& vmBytecode,
    const VMPassConfig& config) {

  Module* M = F.getParent();
  LLVMContext& Ctx = M->getContext();

  // 1. 分割为窗口
  // TODO: 从云端材料配置中获取这些参数
  uint32_t window_size = 2048;  // 默认窗口大小
  uint32_t chaff_pct = 20;      // 默认混淆百分比

  auto windows = splitIntoWindows(vmBytecode, window_size, chaff_pct);

  // 2. 生成配置文件
  // TODO: 配置文件路径应从编译选项获取
  std::string configPath = "";
  if (!configPath.empty()) {
    generateRuntimeConfig(windows, configPath);
  }

  // 3. 在函数入口插入初始化代码
  BasicBlock& Entry = F.getEntryBlock();
  IRBuilder<> Builder(&Entry, Entry.getFirstInsertionPt());

  emitChaffSchedulerInit(Builder, M, windows.size(), chaff_pct);

  // 4. 在每个VM dispatch点插入窗口获取逻辑
  // （这部分需要与VMPass_Emitter协同）

  return true;
}

// ============================================================================
// 后端打包功能
// ============================================================================

#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <filesystem>
#include "llvm/Transforms/Obfuscator/ECC_KeyManager.h"

namespace {

// 获取当前时间戳
std::string getCurrentTimestamp() {
  time_t now = time(nullptr);
  char buf[100];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
  return std::string(buf);
}

// 生成随机密钥
std::string generateRandomSecret(size_t length) {
  static const char charset[] = "0123456789abcdef";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

  std::string secret;
  secret.reserve(length);
  for (size_t i = 0; i < length; i++) {
    secret += charset[dis(gen)];
  }
  return secret;
}

// 材料信息
struct MaterialInfo {
  std::string id;
  size_t total_size;
  uint32_t window_count;
  uint32_t shard_count;
  std::string commitment;
  std::string window_dir;
};

// 后端打包配置
struct BackendPackageConfig {
  std::string output_dir;
  std::string app_id;
  std::string app_version;
  std::string mode;              // "direct" or "zone"
  std::string hmac_secret;       // Direct 模式密钥
  std::string zone_token;        // Zone 模式 token
  bool enable_tls;
  std::string ndk_path;          // NDK 路径
};

// 写入文件
bool writeFile(const std::string& path, const std::string& content) {
  std::ofstream file(path);
  if (!file.is_open()) {
    errs() << "[CloudMaterial] Failed to create file: " << path << "\n";
    return false;
  }
  file << content;
  file.close();
  return true;
}

// 生成 metadata.json
bool generateMetadataJson(const std::string& output_path,
                         const BackendPackageConfig& config,
                         const std::vector<MaterialInfo>& materials) {
  std::ostringstream json;
  json << "{\n";
  json << "  \"app_id\": \"" << config.app_id << "\",\n";
  json << "  \"version\": \"" << config.app_version << "\",\n";
  json << "  \"build_time\": \"" << getCurrentTimestamp() << "\",\n";
  json << "  \"window_size\": 2048,\n";
  json << "  \"chaff_ratio\": 0.3,\n";
  json << "  \"materials\": {\n";

  for (size_t i = 0; i < materials.size(); i++) {
    const auto& mat = materials[i];
    json << "    \"" << mat.id << "\": {\n";
    json << "      \"id\": \"" << mat.id << "\",\n";
    json << "      \"total_size\": " << mat.total_size << ",\n";
    json << "      \"window_count\": " << mat.window_count << ",\n";
    json << "      \"shard_count\": " << mat.shard_count << ",\n";
    json << "      \"commitment\": \"" << mat.commitment << "\"\n";
    json << "    }";
    if (i < materials.size() - 1) {
      json << ",";
    }
    json << "\n";
  }

  json << "  }\n";
  json << "}\n";

  return writeFile(output_path, json.str());
}

// 生成 config.yaml
bool generateConfigYaml(const std::string& output_path,
                       const BackendPackageConfig& config) {
  std::ostringstream yaml;
  yaml << "app:\n";
  yaml << "  id: \"" << config.app_id << "\"\n";
  yaml << "  version: \"" << config.app_version << "\"\n\n";
  yaml << "mode: " << config.mode << "\n\n";

  if (config.mode == "direct") {
    yaml << "direct:\n";
    yaml << "  listen: \"0.0.0.0:8080\"\n";
    yaml << "  auth_method: hmac\n";
    yaml << "  secret: \"" << config.hmac_secret << "\"\n";
    yaml << "  tls:\n";
    yaml << "    enabled: " << (config.enable_tls ? "true" : "false") << "\n";
    if (config.enable_tls) {
      yaml << "    cert: \"/path/to/cert.pem\"\n";
      yaml << "    key: \"/path/to/key.pem\"\n";
    }
    yaml << "  security:\n";
    yaml << "    rate_limit:\n";
    yaml << "      enabled: true\n";
    yaml << "      requests_per_device_per_minute: 100\n";
    yaml << "      requests_per_ip_per_minute: 500\n";
    yaml << "    replay_protection:\n";
    yaml << "      enabled: true\n";
    yaml << "      time_window_seconds: 300\n";
    yaml << "      nonce_cache_size: 10000\n";
  } else {
    yaml << "zone:\n";
    yaml << "  listen: \"0.0.0.0:8081\"\n";
    yaml << "  verify_token: \"" << config.zone_token << "\"\n";
    yaml << "  algorithm_file: \"./cloud_algorithm.js\"\n";
  }

  yaml << "\nstorage:\n";
  yaml << "  windows_dir: \"./windows/\"\n";
  yaml << "  metadata_file: \"./metadata.json\"\n";
  yaml << "\nlogging:\n";
  yaml << "  level: \"info\"\n";

  return writeFile(output_path, yaml.str());
}

// 生成 DEPLOY.txt
bool generateDeployTxt(const std::string& output_path,
                      const BackendPackageConfig& config) {
  std::ostringstream txt;
  txt << "=== xollvm Backend 部署包 ===\n\n";
  txt << "应用: " << config.app_id << " v" << config.app_version << "\n";
  txt << "模式: " << config.mode << "\n";
  txt << "生成时间: " << getCurrentTimestamp() << "\n\n";

  txt << "部署步骤:\n\n";
  txt << "1. 上传此目录所有文件到服务器:\n";
  txt << "   scp -r backend_package/* user@your-server:/opt/xollvm-backend/\n\n";

  if (config.mode == "direct") {
    txt << "2. (推荐) 生成 TLS 证书:\n";
    txt << "   cd /opt/xollvm-backend\n";
    txt << "   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n";
    txt << "   然后更新 config.yaml 中的证书路径\n\n";
    txt << "3. 在客户端配置中设置:\n";
    txt << "   - 后端 URL: https://your-server:8080\n";
    txt << "   - HMAC Secret: " << config.hmac_secret << "\n\n";
    txt << "4. 启动服务器:\n";
    txt << "   chmod +x xollvm-backend-server\n";
    txt << "   ./xollvm-backend-server -config config.yaml\n\n";
  } else {
    txt << "2. 使用 Zone 平台生成的云算法文件替换 cloud_algorithm.js\n\n";
    txt << "3. 在 Zone 平台配置回调 URL:\n";
    txt << "   - 回调 URL: http://your-server:8081/zone/callback\n";
    txt << "   - 验证 Token: " << config.zone_token << "\n\n";
    txt << "4. 启动服务器:\n";
    txt << "   chmod +x xollvm-backend-server\n";
    txt << "   ./xollvm-backend-server -config config.yaml\n\n";
  }

  txt << "5. 检查服务状态:\n";
  txt << "   curl http://localhost:" << (config.mode == "direct" ? "8080" : "8081") << "/health\n\n";
  txt << "详细文档请参考 README.md\n";

  return writeFile(output_path, txt.str());
}

// 生成客户端配置头文件
bool generateClientConfig(const std::string& output_path,
                         const BackendPackageConfig& config,
                         const std::string& ecc_server_pubkey) {
  std::ostringstream header;
  header << "// Auto-generated by xollvm CloudMaterial\n";
  header << "// DO NOT EDIT MANUALLY\n\n";
  header << "#ifndef XOLLVM_CLOUD_CONFIG_H\n";
  header << "#define XOLLVM_CLOUD_CONFIG_H\n\n";
  header << "namespace xovm {\n";
  header << "namespace material {\n\n";
  header << "// 后端配置\n";
  header << "constexpr const char* BACKEND_MODE = \"" << config.mode << "\";\n";

  if (config.mode == "direct") {
    header << "constexpr const char* BACKEND_URL = \"https://your-server:8080\";\n";
    header << "constexpr const char* HMAC_SECRET = \"" << config.hmac_secret << "\";\n";
    header << "constexpr bool ENABLE_TLS = " << (config.enable_tls ? "true" : "false") << ";\n";
    header << "\n// ECC 动态加密配置\n";
    header << "constexpr bool ENABLE_ECC = true;\n";
    header << "constexpr const char* ECC_SERVER_PUBKEY = \"" << ecc_server_pubkey << "\";\n";
  } else {
    header << "constexpr const char* ZONE_CAPABILITY_ID = \"your-zone-capability-id\";\n";
  }

  header << "\n} // namespace material\n";
  header << "} // namespace xovm\n\n";
  header << "#endif // XOLLVM_CLOUD_CONFIG_H\n";

  return writeFile(output_path, header.str());
}

} // anonymous namespace

// 生成后端部署包
bool generateBackendPackage(const BackendPackageConfig& config,
                           const std::vector<MaterialInfo>& materials) {
  namespace fs = std::filesystem;

  outs() << "[CloudMaterial] Generating backend package...\n";

  // 生成 ECC 密钥对
  ECCKeyManager ecc_manager;
  if (!ecc_manager.generateKeys()) {
    errs() << "[CloudMaterial] Failed to generate ECC keys\n";
    return false;
  }
  outs() << "[CloudMaterial] ECC keys generated\n";
  outs() << ecc_manager.getKeyInfo();

  // 1. 创建输出目录
  std::string package_dir = config.output_dir + "/backend_package";
  try {
    fs::create_directories(package_dir);
    fs::create_directories(package_dir + "/windows");
  } catch (const std::exception& e) {
    errs() << "[CloudMaterial] Failed to create directories: " << e.what() << "\n";
    return false;
  }

  // 2. 复制后端服务器二进制
  std::string ndk_backend = config.ndk_path + "/xollvm-backend/xollvm-backend-server";
  std::string dst_backend = package_dir + "/xollvm-backend-server";

  try {
    if (fs::exists(ndk_backend)) {
      fs::copy_file(ndk_backend, dst_backend, fs::copy_options::overwrite_existing);
      fs::permissions(dst_backend, fs::perms::owner_exec | fs::perms::group_exec |
                     fs::perms::owner_read | fs::perms::group_read | fs::perms::owner_write);
      outs() << "[CloudMaterial] Copied backend server binary\n";
    } else {
      outs() << "[CloudMaterial] Warning: Backend server binary not found at " << ndk_backend << "\n";
      outs() << "[CloudMaterial] Please ensure xollvm-backend-server is in the NDK package\n";
    }
  } catch (const std::exception& e) {
    outs() << "[CloudMaterial] Warning: Failed to copy backend binary: " << e.what() << "\n";
  }

  // 3. 生成 metadata.json
  if (!generateMetadataJson(package_dir + "/metadata.json", config, materials)) {
    return false;
  }
  outs() << "[CloudMaterial] Generated metadata.json\n";

  // 4. 生成 config.yaml
  if (!generateConfigYaml(package_dir + "/config.yaml", config)) {
    return false;
  }
  outs() << "[CloudMaterial] Generated config.yaml\n";

  // 4.5 保存 ECC 服务器私钥到配置文件
  if (!ecc_manager.saveServerPrivateKey(package_dir + "/config.yaml")) {
    errs() << "[CloudMaterial] Failed to save ECC private key\n";
    return false;
  }

  // 4.6 生成客户端 ECC 配置头文件
  if (!ecc_manager.generateClientConfigHeader(config.output_dir + "/xollvm_ecc_config.h")) {
    errs() << "[CloudMaterial] Failed to generate ECC client config\n";
    return false;
  }
  outs() << "[CloudMaterial] Generated xollvm_ecc_config.h\n";

  // 5. 复制窗口文件
  size_t total_windows = 0;
  for (const auto& mat : materials) {
    for (uint32_t w = 0; w < mat.window_count; w++) {
      for (uint32_t s = 0; s < mat.shard_count; s++) {
        std::string src = mat.window_dir + "/" + mat.id + "_w" +
                         std::to_string(w) + "_s" + std::to_string(s) + ".bin";
        std::string dst = package_dir + "/windows/" + mat.id + "_w" +
                         std::to_string(w) + "_s" + std::to_string(s) + ".bin";

        try {
          if (fs::exists(src)) {
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
            total_windows++;
          }
        } catch (const std::exception& e) {
          errs() << "[CloudMaterial] Failed to copy window file: " << e.what() << "\n";
        }
      }
    }
  }
  outs() << "[CloudMaterial] Copied " << total_windows << " window files\n";

  // 6. 生成 DEPLOY.txt
  if (!generateDeployTxt(package_dir + "/DEPLOY.txt", config)) {
    return false;
  }

  // 7. 如果是 Zone 模式，创建占位符云算法文件
  if (config.mode == "zone") {
    std::string algo_content = "// Zone 云算法文件\n// 请使用 Zone 平台生成的实际算法文件替换此文件\n";
    writeFile(package_dir + "/cloud_algorithm.js", algo_content);
  }

  // 8. 复制文档
  std::string ndk_readme = config.ndk_path + "/xollvm-backend/README.md";
  try {
    if (fs::exists(ndk_readme)) {
      fs::copy_file(ndk_readme, package_dir + "/README.md", fs::copy_options::overwrite_existing);
    }
  } catch (const std::exception& e) {
    outs() << "[CloudMaterial] Warning: Failed to copy README: " << e.what() << "\n";
  }

  // 9. 生成客户端配置头文件（输出到编译目录）
  std::string ecc_pubkey = ecc_manager.getClientPublicKeyHex();
  if (!generateClientConfig(config.output_dir + "/xollvm_cloud_config.h", config, ecc_pubkey)) {
    return false;
  }
  outs() << "[CloudMaterial] Generated xollvm_cloud_config.h\n";

  // 10. 打包
  std::string tar_cmd = "cd " + config.output_dir + " && tar czf backend_package.tar.gz backend_package 2>/dev/null";
  int ret = system(tar_cmd.c_str());
  if (ret == 0) {
    outs() << "[CloudMaterial] Backend package created: " << config.output_dir << "/backend_package.tar.gz\n";
  } else {
    outs() << "[CloudMaterial] Warning: Failed to create tar archive (tar may not be available)\n";
    outs() << "[CloudMaterial] Backend package directory: " << package_dir << "\n";
  }

  outs() << "\n[CloudMaterial] ========================================\n";
  outs() << "[CloudMaterial] Backend package generated successfully!\n";
  outs() << "[CloudMaterial] ========================================\n";
  outs() << "[CloudMaterial] Location: " << config.output_dir << "/backend_package/\n";
  outs() << "[CloudMaterial] Mode: " << config.mode << "\n";
  if (config.mode == "direct") {
    outs() << "[CloudMaterial] HMAC Secret: " << config.hmac_secret << "\n";
    outs() << "[CloudMaterial] (保存此密钥，客户端需要使用相同密钥)\n";
  } else {
    outs() << "[CloudMaterial] Zone Token: " << config.zone_token << "\n";
  }
  outs() << "[CloudMaterial] 请参考 backend_package/DEPLOY.txt 进行部署\n";
  outs() << "[CloudMaterial] ========================================\n\n";

  return true;
}
