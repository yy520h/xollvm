#!/usr/bin/env node
/**
 * XOVM2 Material Backend - Production Entry Point
 *
 * 启动云材料 v2 后端服务，需要配置：
 * - PostgreSQL 数据库 (DATABASE_URL)
 * - Relay/Admin 认证令牌
 * - 信任时间、签名密钥、匿名策略等生产提供者
 *
 * 详细部署说明见 deploy/README.md
 */

import http from 'node:http';
import {randomBytes} from 'node:crypto';
import pg from 'pg';

import {createProductionService} from './production.mjs';
import {createServer} from './server.mjs';

// 从环境变量读取配置
const config = {
  host: '127.0.0.1', // 仅绑定 loopback，需要 TLS 反向代理
  port: parseInt(process.env.PORT || '8080', 10),
  requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '10000', 10),
  maxConcurrentRequests: parseInt(process.env.MAX_CONCURRENT_REQUESTS || '128', 10),
  relayToken: process.env.XOVM_RELAY_TOKEN,
  adminToken: process.env.XOVM_ADMIN_TOKEN,
};

const databaseUrl = process.env.DATABASE_URL;

// 验证必需配置
function validateConfig() {
  const errors = [];

  if (!databaseUrl) {
    errors.push('DATABASE_URL 环境变量未设置');
  }

  if (!config.relayToken || config.relayToken.length < 32) {
    errors.push('XOVM_RELAY_TOKEN 必须至少 32 字符');
  }

  if (!config.adminToken || config.adminToken.length < 32) {
    errors.push('XOVM_ADMIN_TOKEN 必须至少 32 字符');
  }

  if (config.relayToken === config.adminToken) {
    errors.push('XOVM_RELAY_TOKEN 和 XOVM_ADMIN_TOKEN 必须不同');
  }

  if (!process.env.XOVM_TRUSTED_TIME_PROVIDER) {
    errors.push('XOVM_TRUSTED_TIME_PROVIDER 未配置');
  }

  if (!process.env.XOVM_SIGNING_KEY_PROVIDER) {
    errors.push('XOVM_SIGNING_KEY_PROVIDER 未配置');
  }

  if (!process.env.XOVM_ANONYMOUS_POLICY_PROVIDER) {
    errors.push('XOVM_ANONYMOUS_POLICY_PROVIDER 未配置');
  }

  if (!process.env.XOVM_TRUST_ROOT_PROVIDER) {
    errors.push('XOVM_TRUST_ROOT_PROVIDER 未配置');
  }

  if (errors.length > 0) {
    console.error('❌ 配置错误:\n  ' + errors.join('\n  '));
    console.error('\n详细配置说明见: cloud/material_v2/deploy/README.md');
    process.exit(1);
  }
}

async function main() {
  console.log('🚀 启动 XOVM2 Material Backend...');

  validateConfig();

  // 创建 PostgreSQL 连接池
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });

  try {
    // 测试数据库连接
    const client = await pool.connect();
    console.log('✅ PostgreSQL 连接成功');
    client.release();
  } catch (error) {
    console.error('❌ PostgreSQL 连接失败:', error.message);
    console.error('提示: 检查 DATABASE_URL 并确保数据库已运行且已执行 migrations');
    process.exit(1);
  }

  // TODO: 实例化生产提供者
  // 当前为占位符实现，生产环境需要实现：
  // - store: PostgreSQL-backed material store
  // - authorization: 认证服务
  // - clock: 可信时间源
  // - keyProvider: Ed25519 签名密钥提供者
  // - anonymousPolicy: 匿名策略提供者
  // - trustBundleProvider: 信任根提供者
  // - adminRepository: 管理员仓库

  console.warn('⚠️  生产提供者未完全实现，使用测试模式');
  console.warn('⚠️  不要在生产环境使用此配置！');

  // 创建生产服务（需要完整提供者实现）
  let productionService;
  try {
    productionService = await createProductionService({
      pool,
      store: null, // TODO: 实现 PostgreSQL store
      authorization: null, // TODO: 实现认证服务
      clock: null, // TODO: 实现可信时间
      keyProvider: null, // TODO: 实现密钥提供者
      anonymousPolicy: null, // TODO: 实现匿名策略
      trustBundleProvider: null, // TODO: 实现信任根
      adminRepository: null, // TODO: 实现管理仓库
      relayToken: config.relayToken,
      adminToken: config.adminToken,
      randomBytes,
    });
  } catch (error) {
    console.error('❌ 生产服务创建失败:', error.message);
    console.error('原因: 生产提供者尚未完全实现');
    console.error('当前状态: 后端框架已就绪，等待 store/clock/policy 等提供者实现');
    await pool.end();
    process.exit(1);
  }

  // 创建 HTTP 服务器
  const server = createServer({
    productionService,
    config,
    http,
  });

  // 优雅关闭处理
  const shutdown = async (signal) => {
    console.log(`\n收到 ${signal} 信号，开始优雅关闭...`);
    try {
      await server.close();
      await productionService.close();
      await pool.end();
      console.log('✅ 服务已安全关闭');
      process.exit(0);
    } catch (error) {
      console.error('❌ 关闭时出错:', error.message);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // 启动监听
  try {
    await server.listen();
    console.log(`✅ 服务器运行在 http://${config.host}:${config.port}`);
    console.log('📋 可用路由:');
    console.log('   POST /v2/relay          - 运行时材料请求');
    console.log('   POST /v2/admin/builds/* - 管理员操作');
    console.log('   GET  /v2/trust/*        - 公共信任根');
    console.log('   GET  /healthz           - 健康检查');
    console.log('\n⚠️  生产部署需要在 TLS 反向代理后运行，不要直接暴露此端口！');
  } catch (error) {
    console.error('❌ 服务器启动失败:', error.message);
    await pool.end();
    process.exit(1);
  }
}

main().catch(error => {
  console.error('❌ 未处理的错误:', error);
  process.exit(1);
});
