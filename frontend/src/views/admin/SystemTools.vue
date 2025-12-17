<template>
  <div class="system-tools">
    <div class="page-header">
      <h1>系統工具</h1>
      <p class="subtitle">網路診斷與系統資訊（A03 命令注入演示）</p>
    </div>

    <el-alert type="warning" show-icon :closable="false" class="warning-alert">
      <template #title>
        ⚠️ 安全警告：此頁面在漏洞模式下存在命令注入漏洞
      </template>
      <div class="alert-content">
        <p>嘗試以下攻擊向量：</p>
        <ul>
          <li><code>127.0.0.1; cat /etc/passwd</code> - 命令串接</li>
          <li><code>127.0.0.1 | id</code> - 管道攻擊</li>
          <li><code>$(whoami)</code> - 命令替換</li>
        </ul>
      </div>
    </el-alert>

    <el-row :gutter="24">
      <!-- Ping 工具 -->
      <el-col :span="12">
        <el-card class="tool-card">
          <template #header>
            <div class="card-header">
              <span>🌐 Ping 主機</span>
            </div>
          </template>
          <el-form @submit.prevent="doPing">
            <el-form-item label="主機位址">
              <el-input 
                v-model="pingHost" 
                placeholder="例: 127.0.0.1 或 google.com"
                clearable
              />
            </el-form-item>
            <el-button type="primary" @click="doPing" :loading="pingLoading">
              執行 Ping
            </el-button>
          </el-form>
          <div v-if="pingResult" class="result-box">
            <div class="executed-cmd">$ {{ pingResult.command }}</div>
            <pre class="output">{{ pingResult.output }}</pre>
            <div class="exit-code" :class="{ error: pingResult.exitCode !== 0 }">
              Exit Code: {{ pingResult.exitCode }}
            </div>
          </div>
        </el-card>
      </el-col>

      <!-- DNS 查詢 -->
      <el-col :span="12">
        <el-card class="tool-card">
          <template #header>
            <div class="card-header">
              <span>🔍 DNS 查詢</span>
            </div>
          </template>
          <el-form @submit.prevent="doLookup">
            <el-form-item label="網域名稱">
              <el-input 
                v-model="lookupDomain" 
                placeholder="例: google.com"
                clearable
              />
            </el-form-item>
            <el-button type="primary" @click="doLookup" :loading="lookupLoading">
              查詢 DNS
            </el-button>
          </el-form>
          <div v-if="lookupResult" class="result-box">
            <div class="executed-cmd">$ {{ lookupResult.command }}</div>
            <pre class="output">{{ lookupResult.output }}</pre>
            <div class="exit-code" :class="{ error: lookupResult.exitCode !== 0 }">
              Exit Code: {{ lookupResult.exitCode }}
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 網路診斷 -->
    <el-card class="tool-card diagnose-card">
      <template #header>
        <div class="card-header">
          <span>🔧 網路診斷</span>
        </div>
      </template>
      <el-form :inline="true" @submit.prevent="doDiagnose">
        <el-form-item label="目標主機">
          <el-input 
            v-model="diagnoseTarget" 
            placeholder="主機或 URL"
            style="width: 200px"
          />
        </el-form-item>
        <el-form-item label="埠號">
          <el-input 
            v-model="diagnosePorts" 
            placeholder="80,443"
            style="width: 120px"
          />
        </el-form-item>
        <el-form-item label="工具">
          <el-select v-model="diagnoseTool" style="width: 120px">
            <el-option label="netcat (nc)" value="nc" />
            <el-option label="curl" value="curl" />
            <el-option label="wget" value="wget" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="doDiagnose" :loading="diagnoseLoading">
            執行診斷
          </el-button>
        </el-form-item>
      </el-form>
      <div v-if="diagnoseResult" class="result-box">
        <div class="executed-cmd">$ {{ diagnoseResult.command }}</div>
        <pre class="output">{{ diagnoseResult.output }}</pre>
        <div class="exit-code" :class="{ error: diagnoseResult.exitCode !== 0 }">
          Exit Code: {{ diagnoseResult.exitCode }}
        </div>
      </div>
    </el-card>

    <!-- 系統資訊 -->
    <el-card class="tool-card">
      <template #header>
        <div class="card-header">
          <span>💻 系統資訊</span>
          <el-tag type="danger" size="small">危險</el-tag>
        </div>
      </template>
      <el-form :inline="true" @submit.prevent="doSystemInfo">
        <el-form-item label="命令">
          <el-input 
            v-model="systemCmd" 
            placeholder="系統命令 (預設: uname -a)"
            style="width: 400px"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="danger" @click="doSystemInfo" :loading="systemLoading">
            執行命令
          </el-button>
        </el-form-item>
      </el-form>
      <div v-if="systemResult" class="result-box">
        <div class="executed-cmd">$ {{ systemResult.command }}</div>
        <pre class="output">{{ systemResult.output }}</pre>
        <div class="exit-code" :class="{ error: systemResult.exitCode !== 0 }">
          Exit Code: {{ systemResult.exitCode }}
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

// Ping
const pingHost = ref('')
const pingLoading = ref(false)
const pingResult = ref(null)

// DNS Lookup
const lookupDomain = ref('')
const lookupLoading = ref(false)
const lookupResult = ref(null)

// Diagnose
const diagnoseTarget = ref('')
const diagnosePorts = ref('80')
const diagnoseTool = ref('nc')
const diagnoseLoading = ref(false)
const diagnoseResult = ref(null)

// System Info
const systemCmd = ref('uname -a')
const systemLoading = ref(false)
const systemResult = ref(null)

const doPing = async () => {
  if (!pingHost.value) {
    ElMessage.warning('請輸入主機位址')
    return
  }
  pingLoading.value = true
  pingResult.value = null
  try {
    const response = await api.systemPing(pingHost.value)
    pingResult.value = response.data
  } catch (error) {
    pingResult.value = { 
      command: `ping -c 3 ${pingHost.value}`,
      output: error.response?.data?.detail || error.message,
      exitCode: 1
    }
  } finally {
    pingLoading.value = false
  }
}

const doLookup = async () => {
  if (!lookupDomain.value) {
    ElMessage.warning('請輸入網域名稱')
    return
  }
  lookupLoading.value = true
  lookupResult.value = null
  try {
    const response = await api.systemLookup(lookupDomain.value)
    lookupResult.value = response.data
  } catch (error) {
    lookupResult.value = { 
      command: `nslookup ${lookupDomain.value}`,
      output: error.response?.data?.detail || error.message,
      exitCode: 1
    }
  } finally {
    lookupLoading.value = false
  }
}

const doDiagnose = async () => {
  if (!diagnoseTarget.value) {
    ElMessage.warning('請輸入目標主機')
    return
  }
  diagnoseLoading.value = true
  diagnoseResult.value = null
  try {
    const response = await api.systemDiagnose({
      target: diagnoseTarget.value,
      ports: diagnosePorts.value,
      tool: diagnoseTool.value
    })
    diagnoseResult.value = response.data
  } catch (error) {
    diagnoseResult.value = { 
      command: `${diagnoseTool.value} ${diagnoseTarget.value}`,
      output: error.response?.data?.detail || error.message,
      exitCode: 1
    }
  } finally {
    diagnoseLoading.value = false
  }
}

const doSystemInfo = async () => {
  systemLoading.value = true
  systemResult.value = null
  try {
    const response = await api.systemInfo(systemCmd.value || 'uname -a')
    systemResult.value = response.data
  } catch (error) {
    systemResult.value = { 
      command: systemCmd.value || 'uname -a',
      output: error.response?.data?.detail || error.message,
      exitCode: 1
    }
  } finally {
    systemLoading.value = false
  }
}
</script>

<style lang="scss" scoped>
.system-tools {
  .page-header {
    margin-bottom: 24px;

    h1 {
      font-size: 24px;
      margin: 0 0 8px 0;
    }
    
    .subtitle {
      color: #909399;
      margin: 0;
    }
  }
  
  .warning-alert {
    margin-bottom: 24px;
    
    .alert-content {
      margin-top: 8px;
      
      p {
        margin: 0 0 8px 0;
      }
      
      ul {
        margin: 0;
        padding-left: 20px;
        
        li {
          margin-bottom: 4px;
        }
        
        code {
          background: rgba(0, 0, 0, 0.1);
          padding: 2px 6px;
          border-radius: 4px;
          font-family: 'Consolas', 'Monaco', monospace;
        }
      }
    }
  }
  
  .tool-card {
    margin-bottom: 24px;
    
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
  }
  
  .diagnose-card {
    margin-top: 24px;
  }
  
  .result-box {
    margin-top: 20px;
    background: #1e1e1e;
    border-radius: 8px;
    padding: 16px;
    
    .executed-cmd {
      color: #67c23a;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 14px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid #333;
    }
    
    .output {
      color: #fff;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-all;
      margin: 0;
      max-height: 300px;
      overflow-y: auto;
    }
    
    .exit-code {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid #333;
      color: #67c23a;
      font-size: 12px;
      
      &.error {
        color: #f56c6c;
      }
    }
  }
}
</style>
