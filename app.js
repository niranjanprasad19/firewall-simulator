// ========== DATA STRUCTURES ==========

class Packet {
  constructor(id, sourceIP, sourcePort, destIP, destPort, protocol) {
    this.id = id;
    this.sourceIP = sourceIP;
    this.sourcePort = sourcePort;
    this.destIP = destIP;
    this.destPort = destPort;
    this.protocol = protocol;
    this.timestamp = new Date();
    this.action = null;
    this.matchedRule = null;
  }
}

class FirewallRule {
  constructor(id, priority, action, sourceIP, destIP, protocol, destPort, description) {
    this.id = id;
    this.priority = priority;
    this.action = action;
    this.sourceIP = sourceIP;
    this.destIP = destIP;
    this.protocol = protocol;
    this.destPort = destPort;
    this.description = description;
  }

  matches(packet) {
    // Check source IP
    if (!this.matchesIP(this.sourceIP, packet.sourceIP)) return false;
    
    // Check destination IP
    if (!this.matchesIP(this.destIP, packet.destIP)) return false;
    
    // Check protocol
    if (this.protocol !== '*' && this.protocol !== packet.protocol) return false;
    
    // Check destination port
    if (this.destPort !== '*' && this.destPort !== packet.destPort.toString()) return false;
    
    return true;
  }

  matchesIP(ruleIP, packetIP) {
    if (ruleIP === '*') return true;
    if (ruleIP === '0.0.0.0/0') return true;
    
    // Check for CIDR notation
    if (ruleIP.includes('/')) {
      return this.isIPInCIDR(packetIP, ruleIP);
    }
    
    // Exact match
    return ruleIP === packetIP;
  }

  isIPInCIDR(ip, cidr) {
    const [network, bits] = cidr.split('/');
    const mask = bits ? parseInt(bits) : 32;
    
    const ipNum = this.ipToNumber(ip);
    const networkNum = this.ipToNumber(network);
    const maskNum = -1 << (32 - mask);
    
    return (ipNum & maskNum) === (networkNum & maskNum);
  }

  ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }
}

// ========== GLOBAL STATE ==========

const state = {
  running: false,
  speed: 1.0,
  startTime: null,
  rules: [],
  packetQueue: [],
  activePackets: [],
  logs: [],
  stats: {
    total: 0,
    allowed: 0,
    dropped: 0,
    rejected: 0,
    tcp: 0,
    udp: 0,
    icmp: 0,
    blockedSources: {},
    allowedDestinations: {},
    processingTimes: []
  },
  packetIdCounter: 0,
  ruleIdCounter: 8
};

// ========== DATA POOLS ==========

const dataPools = {
  internalIPs: ['192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.50', '192.168.1.100', '10.0.0.5', '10.0.0.10'],
  maliciousIPs: ['203.0.113.5', '203.0.113.10', '203.0.113.25'],
  externalIPs: ['93.184.216.34', '142.250.185.78', '8.8.8.8', '1.1.1.1', '172.217.16.46'],
  serverIPs: ['192.168.2.50', '192.168.2.100'],
  commonPorts: [22, 23, 25, 53, 80, 443, 3306, 3389, 8080],
  protocols: ['TCP', 'UDP', 'ICMP']
};

// ========== INITIALIZATION ==========

function initializeDefaultRules() {
  state.rules = [
    new FirewallRule(1, 1, 'ALLOW', '192.168.1.0/24', '0.0.0.0/0', 'TCP', '80', 'Allow HTTP traffic from internal network'),
    new FirewallRule(2, 2, 'ALLOW', '192.168.1.0/24', '0.0.0.0/0', 'TCP', '443', 'Allow HTTPS traffic from internal network'),
    new FirewallRule(3, 3, 'DROP', '203.0.113.0/24', '*', '*', '*', 'Block malicious IP range (RFC 5737)'),
    new FirewallRule(4, 4, 'ALLOW', '192.168.1.100', '192.168.2.50', 'TCP', '22', 'Allow SSH from admin to server'),
    new FirewallRule(5, 5, 'DROP', '*', '*', 'TCP', '23', 'Block all Telnet (insecure)'),
    new FirewallRule(6, 6, 'DROP', '*', '*', 'TCP', '3389', 'Block RDP from internet'),
    new FirewallRule(7, 7, 'ALLOW', '192.168.1.0/24', '0.0.0.0/0', 'UDP', '53', 'Allow DNS queries')
  ];
}

// ========== PACKET GENERATION ==========

function generateRandomPacket() {
  const allSourceIPs = [...dataPools.internalIPs, ...dataPools.maliciousIPs, ...dataPools.externalIPs];
  const allDestIPs = [...dataPools.externalIPs, ...dataPools.serverIPs, ...dataPools.internalIPs];
  
  const sourceIP = allSourceIPs[Math.floor(Math.random() * allSourceIPs.length)];
  const sourcePort = Math.floor(Math.random() * (65535 - 1024) + 1024);
  const destIP = allDestIPs[Math.floor(Math.random() * allDestIPs.length)];
  const destPort = dataPools.commonPorts[Math.floor(Math.random() * dataPools.commonPorts.length)];
  const protocol = dataPools.protocols[Math.floor(Math.random() * dataPools.protocols.length)];
  
  return new Packet(++state.packetIdCounter, sourceIP, sourcePort, destIP, destPort, protocol);
}

function generatePackets() {
  if (!state.running) return;
  
  const packet = generateRandomPacket();
  state.packetQueue.push(packet);
  updatePacketQueue();
  
  // Process packet after queue update
  setTimeout(() => processNextPacket(), 500 / state.speed);
}

// ========== FIREWALL DECISION ENGINE ==========

function processNextPacket() {
  if (!state.running || state.packetQueue.length === 0) return;
  
  const packet = state.packetQueue.shift();
  updatePacketQueue();
  
  const startTime = performance.now();
  
  // Match against rules
  let matchedRule = null;
  for (const rule of state.rules) {
    if (rule.matches(packet)) {
      matchedRule = rule;
      break;
    }
  }
  
  // Apply action
  if (matchedRule) {
    packet.action = matchedRule.action;
    packet.matchedRule = matchedRule.id;
  } else {
    packet.action = 'DROP';
    packet.matchedRule = 'DEFAULT POLICY';
  }
  
  const endTime = performance.now();
  const processingTime = endTime - startTime;
  state.stats.processingTimes.push(processingTime);
  if (state.stats.processingTimes.length > 100) {
    state.stats.processingTimes.shift();
  }
  
  // Update statistics
  updateStatistics(packet);
  
  // Animate packet
  animatePacket(packet);
  
  // Log the decision
  logPacketDecision(packet);
  
  // Update current packet display
  displayCurrentPacket(packet);
}

function updateStatistics(packet) {
  state.stats.total++;
  
  switch (packet.action) {
    case 'ALLOW':
      state.stats.allowed++;
      const destKey = `${packet.destIP}:${packet.destPort}`;
      state.stats.allowedDestinations[destKey] = (state.stats.allowedDestinations[destKey] || 0) + 1;
      break;
    case 'DROP':
      state.stats.dropped++;
      state.stats.blockedSources[packet.sourceIP] = (state.stats.blockedSources[packet.sourceIP] || 0) + 1;
      break;
    case 'REJECT':
      state.stats.rejected++;
      state.stats.blockedSources[packet.sourceIP] = (state.stats.blockedSources[packet.sourceIP] || 0) + 1;
      break;
  }
  
  switch (packet.protocol) {
    case 'TCP':
      state.stats.tcp++;
      break;
    case 'UDP':
      state.stats.udp++;
      break;
    case 'ICMP':
      state.stats.icmp++;
      break;
  }
  
  updateStatsDisplay();
}

// ========== ANIMATION ==========

function animatePacket(packet) {
  const animationArea = document.getElementById('packetAnimation');
  const packetElement = document.createElement('div');
  packetElement.className = 'packet idle';
  packetElement.textContent = packet.protocol.substring(0, 3);
  packetElement.style.left = '10%';
  packetElement.style.top = '50%';
  
  animationArea.appendChild(packetElement);
  
  // Animate to center (firewall)
  setTimeout(() => {
    packetElement.style.left = '50%';
    packetElement.style.transition = `left ${1000 / state.speed}ms ease-in-out`;
  }, 50);
  
  // Apply decision at firewall
  setTimeout(() => {
    packetElement.classList.remove('idle');
    packetElement.classList.add(packet.action.toLowerCase());
    
    if (packet.action === 'ALLOW') {
      // Continue to destination
      setTimeout(() => {
        packetElement.style.left = '90%';
        packetElement.style.transition = `left ${1000 / state.speed}ms ease-in-out`;
      }, 100);
      
      setTimeout(() => {
        packetElement.remove();
      }, 1000 / state.speed + 200);
    } else {
      // Remove after animation
      setTimeout(() => {
        packetElement.remove();
      }, 600 / state.speed);
    }
  }, 1000 / state.speed + 100);
}

// ========== UI UPDATE FUNCTIONS ==========

function updateStatsDisplay() {
  document.getElementById('totalPackets').textContent = state.stats.total;
  document.getElementById('allowedPackets').textContent = state.stats.allowed;
  document.getElementById('droppedPackets').textContent = state.stats.dropped;
  document.getElementById('rejectedPackets').textContent = state.stats.rejected;
  
  const total = state.stats.total || 1;
  const allowedPercent = ((state.stats.allowed / total) * 100).toFixed(1);
  const droppedPercent = ((state.stats.dropped / total) * 100).toFixed(1);
  const rejectedPercent = ((state.stats.rejected / total) * 100).toFixed(1);
  
  document.getElementById('allowedPercent').textContent = `${allowedPercent}%`;
  document.getElementById('droppedPercent').textContent = `${droppedPercent}%`;
  document.getElementById('rejectedPercent').textContent = `${rejectedPercent}%`;
  
  document.getElementById('allowedProgress').style.width = `${allowedPercent}%`;
  document.getElementById('droppedProgress').style.width = `${droppedPercent}%`;
  document.getElementById('rejectedProgress').style.width = `${rejectedPercent}%`;
  
  // Protocol distribution
  const protocolTotal = state.stats.tcp + state.stats.udp + state.stats.icmp || 1;
  const tcpPercent = ((state.stats.tcp / protocolTotal) * 100).toFixed(0);
  const udpPercent = ((state.stats.udp / protocolTotal) * 100).toFixed(0);
  const icmpPercent = ((state.stats.icmp / protocolTotal) * 100).toFixed(0);
  
  document.getElementById('tcpBar').style.width = `${tcpPercent}%`;
  document.getElementById('udpBar').style.width = `${udpPercent}%`;
  document.getElementById('icmpBar').style.width = `${icmpPercent}%`;
  
  document.getElementById('tcpCount').textContent = state.stats.tcp;
  document.getElementById('udpCount').textContent = state.stats.udp;
  document.getElementById('icmpCount').textContent = state.stats.icmp;
  
  // Top blocked sources
  updateTopList('topBlocked', state.stats.blockedSources, 5);
  
  // Top allowed destinations
  updateTopList('topAllowed', state.stats.allowedDestinations, 5);
  
  // Performance stats
  const avgProcessing = state.stats.processingTimes.length > 0
    ? (state.stats.processingTimes.reduce((a, b) => a + b, 0) / state.stats.processingTimes.length).toFixed(2)
    : 0;
  document.getElementById('avgProcessing').textContent = `${avgProcessing}ms`;
  
  // Threat level
  const dropRate = ((state.stats.dropped + state.stats.rejected) / total) * 100;
  const threatLevelEl = document.getElementById('threatLevel');
  threatLevelEl.classList.remove('threat-low', 'threat-medium', 'threat-high');
  
  if (dropRate < 20) {
    threatLevelEl.textContent = 'Low';
    threatLevelEl.classList.add('threat-low');
  } else if (dropRate < 50) {
    threatLevelEl.textContent = 'Medium';
    threatLevelEl.classList.add('threat-medium');
  } else {
    threatLevelEl.textContent = 'High';
    threatLevelEl.classList.add('threat-high');
  }
}

function updateTopList(elementId, data, limit) {
  const container = document.getElementById(elementId);
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, limit);
  
  if (sorted.length === 0) {
    container.innerHTML = '<div class="top-item"><span class="top-item-label">No data yet</span></div>';
    return;
  }
  
  container.innerHTML = sorted.map(([key, count]) => `
    <div class="top-item">
      <span class="top-item-label">${key}</span>
      <span class="top-item-count">${count}</span>
    </div>
  `).join('');
}

function displayCurrentPacket(packet) {
  const container = document.getElementById('currentPacketDetails');
  const actionClass = packet.action.toLowerCase();
  const actionColor = {
    'allow': '#27ae60',
    'drop': '#e74c3c',
    'reject': '#f39c12'
  }[actionClass];
  
  container.innerHTML = `
    <div class="packet-info-grid">
      <div class="packet-info-item">
        <span class="packet-info-label">Source</span>
        <span class="packet-info-value">${packet.sourceIP}:${packet.sourcePort}</span>
      </div>
      <div class="packet-info-item">
        <span class="packet-info-label">Destination</span>
        <span class="packet-info-value">${packet.destIP}:${packet.destPort}</span>
      </div>
      <div class="packet-info-item">
        <span class="packet-info-label">Protocol</span>
        <span class="packet-info-value">${packet.protocol}</span>
      </div>
      <div class="packet-info-item">
        <span class="packet-info-label">Matched Rule</span>
        <span class="packet-info-value">#${packet.matchedRule}</span>
      </div>
    </div>
    <div class="packet-action action-${actionClass}" style="background: ${actionColor}15; border: 1px solid ${actionColor}; color: ${actionColor};">
      ${packet.action}
    </div>
  `;
}

function updatePacketQueue() {
  const container = document.getElementById('packetQueue');
  const queue = state.packetQueue.slice(0, 5);
  
  if (queue.length === 0) {
    container.innerHTML = '<p class="waiting">No packets in queue</p>';
    return;
  }
  
  container.innerHTML = queue.map(packet => `
    <div class="queue-item">
      ${packet.sourceIP}:${packet.sourcePort} → ${packet.destIP}:${packet.destPort} [${packet.protocol}]
    </div>
  `).join('');
}

function logPacketDecision(packet) {
  const timestamp = packet.timestamp.toLocaleTimeString();
  const icon = {
    'ALLOW': '✓',
    'DROP': '✗',
    'REJECT': '↩'
  }[packet.action];
  
  const logEntry = {
    timestamp,
    icon,
    action: packet.action,
    details: `${packet.sourceIP}:${packet.sourcePort} → ${packet.destIP}:${packet.destPort} [${packet.protocol}]`,
    rule: packet.matchedRule
  };
  
  state.logs.unshift(logEntry);
  if (state.logs.length > 50) {
    state.logs.pop();
  }
  
  updateActivityLog();
}

function updateActivityLog() {
  const container = document.getElementById('activityLog');
  
  if (state.logs.length === 0) {
    container.innerHTML = '<div class="log-entry"><span class="log-details">No activity yet</span></div>';
    return;
  }
  
  container.innerHTML = state.logs.map(log => `
    <div class="log-entry ${log.action.toLowerCase()}">
      <span class="log-timestamp">${log.timestamp}</span>
      <span class="log-icon ${log.action.toLowerCase()}">${log.icon}</span>
      <span class="log-details">${log.details}</span>
      <span class="log-rule">Rule: ${log.rule}</span>
    </div>
  `).join('');
}

function displayRules() {
  const container = document.getElementById('rulesList');
  document.getElementById('ruleCount').textContent = `${state.rules.length} Rules`;
  
  container.innerHTML = state.rules.map(rule => `
    <div class="rule-item">
      <div class="rule-header">
        <span class="rule-id">Rule #${rule.id} (Priority ${rule.priority})</span>
        <span class="rule-action action-${rule.action.toLowerCase()}">${rule.action}</span>
      </div>
      <div class="rule-details">
        <div class="rule-detail-row"><strong>Source:</strong> ${rule.sourceIP}</div>
        <div class="rule-detail-row"><strong>Dest:</strong> ${rule.destIP}</div>
        <div class="rule-detail-row"><strong>Protocol:</strong> ${rule.protocol} | <strong>Port:</strong> ${rule.destPort}</div>
        <div class="rule-description">${rule.description}</div>
      </div>
    </div>
  `).join('');
}

// ========== CONTROL FUNCTIONS ==========

function startSimulation() {
  if (state.running) return;
  
  state.running = true;
  state.startTime = Date.now();
  
  document.getElementById('startBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  document.getElementById('simStatus').textContent = 'Running';
  document.getElementById('simStatus').classList.remove('stopped');
  document.getElementById('simStatus').classList.add('running');
  
  // Start packet generation
  state.generationInterval = setInterval(() => {
    generatePackets();
  }, (1000 / state.speed));
  
  // Start runtime timer
  state.runtimeInterval = setInterval(updateRuntime, 1000);
  
  // Start packets per second counter
  state.ppsInterval = setInterval(updatePacketsPerSecond, 1000);
}

function stopSimulation() {
  if (!state.running) return;
  
  state.running = false;
  
  document.getElementById('startBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('simStatus').textContent = 'Stopped';
  document.getElementById('simStatus').classList.remove('running');
  document.getElementById('simStatus').classList.add('stopped');
  
  clearInterval(state.generationInterval);
  clearInterval(state.runtimeInterval);
  clearInterval(state.ppsInterval);
}

function resetStatistics() {
  state.stats = {
    total: 0,
    allowed: 0,
    dropped: 0,
    rejected: 0,
    tcp: 0,
    udp: 0,
    icmp: 0,
    blockedSources: {},
    allowedDestinations: {},
    processingTimes: []
  };
  
  updateStatsDisplay();
}

function clearLogs() {
  state.logs = [];
  updateActivityLog();
}

function updateRuntime() {
  if (!state.startTime) return;
  
  const elapsed = Math.floor((Date.now() - state.startTime) / 1000);
  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  
  document.getElementById('runtime').textContent = 
    `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function updatePacketsPerSecond() {
  if (!state.lastPacketCount) {
    state.lastPacketCount = state.stats.total;
    return;
  }
  
  const pps = state.stats.total - state.lastPacketCount;
  document.getElementById('packetsPerSec').textContent = pps;
  state.lastPacketCount = state.stats.total;
}

function exportLog() {
  if (state.logs.length === 0) {
    alert('No logs to export');
    return;
  }
  
  const headers = ['Timestamp', 'Action', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Protocol', 'Rule ID'];
  const rows = state.logs.map(log => {
    const parts = log.details.match(/(\d+\.\d+\.\d+\.\d+):(\d+) → (\d+\.\d+\.\d+\.\d+):(\d+) \[([A-Z]+)\]/);
    return [
      log.timestamp,
      log.action,
      parts[1],
      parts[2],
      parts[3],
      parts[4],
      parts[5],
      log.rule
    ];
  });
  
  const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `simushield-log-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function showAddRuleModal() {
  document.getElementById('addRuleModal').classList.add('active');
}

function closeAddRuleModal() {
  document.getElementById('addRuleModal').classList.remove('active');
  document.getElementById('ruleForm').reset();
}

function addRule(event) {
  event.preventDefault();
  
  const action = document.getElementById('ruleAction').value;
  const sourceIP = document.getElementById('ruleSourceIP').value.trim();
  const destIP = document.getElementById('ruleDestIP').value.trim();
  const protocol = document.getElementById('ruleProtocol').value;
  const destPort = document.getElementById('ruleDestPort').value.trim();
  const description = document.getElementById('ruleDescription').value.trim();
  
  const newRule = new FirewallRule(
    state.ruleIdCounter++,
    state.rules.length + 1,
    action,
    sourceIP,
    destIP,
    protocol,
    destPort,
    description
  );
  
  state.rules.push(newRule);
  displayRules();
  closeAddRuleModal();
}

// ========== EVENT LISTENERS ==========

document.addEventListener('DOMContentLoaded', () => {
  initializeDefaultRules();
  displayRules();
  updateStatsDisplay();
  updateActivityLog();
  
  document.getElementById('startBtn').addEventListener('click', startSimulation);
  document.getElementById('stopBtn').addEventListener('click', stopSimulation);
  document.getElementById('resetBtn').addEventListener('click', resetStatistics);
  document.getElementById('clearLogBtn').addEventListener('click', clearLogs);
  document.getElementById('exportLogBtn').addEventListener('click', exportLog);
  document.getElementById('addRuleBtn').addEventListener('click', showAddRuleModal);
  document.getElementById('closeModal').addEventListener('click', closeAddRuleModal);
  document.getElementById('cancelRuleBtn').addEventListener('click', closeAddRuleModal);
  document.getElementById('ruleForm').addEventListener('submit', addRule);
  
  document.getElementById('speedSlider').addEventListener('input', (e) => {
    state.speed = parseFloat(e.target.value);
    document.getElementById('speedValue').textContent = `${state.speed.toFixed(1)}x`;
    
    // Restart intervals if running
    if (state.running) {
      clearInterval(state.generationInterval);
      state.generationInterval = setInterval(() => {
        generatePackets();
      }, (1000 / state.speed));
    }
  });
  
  // Close modal on outside click
  document.getElementById('addRuleModal').addEventListener('click', (e) => {
    if (e.target.id === 'addRuleModal') {
      closeAddRuleModal();
    }
  });
});