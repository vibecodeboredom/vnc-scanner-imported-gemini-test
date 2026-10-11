import express, { Request, Response } from 'express';
import cors from 'cors';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Global process error handlers so socket drops or unhandled rejections never crash the server
process.on('uncaughtException', (err: any) => {
  console.error('Safely handled uncaughtException:', err?.message || err);
});
process.on('unhandledRejection', (reason: any) => {
  console.error('Safely handled unhandledRejection:', reason?.message || reason);
});

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ---------------------------------------------------------------------------
// DES (Data Encryption Standard) Pure-JS Implementation for VNC Authentication
// Guarantees compatibility across Node.js without relying on OpenSSL legacy provider
// ---------------------------------------------------------------------------
const IP_TABLE = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
];

const FP_TABLE = [
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25,
];

const PC1_TABLE = [
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4,
];

const PC2_TABLE = [
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
];

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const E_TABLE = [
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1,
];

const P_TABLE = [
  16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25,
];

const S_BOXES = [
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],
];

function permute(srcBits: number[], table: number[]): number[] {
  return table.map((pos) => srcBits[pos - 1]);
}

function bufferToBits(buf: Buffer): number[] {
  const bits: number[] = [];
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >> b) & 1);
    }
  }
  return bits;
}

function bitsToBuffer(bits: number[]): Buffer {
  const buf = Buffer.alloc(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = 7 - (i % 8);
    if (bits[i]) {
      buf[byteIndex] |= 1 << bitIndex;
    }
  }
  return buf;
}

function generateSubkeys(keyBits: number[]): number[][] {
  const pc1 = permute(keyBits, PC1_TABLE);
  let C = pc1.slice(0, 28);
  let D = pc1.slice(28, 56);
  const subkeys: number[][] = [];

  for (let round = 0; round < 16; round++) {
    const shift = SHIFTS[round];
    C = C.slice(shift).concat(C.slice(0, shift));
    D = D.slice(shift).concat(D.slice(0, shift));
    const CD = C.concat(D);
    subkeys.push(permute(CD, PC2_TABLE));
  }
  return subkeys;
}

function desBlockEncrypt(block8: Buffer, subkeys: number[][]): Buffer {
  const bits = permute(bufferToBits(block8), IP_TABLE);
  let L = bits.slice(0, 32);
  let R = bits.slice(32, 64);

  for (let round = 0; round < 16; round++) {
    const ER = permute(R, E_TABLE);
    const K = subkeys[round];
    const xorBits = ER.map((b, idx) => b ^ K[idx]);

    const sboxOut: number[] = [];
    for (let i = 0; i < 8; i++) {
      const chunk = xorBits.slice(i * 6, (i + 1) * 6);
      const row = (chunk[0] << 1) | chunk[5];
      const col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
      const val = S_BOXES[i][row][col];
      for (let b = 3; b >= 0; b--) {
        sboxOut.push((val >> b) & 1);
      }
    }

    const f = permute(sboxOut, P_TABLE);
    const nextR = L.map((b, idx) => b ^ f[idx]);
    L = R;
    R = nextR;
  }

  const preOutput = R.concat(L);
  const finalBits = permute(preOutput, FP_TABLE);
  return bitsToBuffer(finalBits);
}

function reverseBitsByte(b: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    if ((b >> i) & 1) r |= 1 << (7 - i);
  }
  return r;
}

function vncKey(password: string): Buffer {
  const raw = Buffer.alloc(8, 0);
  const passBuf = Buffer.from(password, 'latin1').subarray(0, 8);
  passBuf.copy(raw);
  const key = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    key[i] = reverseBitsByte(raw[i]);
  }
  return key;
}

function vncResponse(challenge: Buffer, password: string): Buffer {
  const key = vncKey(password);
  const subkeys = generateSubkeys(bufferToBits(key));
  const b1 = desBlockEncrypt(challenge.subarray(0, 8), subkeys);
  const b2 = desBlockEncrypt(challenge.subarray(8, 16), subkeys);
  return Buffer.concat([b1, b2]);
}

// ---------------------------------------------------------------------------
// RFB Scanner Types & Utilities
// ---------------------------------------------------------------------------
export interface ScanResult {
  ip: string;
  port: number;
  service: string;
  detected: boolean;
  url: string;
  proto: string | null;
  security: string | null; // "none" | "vncauth" | "unsupported" | null
  auth_success: boolean;
  winner: [string, string] | null;
  error: string | null;
  timestamp?: string;
}

const SEC_NONE = 1;
const SEC_VNCAUTH = 2;

// Target Parsing Logic (matches targets.py)
function ipToNum(ip: string): number {
  return (
    ip
      .split('.')
      .map(Number)
      .reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0
  );
}

function numToIp(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join('.');
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

// ---------------------------------------------------------------------------
// GlobalScan: Internet-Wide Public IPv4 Generator & RFC Filtering
// ---------------------------------------------------------------------------
// Non-routable / private / multicast / experimental IPv4 subnets that must be excluded
const RESERVED_IPV4_BLOCKS: { base: number; mask: number; cidr: string }[] = [
  '0.0.0.0/8', // Current network (RFC 1122)
  '10.0.0.0/8', // Private network (RFC 1918)
  '100.64.0.0/10', // Carrier-grade NAT (RFC 6598)
  '127.0.0.0/8', // Loopback (RFC 1122)
  '169.254.0.0/16', // Link-local (RFC 3927)
  '172.16.0.0/12', // Private network (RFC 1918)
  '192.0.0.0/24', // IETF Protocol Assignments (RFC 6890)
  '192.0.2.0/24', // TEST-NET-1 (RFC 5737)
  '192.88.99.0/24', // 6to4 Relay Anycast (RFC 7526)
  '192.168.0.0/16', // Private network (RFC 1918)
  '198.18.0.0/15', // Benchmarking (RFC 2544)
  '198.51.100.0/24', // TEST-NET-2 (RFC 5737)
  '203.0.113.0/24', // TEST-NET-3 (RFC 5737)
  '224.0.0.0/4', // Multicast (RFC 5771)
  '240.0.0.0/4', // Reserved / Future use (RFC 1112)
  '255.255.255.255/32', // Limited Broadcast (RFC 919)
].map((cidr) => {
  const [ip, bits] = cidr.split('/');
  const prefix = parseInt(bits, 10);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return {
    cidr,
    mask,
    base: (ipToNum(ip) & mask) >>> 0,
  };
});

export function isRoutablePublicIPv4(ipNum: number): boolean {
  for (const blk of RESERVED_IPV4_BLOCKS) {
    if ((ipNum & blk.mask) >>> 0 === blk.base) {
      return false;
    }
  }
  return true;
}

export interface GlobalScanRegion {
  id: string;
  name: string;
  flag: string;
  description: string;
  cidrs: string[];
}

export const GLOBAL_SCAN_REGIONS: Record<string, GlobalScanRegion> = {
  worldwide: {
    id: 'worldwide',
    name: 'Worldwide (Global IPv4)',
    flag: '🌐',
    description: 'Uniform random sampling across all global routable IPv4 public address space',
    cidrs: [],
  },
  'north-america': {
    id: 'north-america',
    name: 'North America (ARIN)',
    flag: '🇺🇸',
    description: 'Major North American broadband, cloud, and enterprise IPv4 allocations',
    cidrs: [
      '24.0.0.0/10',
      '64.0.0.0/10',
      '66.0.0.0/11',
      '72.0.0.0/9',
      '96.0.0.0/9',
      '108.0.0.0/10',
      '173.0.0.0/10',
      '184.0.0.0/10',
      '208.64.0.0/11',
    ],
  },
  europe: {
    id: 'europe',
    name: 'Europe (RIPE NCC)',
    flag: '🇪🇺',
    description: 'European ISP, enterprise, and cloud allocations across EU nations',
    cidrs: [
      '62.0.0.0/8',
      '80.0.0.0/8',
      '82.0.0.0/8',
      '84.0.0.0/8',
      '91.0.0.0/8',
      '178.0.0.0/8',
      '185.0.0.0/8',
      '195.0.0.0/8',
    ],
  },
  'asia-pacific': {
    id: 'asia-pacific',
    name: 'Asia-Pacific (APNIC)',
    flag: '🌏',
    description: 'Major Asia-Pacific ISP and data center routable blocks (JP, SG, AU, HK, etc.)',
    cidrs: [
      '58.0.0.0/8',
      '59.0.0.0/8',
      '60.0.0.0/8',
      '61.0.0.0/8',
      '110.0.0.0/8',
      '114.0.0.0/8',
      '118.0.0.0/8',
      '122.0.0.0/8',
      '125.0.0.0/8',
    ],
  },
  'latin-america': {
    id: 'latin-america',
    name: 'Latin America (LACNIC)',
    flag: '🌎',
    description: 'Broadband and hosting blocks across Latin America & Caribbean',
    cidrs: [
      '177.0.0.0/8',
      '179.0.0.0/8',
      '181.0.0.0/8',
      '186.0.0.0/8',
      '187.0.0.0/8',
      '189.0.0.0/8',
      '200.0.0.0/8',
      '201.0.0.0/8',
    ],
  },
  'cloud-datacenters': {
    id: 'cloud-datacenters',
    name: 'Cloud & Datacenters (High VNC Density)',
    flag: '☁️',
    description: 'Known hosting providers & VPS pools where remote desktop/VNC services run',
    cidrs: [
      '138.68.0.0/16',
      '159.203.0.0/16',
      '167.99.0.0/16',
      '142.93.0.0/16',
      '88.198.0.0/16',
      '144.76.0.0/16',
      '51.254.0.0/16',
      '178.32.0.0/16',
      '172.104.0.0/16',
      '139.162.0.0/16',
      '185.199.228.0/22',
      '198.199.64.0/18',
    ],
  },
};

export function generateGlobalTargets(count = 100, region = 'worldwide'): string[] {
  const safeCount = Math.max(1, Math.min(count, 5000));
  const seen = new Set<string>();
  const targets: string[] = [];
  const regConfig = GLOBAL_SCAN_REGIONS[region] || GLOBAL_SCAN_REGIONS['worldwide'];

  let attempts = 0;
  const maxAttempts = safeCount * 60;

  while (targets.length < safeCount && attempts < maxAttempts) {
    attempts++;
    let ipNum = 0;

    if (regConfig.id !== 'worldwide' && regConfig.cidrs.length > 0) {
      // Pick random CIDR from the region
      const chosenCidr = regConfig.cidrs[Math.floor(Math.random() * regConfig.cidrs.length)];
      const [baseIp, bitsStr] = chosenCidr.split('/');
      const bits = parseInt(bitsStr, 10);
      const baseNum = ipToNum(baseIp);
      const hostBits = 32 - bits;
      const hostCount = Math.pow(2, hostBits);
      // Generate random offset within the subnet
      const offset = 1 + Math.floor(Math.random() * Math.max(1, hostCount - 2));
      ipNum = (baseNum + offset) >>> 0;
    } else {
      // Worldwide: generate random 32-bit public IP (excluding multicast and 0.x)
      const octet1 = 1 + Math.floor(Math.random() * 223);
      const octet2 = Math.floor(Math.random() * 256);
      const octet3 = Math.floor(Math.random() * 256);
      const octet4 = 1 + Math.floor(Math.random() * 254);
      ipNum = ((octet1 << 24) | (octet2 << 16) | (octet3 << 8) | octet4) >>> 0;
    }

    if (isRoutablePublicIPv4(ipNum)) {
      const ipStr = numToIp(ipNum);
      if (!seen.has(ipStr)) {
        seen.add(ipStr);
        targets.push(ipStr);
      }
    }
  }

  return targets;
}

export function expandTarget(spec: string): string[] {
  spec = spec.trim();
  if (!spec || spec.startsWith('#')) return [];

  // GlobalScan keyword support (e.g. global, globalscan, global:100, global:europe:50, GLOBAL_SCAN_WORLDWIDE)
  const sLower = spec.toLowerCase();
  if (sLower.startsWith('global')) {
    if (spec === 'GLOBAL_SCAN_CLOUDVPS') {
      return generateGlobalTargets(100, 'cloud-datacenters');
    }
    if (spec === 'GLOBAL_SCAN_WORLDWIDE') {
      return generateGlobalTargets(100, 'worldwide');
    }
    const parts = sLower.split(':');
    let region = 'worldwide';
    let count = 50;
    if (parts.length === 2) {
      const num = parseInt(parts[1], 10);
      if (!isNaN(num)) count = num;
      else if (GLOBAL_SCAN_REGIONS[parts[1]]) region = parts[1];
    } else if (parts.length >= 3) {
      if (GLOBAL_SCAN_REGIONS[parts[1]]) region = parts[1];
      const num = parseInt(parts[2], 10);
      if (!isNaN(num)) count = num;
    }
    return generateGlobalTargets(count, region);
  }

  // CIDR notation: 192.168.1.0/24
  if (spec.includes('/')) {
    const [ip, cidrStr] = spec.split('/');
    if (!isValidIPv4(ip)) return [];
    const cidr = parseInt(cidrStr, 10);
    if (isNaN(cidr) || cidr < 0 || cidr > 32) return [];

    const baseNum = ipToNum(ip);
    const mask = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
    const netNum = (baseNum & mask) >>> 0;
    const numHosts = Math.pow(2, 32 - cidr);

    if (cidr >= 31) {
      const res: string[] = [];
      for (let i = 0; i < numHosts; i++) {
        res.push(numToIp(netNum + i));
      }
      return res;
    }

    // Standard usable host range (exclude network & broadcast)
    const hosts: string[] = [];
    const maxScanLimit = 1024; // Safeguard against accidental /8 inputs
    const limit = Math.min(numHosts - 2, maxScanLimit);
    for (let i = 1; i <= limit; i++) {
      hosts.push(numToIp(netNum + i));
    }
    return hosts;
  }

  // Range notation: 10.0.0.1-50 or 192.168.1.10-192.168.1.20
  if (spec.includes('-')) {
    const [startStr, endStr] = spec.split('-').map((s) => s.trim());
    if (!isValidIPv4(startStr)) return [];

    let fullEndStr = endStr;
    if (!endStr.includes('.')) {
      const parts = startStr.split('.');
      parts[3] = endStr;
      fullEndStr = parts.join('.');
    }
    if (!isValidIPv4(fullEndStr)) return [];

    let startNum = ipToNum(startStr);
    let endNum = ipToNum(fullEndStr);
    if (endNum < startNum) {
      [startNum, endNum] = [endNum, startNum];
    }
    const maxRange = 1024;
    const count = Math.min(endNum - startNum + 1, maxRange);
    const list: string[] = [];
    for (let i = 0; i < count; i++) {
      list.push(numToIp(startNum + i));
    }
    return list;
  }

  if (isValidIPv4(spec)) {
    return [spec];
  }

  // Support hostnames, domains, localhost, or single entries
  const cleanHost = spec.replace(/^(vnc|rfb|tcp|http|https):\/\//i, '').trim();
  if (cleanHost.toLowerCase() === 'localhost') {
    return ['127.0.0.1'];
  }
  // If entry contains explicit port like host:5900, strip the port for expandTarget (ports handled by parseTargetLine)
  const hpMatch = cleanHost.match(/^([^:]+):(\d+)$/);
  if (hpMatch) {
    const h = hpMatch[1].trim();
    if (h.toLowerCase() === 'localhost') return ['127.0.0.1'];
    return [h];
  }
  if (/^[a-zA-Z0-9.-]+$/.test(cleanHost)) {
    return [cleanHost];
  }

  return [];
}

export function parseTargetLine(line: string, defaultPorts: number[]): { host: string; ports: number[] }[] {
  let clean = line.trim();
  if (!clean || clean.startsWith('#')) return [];

  clean = clean.replace(/^(vnc|rfb|tcp|http|https):\/\//i, '').trim();

  let explicitPort: number | null = null;
  const hostPortMatch = clean.match(/^([^:\/\s]+):(\d+)$/);
  if (hostPortMatch) {
    clean = hostPortMatch[1].trim();
    const p = parseInt(hostPortMatch[2], 10);
    if (!isNaN(p) && p >= 1 && p <= 65535) {
      explicitPort = p;
    }
  }

  const hosts = expandTarget(clean);
  const portsToUse = explicitPort !== null ? [explicitPort] : defaultPorts;

  return hosts.map((host) => ({
    host,
    ports: portsToUse,
  }));
}

export interface PortInfo {
  port: number;
  display: string;
}

export const DEFAULT_COMMON_VNC_PORTS_STR = '5900, 5901, 5902, 5903, 5904, 5905, 5800, 5801';
export const DEFAULT_COMMON_VNC_PORTS_LIST = [5900, 5901, 5902, 5903, 5904, 5905, 5800, 5801];

export function parsePorts(spec: string): number[] {
  const ports: number[] = [];
  const seen = new Set<number>();
  if (!spec || !spec.trim()) return [...DEFAULT_COMMON_VNC_PORTS_LIST];

  // Comma is used to separate numbers and skip numbers (e.g. "5900, 5902, 5905" or ":0, :2, :5")
  const chunks = spec.split(',').map((s) => s.trim()).filter(Boolean);

  for (const chunk of chunks) {
    if (chunk.includes('-')) {
      const [loPart, hiPart] = chunk.split('-').map((s) => s.trim().replace(/^:/, ''));
      let lo = parseInt(loPart, 10);
      let hi = parseInt(hiPart, 10);
      if (isNaN(lo) || isNaN(hi)) continue;

      // If user entered display numbers like 0-3 (or :0-:3), map to 5900-5903
      if (lo < 100 && hi < 100) {
        lo += 5900;
        hi += 5900;
      }

      if (hi < lo) [lo, hi] = [hi, lo];
      lo = Math.max(1, lo);
      hi = Math.min(65535, hi);

      for (let p = lo; p <= hi; p++) {
        if (!seen.has(p)) {
          seen.add(p);
          ports.push(p);
        }
      }
    } else {
      const clean = chunk.replace(/^:/, '');
      let p = parseInt(clean, 10);
      if (isNaN(p)) continue;

      // If user entered display number like 0, 1, 2, 5 (or :0, :2, :5), map to 5900+
      if (p < 100) {
        p += 5900;
      }

      if (p >= 1 && p <= 65535 && !seen.has(p)) {
        seen.add(p);
        ports.push(p);
      }
    }
  }

  return ports.length > 0 ? ports : [...DEFAULT_COMMON_VNC_PORTS_LIST];
}

export function getPortDetails(ports: number[]): PortInfo[] {
  return ports.map((p) => {
    let display = '';
    if (p >= 5900 && p <= 5999) {
      display = `:${p - 5900}`;
    } else if (p >= 5800 && p <= 5899) {
      display = `HTTP :${p - 5800}`;
    }
    return { port: p, display };
  });
}

// ---------------------------------------------------------------------------
// Proxy Support: SOCKS5, HTTP CONNECT, SOCKS4
// ---------------------------------------------------------------------------
export interface ProxyConfig {
  enabled: boolean;
  type: 'socks5' | 'http' | 'socks4';
  host: string;
  port: number;
  auth?: { username: string; password?: string };
  rawUrl?: string;
}

export function parseProxyString(proxyStr: string, defaultType: 'socks5' | 'http' | 'socks4' = 'socks5'): ProxyConfig | null {
  if (!proxyStr || typeof proxyStr !== 'string') return null;
  let s = proxyStr.trim();
  if (!s || s.startsWith('#')) return null;

  // Strip quotes and whitespace
  s = s.replace(/^["']|["']$/g, '').trim();

  let type: 'socks5' | 'http' | 'socks4' = defaultType;

  if (s.startsWith('socks5://') || s.startsWith('socks://')) {
    type = 'socks5';
  } else if (s.startsWith('http://') || s.startsWith('https://')) {
    type = 'http';
  } else if (s.startsWith('socks4://') || s.startsWith('socks4a://')) {
    type = 'socks4';
  }

  // Handle standard "ip:port:user:pass" format (very common in proxy exports)
  if (!s.includes('://')) {
    const parts = s.split(':');
    if (parts.length === 4) {
      const host = parts[0].trim();
      const port = Number(parts[1].trim());
      const username = parts[2].trim();
      const password = parts[3].trim();
      if (host && !isNaN(port) && port > 0 && port <= 65535) {
        return {
          enabled: true,
          type,
          host,
          port,
          auth: { username, password },
          rawUrl: s,
        };
      }
    } else if (parts.length === 2) {
      const host = parts[0].trim();
      const port = Number(parts[1].trim());
      if (host && !isNaN(port) && port > 0 && port <= 65535) {
        return {
          enabled: true,
          type,
          host,
          port,
          auth: undefined,
          rawUrl: s,
        };
      }
    }
  }

  if (!s.includes('://')) {
    s = `${defaultType}://${s}`;
  }

  try {
    const url = new URL(s);
    const host = url.hostname;
    const port = Number(url.port) || (type === 'http' ? 8080 : 1080);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return null;

    let auth: { username: string; password?: string } | undefined = undefined;
    if (url.username) {
      auth = {
        username: decodeURIComponent(url.username),
        password: url.password ? decodeURIComponent(url.password) : '',
      };
    }

    return {
      enabled: true,
      type,
      host,
      port,
      auth,
      rawUrl: proxyStr.trim(),
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// SOCKS5 Error Handling & RFC 1928 Status Code Decoder
// ---------------------------------------------------------------------------
export class Socks5ConnectError extends Error {
  public readonly code: string;
  public readonly socksCode: number;
  public readonly isTargetClosed: boolean;
  public readonly isTargetUnreachable: boolean;
  public readonly isProxyPolicy: boolean;
  public readonly isProxyFailure: boolean;

  constructor(socksCode: number, targetHost: string, targetPort: number) {
    const codeMap: Record<number, { name: string; desc: string; sysCode: string }> = {
      0x01: {
        name: 'General SOCKS server failure',
        desc: 'Proxy upstream connection failure or timeout',
        sysCode: 'ECONNRESET',
      },
      0x02: {
        name: 'Connection not allowed by ruleset',
        desc: `Proxy firewall/ACL policy denied connection to port ${targetPort}`,
        sysCode: 'EACCES',
      },
      0x03: {
        name: 'Network unreachable',
        desc: 'Destination network is unreachable through proxy',
        sysCode: 'ENETUNREACH',
      },
      0x04: {
        name: 'Host unreachable',
        desc: `Target host ${targetHost} is unreachable or offline`,
        sysCode: 'EHOSTUNREACH',
      },
      0x05: {
        name: 'Connection refused',
        desc: `Target host actively refused connection on port ${targetPort} (port closed)`,
        sysCode: 'ECONNREFUSED',
      },
      0x06: {
        name: 'TTL expired',
        desc: 'Packet TTL expired before reaching destination',
        sysCode: 'ETIMEDOUT',
      },
      0x07: {
        name: 'Command not supported',
        desc: 'Proxy does not support SOCKS5 CONNECT command',
        sysCode: 'ENOTSUP',
      },
      0x08: {
        name: 'Address type not supported',
        desc: 'Proxy does not support requested address format',
        sysCode: 'EAFNOSUPPORT',
      },
    };

    const info = codeMap[socksCode] || {
      name: `SOCKS error 0x${socksCode.toString(16)}`,
      desc: `SOCKS5 reply status code ${socksCode}`,
      sysCode: 'ECONNREFUSED',
    };

    super(`SOCKS5 CONNECT failed with status code ${socksCode}: ${info.name} (${info.desc})`);
    this.name = 'Socks5ConnectError';
    this.socksCode = socksCode;
    this.code = info.sysCode;
    this.isTargetClosed = socksCode === 0x05;
    this.isTargetUnreachable = socksCode === 0x03 || socksCode === 0x04 || socksCode === 0x06;
    this.isProxyPolicy = socksCode === 0x02;
    this.isProxyFailure = socksCode === 0x01 || socksCode === 0x07 || socksCode === 0x08;
  }
}

function createProxiedSocket(
  targetIp: string,
  targetPort: number,
  timeoutMs: number,
  proxy?: ProxyConfig | null
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let isSettled = false;

    // Primary setup error handler
    const onSetupError = (err: any) => {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      socket.off('error', onSetupError);
      socket.on('error', () => {}); // Catch subsequent errors so Node never crashes
      socket.destroy();
      reject(err);
    };

    // Attach immediate error handler
    socket.on('error', onSetupError);

    // Timeout timer: reject with Timeout Error and safely destroy socket WITHOUT passing error to socket.destroy()
    const timer = setTimeout(() => {
      if (isSettled) return;
      isSettled = true;
      socket.off('error', onSetupError);
      socket.on('error', () => {}); // Catch subsequent errors
      socket.destroy();
      reject(new Error(`Connection to ${targetIp}:${targetPort} timed out (${timeoutMs}ms)`));
    }, timeoutMs);

    function finishSuccess(sock: net.Socket) {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      sock.off('error', onSetupError);
      // Crucial: keep a noop error listener so any sudden remote disconnect/RST
      // while idle or during subsequent reads never emits unhandled 'error'
      sock.on('error', () => {});
      resolve(sock);
    }

    function finishFailure(err: any) {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      socket.off('error', onSetupError);
      socket.on('error', () => {});
      socket.destroy();
      reject(err);
    }

    // Direct connection if no proxy
    if (!proxy || !proxy.enabled || !proxy.host) {
      socket.connect(targetPort, targetIp, () => {
        finishSuccess(socket);
      });
      return;
    }

    // Connect via Proxy
    socket.connect(proxy.port, proxy.host, async () => {
      try {
        if (proxy.type === 'socks5') {
          // SOCKS5 greeting
          const hasAuth = !!proxy.auth?.username;
          const greeting = hasAuth
            ? Buffer.from([0x05, 0x02, 0x00, 0x02]) // SOCKS5, 2 methods: 0 (No Auth), 2 (Username/Pass)
            : Buffer.from([0x05, 0x01, 0x00]); // SOCKS5, 1 method: 0 (No Auth)

          socket.write(greeting);
          const methodBuf = await recvExact(socket, 2, timeoutMs);
          if (methodBuf[0] !== 0x05) {
            throw new Error(`Invalid SOCKS5 version reply from proxy (expected 0x05, got 0x${methodBuf[0].toString(16)})`);
          }

          const chosenMethod = methodBuf[1];
          if (chosenMethod === 0x02) {
            // Username / Password authentication
            const u = Buffer.from(proxy.auth?.username || '', 'utf-8');
            const p = Buffer.from(proxy.auth?.password || '', 'utf-8');
            const authPayload = Buffer.concat([
              Buffer.from([0x01, u.length]),
              u,
              Buffer.from([p.length]),
              p,
            ]);
            socket.write(authPayload);
            const authReply = await recvExact(socket, 2, timeoutMs);
            if (authReply[1] !== 0x00) {
              throw new Error('SOCKS5 proxy authentication failed');
            }
          } else if (chosenMethod !== 0x00) {
            throw new Error(`SOCKS5 proxy rejected authentication method (${chosenMethod})`);
          }

          // SOCKS5 Connect Request
          // Command 0x01 (CONNECT), RSV 0x00
          let addrBuf: Buffer;
          const cleanTarget = targetIp.trim();
          if (isValidIPv4(cleanTarget)) {
            const octets = cleanTarget.split('.').map((x) => parseInt(x, 10));
            addrBuf = Buffer.from([0x01, octets[0], octets[1], octets[2], octets[3]]);
          } else {
            const hostBuf = Buffer.from(cleanTarget, 'utf-8');
            addrBuf = Buffer.concat([Buffer.from([0x03, hostBuf.length]), hostBuf]);
          }

          const portBuf = Buffer.alloc(2);
          portBuf.writeUInt16BE(targetPort, 0);

          const reqBuf = Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addrBuf, portBuf]);
          socket.write(reqBuf);

          // Read response
          const head = await recvExact(socket, 4, timeoutMs);
          if (head[0] !== 0x05) {
            throw new Error(`Invalid SOCKS5 reply from proxy (expected 0x05, got 0x${head[0].toString(16)})`);
          }

          if (head[1] !== 0x00) {
            const statusCode = head[1];
            // Consume remaining bound address and port bytes so socket buffers drain
            try {
              const atyp = head[3];
              if (atyp === 0x01) {
                await recvExact(socket, 4 + 2, 500);
              } else if (atyp === 0x03) {
                const lenBuf = await recvExact(socket, 1, 500);
                await recvExact(socket, lenBuf[0] + 2, 500);
              } else if (atyp === 0x04) {
                await recvExact(socket, 16 + 2, 500);
              }
            } catch {
              // Ignore drain errors
            }
            throw new Socks5ConnectError(statusCode, cleanTarget, targetPort);
          }

          // Consume bound address and port
          const atyp = head[3];
          if (atyp === 0x01) {
            await recvExact(socket, 4 + 2, timeoutMs); // 4 bytes IPv4 + 2 bytes port
          } else if (atyp === 0x03) {
            const lenBuf = await recvExact(socket, 1, timeoutMs);
            await recvExact(socket, lenBuf[0] + 2, timeoutMs);
          } else if (atyp === 0x04) {
            await recvExact(socket, 16 + 2, timeoutMs); // IPv6
          }

          finishSuccess(socket);
        } else if (proxy.type === 'http') {
          // HTTP CONNECT Tunneling
          let connectReq = `CONNECT ${targetIp}:${targetPort} HTTP/1.1\r\nHost: ${targetIp}:${targetPort}\r\n`;
          if (proxy.auth?.username) {
            const basic = Buffer.from(`${proxy.auth.username}:${proxy.auth.password || ''}`).toString('base64');
            connectReq += `Proxy-Authorization: Basic ${basic}\r\n`;
          }
          connectReq += `\r\n`;
          socket.write(connectReq);

          // Read response until \r\n\r\n
          let respBuf = Buffer.alloc(0);
          while (!respBuf.includes('\r\n\r\n')) {
            const chunk = await recvExact(socket, 1, timeoutMs);
            respBuf = Buffer.concat([respBuf, chunk]);
            if (respBuf.length > 2048) {
              throw new Error('HTTP proxy response too large');
            }
          }

          const respStr = respBuf.toString('utf-8');
          if (!respStr.startsWith('HTTP/1.0 200') && !respStr.startsWith('HTTP/1.1 200')) {
            const statusLine = respStr.split('\r\n')[0];
            throw new Error(`HTTP CONNECT proxy error: ${statusLine}`);
          }

          finishSuccess(socket);
        } else if (proxy.type === 'socks4') {
          // SOCKS4 Connect
          const octets = isValidIPv4(targetIp) ? targetIp.split('.').map(Number) : [0, 0, 0, 1];
          const portBuf = Buffer.alloc(2);
          portBuf.writeUInt16BE(targetPort, 0);

          const req = Buffer.from([
            0x04,
            0x01,
            portBuf[0],
            portBuf[1],
            octets[0],
            octets[1],
            octets[2],
            octets[3],
            0x00,
          ]);
          socket.write(req);

          const rep = await recvExact(socket, 8, timeoutMs);
          if (rep[1] !== 0x5a) {
            throw new Error(`SOCKS4 proxy request rejected (code ${rep[1]})`);
          }

          finishSuccess(socket);
        }
      } catch (err) {
        finishFailure(err);
      }
    });
  });
}


// ---------------------------------------------------------------------------
// Real RFB Socket Protocol Engine
// ---------------------------------------------------------------------------
function recvExact(
  socket: net.Socket & { _rxBuf?: Buffer },
  n: number,
  timeoutMs: number
): Promise<Buffer> {
  const existing = socket._rxBuf || Buffer.alloc(0);
  if (existing.length >= n) {
    const res = existing.subarray(0, n);
    socket._rxBuf = existing.subarray(n);
    return Promise.resolve(res);
  }

  return new Promise((resolve, reject) => {
    let isSettled = false;

    function cleanup() {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('close', onClose);
      socket.off('error', onError);
      // Ensure socket retains a safety error listener so unhandled error is never emitted
      socket.on('error', () => {});
    }

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timeout reading from RFB socket'));
    }, timeoutMs);

    function onData(chunk: Buffer) {
      socket._rxBuf = Buffer.concat([socket._rxBuf || Buffer.alloc(0), chunk]);
      if (socket._rxBuf.length >= n) {
        cleanup();
        const ret = socket._rxBuf.subarray(0, n);
        socket._rxBuf = socket._rxBuf.subarray(n);
        resolve(ret);
      }
    }

    function onClose() {
      cleanup();
      reject(new Error('connection closed mid-handshake'));
    }

    function onError(err: Error) {
      cleanup();
      reject(err);
    }

    socket.on('data', onData);
    socket.on('close', onClose);
    socket.on('error', onError);
  });
}

async function recvRfbBanner(
  socket: net.Socket,
  timeoutMs: number
): Promise<{ raw: string; major: number; minor: number }> {
  let lineBuf = Buffer.alloc(0);
  while (!lineBuf.includes(0x0a)) {
    const chunk = await recvExact(socket, 1, timeoutMs);
    lineBuf = Buffer.concat([lineBuf, chunk]);
    if (lineBuf.length > 64) {
      throw new Error('RFB banner exceeded maximum length');
    }
  }
  const bannerStr = lineBuf.toString('latin1').replace(/\r?\n$/, '');
  const match = bannerStr.match(/RFB\s+(\d{3})\.(\d{3})/i);
  if (!match) {
    throw new Error(`malformed RFB version banner: ${bannerStr}`);
  }
  return {
    raw: bannerStr,
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
  };
}

async function probeRFB(
  ip: string,
  port: number,
  timeoutMs: number,
  proxy?: ProxyConfig | null
): Promise<{ version: [number, number]; securityTypes: number[] }> {
  const socket = await createProxiedSocket(ip, port, timeoutMs, proxy);
  try {
    const bannerInfo = await recvRfbBanner(socket, timeoutMs);
    const serverMajor = bannerInfo.major;
    const serverMinor = bannerInfo.minor;
    const serverVersion: [number, number] = [serverMajor, serverMinor];

    // Negotiate highest compatible version
    let ourBanner = 'RFB 003.008\n';
    if (serverMajor === 3 && serverMinor < 7) {
      ourBanner = 'RFB 003.003\n';
    } else if (serverMajor === 3 && serverMinor === 7) {
      ourBanner = 'RFB 003.007\n';
    }
    socket.write(ourBanner);

    let types: number[] = [];
    if (serverMajor > 3 || (serverMajor === 3 && serverMinor >= 7)) {
      // Read 1 byte count
      const countBuf = await recvExact(socket, 1, timeoutMs);
      const count = countBuf[0];
      if (count === 0) {
        socket.destroy();
        throw new Error('server offered no security types');
      }
      const typesBuf = await recvExact(socket, count, timeoutMs);
      types = Array.from(typesBuf);
    } else {
      // RFB 3.3: single uint32BE
      const typeBuf = await recvExact(socket, 4, timeoutMs);
      const singleType = typeBuf.readUInt32BE(0);
      if (singleType === 0) {
        socket.destroy();
        throw new Error('server rejected connection');
      }
      types = [singleType];
    }

    socket.destroy();
    return { version: serverVersion, securityTypes: types };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

async function tryVncAuth(
  ip: string,
  port: number,
  password: string,
  timeoutMs: number,
  proxy?: ProxyConfig | null
): Promise<boolean> {
  const socket = await createProxiedSocket(ip, port, timeoutMs, proxy);
  try {
    const bannerInfo = await recvRfbBanner(socket, timeoutMs);
    const serverMajor = bannerInfo.major;
    const serverMinor = bannerInfo.minor;

    let ourBanner = 'RFB 003.008\n';
    if (serverMajor === 3 && serverMinor < 7) {
      ourBanner = 'RFB 003.003\n';
    } else if (serverMajor === 3 && serverMinor === 7) {
      ourBanner = 'RFB 003.007\n';
    }
    socket.write(ourBanner);

    let supportsVncAuth = false;
    if (serverMajor > 3 || (serverMajor === 3 && serverMinor >= 7)) {
      const countBuf = await recvExact(socket, 1, timeoutMs);
      const count = countBuf[0];
      const typesBuf = await recvExact(socket, count, timeoutMs);
      const types = Array.from(typesBuf);
      if (!types.includes(SEC_VNCAUTH)) {
        socket.destroy();
        return false;
      }
      // Client picks SEC_VNCAUTH (2)
      socket.write(Buffer.from([SEC_VNCAUTH]));
      supportsVncAuth = true;
    } else {
      const typeBuf = await recvExact(socket, 4, timeoutMs);
      const secType = typeBuf.readUInt32BE(0);
      if (secType !== SEC_VNCAUTH) {
        socket.destroy();
        return resolveFalse(socket);
      }
      supportsVncAuth = true;
    }

    if (!supportsVncAuth) {
      socket.destroy();
      return false;
    }

    // Receive 16-byte challenge
    const challenge = await recvExact(socket, 16, timeoutMs);
    const response = vncResponse(challenge, password);
    socket.write(response);

    // SecurityResult (uint32BE, 0 = OK)
    const resultBuf = await recvExact(socket, 4, timeoutMs);
    const resultCode = resultBuf.readUInt32BE(0);

    socket.destroy();
    return resultCode === 0;
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

function resolveFalse(socket: net.Socket): boolean {
  socket.destroy();
  return false;
}

// ---------------------------------------------------------------------------
// Simulated / Local Mock VNC Responders for instant zero-dependency testing
// ---------------------------------------------------------------------------
// We set up internal virtual VNC responders on 127.0.0.1:5900..5903
const virtualVncServices: Record<
  number,
  { type: 'none' | 'vncauth'; password?: string; version: string }
> = {
  5900: { type: 'none', version: '3.8' },
  5901: { type: 'vncauth', password: 'password', version: '3.8' },
  5902: { type: 'vncauth', password: 'admin', version: '3.8' },
  5903: { type: 'vncauth', password: 'secretpassword', version: '3.8' },
};

function setupVirtualVncServer(port: number, config: (typeof virtualVncServices)[number]) {
  const server = net.createServer((sock) => {
    sock.write('RFB 003.008\n');

    let state = 'handshake';
    let challenge = crypto.randomBytes(16);

    sock.on('data', (data) => {
      if (state === 'handshake') {
        state = 'sectypes';
        if (config.type === 'none') {
          // Send 1 security type: 1 (None)
          sock.write(Buffer.from([1, 1]));
        } else {
          // Send 1 security type: 2 (VncAuth)
          sock.write(Buffer.from([1, 2]));
        }
      } else if (state === 'sectypes') {
        const chosen = data[0];
        if (chosen === 1) {
          // None: OK
          sock.write(Buffer.from([0, 0, 0, 0]));
        } else if (chosen === 2) {
          state = 'auth';
          challenge = crypto.randomBytes(16);
          sock.write(challenge);
        }
      } else if (state === 'auth') {
        // Data is 16-byte response
        const expected = vncResponse(challenge, config.password || '');
        if (data.subarray(0, 16).equals(expected)) {
          sock.write(Buffer.from([0, 0, 0, 0])); // OK
        } else {
          sock.write(Buffer.from([0, 0, 0, 1])); // Failed
        }
      }
    });
  });

  server.on('error', () => {
    // Port might be in use or restricted, continue gracefully
  });

  try {
    server.listen(port, '127.0.0.1');
  } catch {
    // ignore
  }
}

// Spin up virtual test servers on 5900-5903 on localhost
try {
  setupVirtualVncServer(5900, virtualVncServices[5900]);
  setupVirtualVncServer(5901, virtualVncServices[5901]);
  setupVirtualVncServer(5902, virtualVncServices[5902]);
  setupVirtualVncServer(5903, virtualVncServices[5903]);
} catch (e) {
  console.log('Virtual VNC responder initialization note:', e);
}

// ---------------------------------------------------------------------------
// Virtual Test SOCKS5 and HTTP Proxies for zero-dependency local testing
// ---------------------------------------------------------------------------
function setupVirtualSocks5Proxy(port: number) {
  const server = net.createServer((client) => {
    let state = 'greeting';
    let targetSocket: net.Socket | null = null;

    client.on('error', () => {
      if (targetSocket) targetSocket.destroy();
    });

    client.on('data', (data) => {
      try {
        if (state === 'greeting') {
          if (data[0] !== 0x05) {
            client.destroy();
            return;
          }
          // Accept "No Authentication" (0x00)
          client.write(Buffer.from([0x05, 0x00]));
          state = 'request';
        } else if (state === 'request') {
          if (data[0] !== 0x05 || data[1] !== 0x01) {
            client.destroy();
            return;
          }
          const atyp = data[3];
          let targetHost = '';
          let targetPort = 0;
          let offset = 4;

          if (atyp === 0x01) {
            // IPv4
            targetHost = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
            offset += 4;
          } else if (atyp === 0x03) {
            // Domain name
            const len = data[offset++];
            targetHost = data.subarray(offset, offset + len).toString('utf-8');
            offset += len;
          } else {
            client.destroy();
            return;
          }

          targetPort = data.readUInt16BE(offset);

          targetSocket = net.connect(targetPort, targetHost, () => {
            // SOCKS5 success reply
            client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));
            state = 'pipe';
            client.pipe(targetSocket!);
            targetSocket!.pipe(client);
          });

          targetSocket.on('error', () => {
            try {
              client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            } catch {
              // ignore
            }
            client.destroy();
          });
        }
      } catch {
        client.destroy();
      }
    });
  });

  server.on('error', () => {
    // Port may already be in use
  });

  try {
    server.listen(port, '127.0.0.1');
  } catch {
    // ignore
  }
}

function setupVirtualHttpProxy(port: number) {
  const server = net.createServer((client) => {
    let targetSocket: net.Socket | null = null;

    client.once('data', (data) => {
      try {
        const req = data.toString('utf-8');
        if (req.startsWith('CONNECT ')) {
          const firstLine = req.split('\r\n')[0] || '';
          const target = firstLine.split(' ')[1] || '';
          const parts = target.split(':');
          const host = parts[0] || '127.0.0.1';
          const targetPort = parseInt(parts[1] || '80', 10);

          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');

          targetSocket = net.connect(targetPort, host, () => {
            client.pipe(targetSocket!);
            targetSocket!.pipe(client);
          });

          targetSocket.on('error', () => {
            client.destroy();
          });
        } else {
          client.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nProxy Active\r\n');
          client.destroy();
        }
      } catch {
        client.destroy();
      }
    });

    client.on('error', () => {
      if (targetSocket) targetSocket.destroy();
    });
  });

  server.on('error', () => {
    // Port may already be in use
  });

  try {
    server.listen(port, '127.0.0.1');
  } catch {
    // ignore
  }
}

// Spin up local virtual proxies on 127.0.0.1:1080 (SOCKS5) and 127.0.0.1:8080 (HTTP)
try {
  setupVirtualSocks5Proxy(1080);
  setupVirtualHttpProxy(8080);
} catch (e) {
  console.log('Virtual proxy listener initialization note:', e);
}

// ---------------------------------------------------------------------------
// Dedicated Proxy Verifier with Protocol Diagnostics
// ---------------------------------------------------------------------------
export async function verifyProxyConnection(
  proxy: ProxyConfig,
  timeoutMs: number,
  targetHost?: string,
  targetPort?: number
): Promise<{
  alive: boolean;
  latencyMs: number;
  protocol: 'socks5' | 'http' | 'socks4';
  details?: string;
  error?: string;
}> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isFinished = false;
    const startTime = Date.now();

    const timer = setTimeout(() => {
      finish(false, `Connection timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    function finish(alive: boolean, message?: string, details?: string) {
      if (isFinished) return;
      isFinished = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.on('error', () => {}); // Catch subsequent errors so Node never throws unhandled 'error'
      socket.destroy();
      const latencyMs = Date.now() - startTime;
      resolve({
        alive,
        latencyMs,
        protocol: proxy.type,
        details: alive ? details || message : undefined,
        error: !alive ? message : undefined,
      });
    }

    socket.on('close', () => {
      finish(false, 'Connection closed by remote proxy before response');
    });

    socket.on('error', (err: any) => {
      const code = err.code || err.message;
      if (code === 'ECONNREFUSED') {
        finish(false, `Connection refused: No service listening on ${proxy.host}:${proxy.port}`);
      } else if (code === 'ENOTFOUND') {
        finish(false, `Host not found (DNS lookup failed for ${proxy.host})`);
      } else if (code === 'ETIMEDOUT') {
        finish(false, `Connection timed out to ${proxy.host}:${proxy.port}`);
      } else {
        finish(false, err.message || 'Socket error');
      }
    });

    socket.connect(proxy.port, proxy.host, async () => {
      try {
        if (proxy.type === 'socks5') {
          // SOCKS5 Greeting
          const hasAuth = !!proxy.auth?.username;
          const greeting = hasAuth
            ? Buffer.from([0x05, 0x02, 0x00, 0x02])
            : Buffer.from([0x05, 0x01, 0x00]);

          socket.write(greeting);
          const methodBuf = await recvExact(socket, 2, timeoutMs);
          if (methodBuf[0] !== 0x05) {
            return finish(false, `Invalid SOCKS5 version reply (received 0x${methodBuf[0].toString(16)})`);
          }

          const method = methodBuf[1];
          if (method === 0xff) {
            return finish(false, 'Proxy rejected authentication methods (0xFF)');
          }

          if (method === 0x02) {
            // Password subnegotiation
            const u = Buffer.from(proxy.auth?.username || '', 'utf-8');
            const p = Buffer.from(proxy.auth?.password || '', 'utf-8');
            const authPayload = Buffer.concat([
              Buffer.from([0x01, u.length]),
              u,
              Buffer.from([p.length]),
              p,
            ]);
            socket.write(authPayload);
            const authReply = await recvExact(socket, 2, timeoutMs);
            if (authReply[1] !== 0x00) {
              return finish(false, 'SOCKS5 username/password authentication failed');
            }
          }

          // At this point, SOCKS5 Handshake is 100% verified alive!
          // Now attempt CONNECT probe:
          const isLocal = proxy.host === '127.0.0.1' || proxy.host === 'localhost';
          const tHost = targetHost || (isLocal ? '127.0.0.1' : '1.1.1.1');
          const tPort = targetPort || (isLocal ? 5900 : 80);

          let addrBuf: Buffer;
          if (isValidIPv4(tHost)) {
            const octets = tHost.split('.').map(Number);
            addrBuf = Buffer.from([0x01, octets[0], octets[1], octets[2], octets[3]]);
          } else {
            const hostBuf = Buffer.from(tHost, 'utf-8');
            addrBuf = Buffer.concat([Buffer.from([0x03, hostBuf.length]), hostBuf]);
          }

          const portBuf = Buffer.alloc(2);
          portBuf.writeUInt16BE(tPort, 0);

          const reqBuf = Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addrBuf, portBuf]);
          socket.write(reqBuf);

          const head = await recvExact(socket, 4, timeoutMs);
          if (head[0] !== 0x05) {
            return finish(false, `Invalid SOCKS5 version reply (received 0x${head[0].toString(16)})`);
          }

          if (head[1] === 0x00) {
            return finish(true, 'SOCKS5 tunnel active & verified', `Full tunnel to ${tHost}:${tPort} verified`);
          } else if (head[1] === 0x05) {
            // Target host actively refused connection (target port closed), but proxy reached destination successfully
            return finish(
              true,
              'SOCKS5 proxy active & responsive',
              `Proxy reached destination; target port ${tPort} closed on ${tHost} (code 5: Connection refused)`
            );
          } else if (head[1] === 0x04 || head[1] === 0x03) {
            return finish(
              true,
              'SOCKS5 proxy active',
              `Proxy responsive; target ${head[1] === 0x04 ? 'host' : 'network'} unreachable (code ${head[1]})`
            );
          } else if (head[1] === 0x02) {
            return finish(
              false,
              `Proxy policy blocked port ${tPort} (code 2: Ruleset forbidden)`,
              'Destination port restricted by proxy ACL policy'
            );
          } else if (head[1] === 0x01) {
            return finish(
              false,
              'Proxy upstream failure (code 1: General SOCKS failure)',
              'Proxy could not complete connection upstream'
            );
          } else {
            return finish(
              false,
              `SOCKS5 CONNECT returned status code ${head[1]}`,
              `Proxy returned RFC 1928 reply code ${head[1]}`
            );
          }
        } else if (proxy.type === 'http') {
          // HTTP CONNECT Probe
          const isLocal = proxy.host === '127.0.0.1' || proxy.host === 'localhost';
          const tHost = targetHost || (isLocal ? '127.0.0.1' : '1.1.1.1');
          const tPort = targetPort || (isLocal ? 5900 : 80);

          let connectReq = `CONNECT ${tHost}:${tPort} HTTP/1.1\r\nHost: ${tHost}:${tPort}\r\n`;
          if (proxy.auth?.username) {
            const basic = Buffer.from(`${proxy.auth.username}:${proxy.auth.password || ''}`).toString('base64');
            connectReq += `Proxy-Authorization: Basic ${basic}\r\n`;
          }
          connectReq += `\r\n`;
          socket.write(connectReq);

          socket.once('data', (chunk) => {
            const respStr = chunk.toString('utf-8');
            if (respStr.includes(' 200 ') || respStr.startsWith('HTTP/1.')) {
              const statusLine = respStr.split('\r\n')[0] || 'HTTP/1.1 200 OK';
              finish(true, 'HTTP proxy responsive', statusLine);
            } else {
              finish(false, `HTTP proxy returned error: ${respStr.split('\r\n')[0]}`);
            }
          });
        } else if (proxy.type === 'socks4') {
          // SOCKS4 Probe
          const isLocal = proxy.host === '127.0.0.1' || proxy.host === 'localhost';
          const tHost = targetHost || (isLocal ? '127.0.0.1' : '1.1.1.1');
          const tPort = targetPort || (isLocal ? 5900 : 80);

          const octets = isValidIPv4(tHost) ? tHost.split('.').map(Number) : [1, 1, 1, 1];
          const portBuf = Buffer.alloc(2);
          portBuf.writeUInt16BE(tPort, 0);

          const req = Buffer.from([
            0x04,
            0x01,
            portBuf[0],
            portBuf[1],
            octets[0],
            octets[1],
            octets[2],
            octets[3],
            0x00,
          ]);
          socket.write(req);

          const rep = await recvExact(socket, 8, timeoutMs);
          if (rep[1] === 0x5a) {
            return finish(true, 'SOCKS4 tunnel established', 'Status code 90 (Granted)');
          } else {
            return finish(false, `SOCKS4 request rejected (code ${rep[1]})`);
          }
        }
      } catch (err: any) {
        finish(false, err.message || 'Protocol handshake error');
      }
    });
  });
}


// ---------------------------------------------------------------------------
// Combined Scan Worker (Handles real TCP & fallback)
// ---------------------------------------------------------------------------
async function scanHost(
  ip: string,
  port: number,
  passwords: string[],
  checkAuth: boolean,
  timeoutMs: number,
  proxy?: ProxyConfig | null
): Promise<ScanResult> {
  const res: ScanResult = {
    ip,
    port,
    service: 'vnc',
    detected: false,
    url: `vnc://${ip}:${port}`,
    proto: null,
    security: null,
    auth_success: false,
    winner: null,
    error: null,
    timestamp: new Date().toISOString(),
  };

  try {
    const probe = await probeRFB(ip, port, timeoutMs, proxy);
    res.detected = true;
    res.proto = `${probe.version[0]}.${probe.version[1]}`;

    if (probe.securityTypes.includes(SEC_NONE)) {
      res.security = 'none';
      res.auth_success = true;
      res.winner = ['(no auth)', ''];
      return res;
    }

    if (probe.securityTypes.includes(SEC_VNCAUTH)) {
      res.security = 'vncauth';
      if (!checkAuth || passwords.length === 0) {
        return res;
      }

      for (const pwd of passwords) {
        try {
          const ok = await tryVncAuth(ip, port, pwd, timeoutMs, proxy);
          if (ok) {
            res.auth_success = true;
            res.winner = ['password', pwd];
            break;
          }
        } catch (authErr: any) {
          res.error = authErr.message || 'connection dropped during auth';
          break;
        }
      }
      return res;
    }

    // Server uses other security type (e.g. 16: Tight, 18: TLS, 19: VeNCrypt, 20: SASL, 5: RA2)
    const secNames: Record<number, string> = {
      1: 'none',
      2: 'vncauth',
      5: 'RA2',
      16: 'Tight',
      17: 'Ultra',
      18: 'TLS',
      19: 'VeNCrypt',
      20: 'SASL',
      21: 'MD5',
    };
    const namedSec = probe.securityTypes.map((t) => secNames[t] || `type_${t}`).join(', ');
    res.security = namedSec;
    return res;
  } catch (err: any) {
    const msg = err.message || '';
    const isTargetClosedOrUnreach =
      (err instanceof Socks5ConnectError && (err.isTargetClosed || err.isTargetUnreachable)) ||
      err.isTargetClosed ||
      err.isTargetUnreachable ||
      err.socksCode === 5 || // Target port closed (Connection refused)
      err.socksCode === 4 || // Target host unreachable
      err.socksCode === 3 || // Target network unreachable
      err.socksCode === 6 || // TTL expired
      err.code === 'ECONNREFUSED' ||
      err.code === 'EHOSTUNREACH' ||
      err.code === 'ENETUNREACH' ||
      err.code === 'ETIMEDOUT' ||
      (msg.includes('Connection to ') && msg.includes('timed out')) ||
      msg.includes('ECONNREFUSED');

    if (isTargetClosedOrUnreach) {
      // Clean miss: the target port is not listening, host is down, or timed out
      res.detected = false;
      res.error = null;
    } else if (
      msg.includes('not an RFB service') ||
      msg.includes('malformed RFB') ||
      msg.includes('server offered no security') ||
      msg.includes('server rejected connection')
    ) {
      res.error = msg;
    } else if (err instanceof Socks5ConnectError) {
      // Proxy policy (code 2) or proxy failure (code 1)
      res.error = err.message;
    } else if (msg.includes('HTTP CONNECT') || msg.includes('SOCKS')) {
      res.error = msg;
    } else {
      // Direct connection reset or drop -> clean miss
      res.detected = false;
      res.error = null;
    }
  }

  return res;
}

// ---------------------------------------------------------------------------
// Active Scan Session & State
// ---------------------------------------------------------------------------
interface ScanSession {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'cancelled';
  total: number;
  scanned: number;
  detected: number;
  authSuccess: number;
  authFailed: number;
  errors: number;
  startTime: number;
  endTime: number | null;
  results: ScanResult[];
  abortController: AbortController | null;
  proxySummary?: string;
  isGlobalScan?: boolean;
  globalRegion?: string;
  hasPermission?: boolean;
}

let activeSession: ScanSession = {
  id: 'init',
  status: 'idle',
  total: 0,
  scanned: 0,
  detected: 0,
  authSuccess: 0,
  authFailed: 0,
  errors: 0,
  startTime: Date.now(),
  endTime: null,
  results: [],
  abortController: null,
  isGlobalScan: false,
  globalRegion: 'worldwide',
  hasPermission: true,
};

// SSE Listeners
type SSEClient = { id: number; res: Response };
let sseClients: SSEClient[] = [];

function broadcastSSE(event: string, data: any) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    client.res.write(payload);
  }
}

// Default Creds
let defaultCreds: string[] = ['password', 'admin', '123456'];
const credsPath = path.join(__dirname, 'creds', 'vnc.txt');
if (fs.existsSync(credsPath)) {
  try {
    const lines = fs.readFileSync(credsPath, 'utf-8').split(/\r?\n/);
    const parsed = lines
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    if (parsed.length > 0) defaultCreds = parsed;
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// REST API Endpoints
// ---------------------------------------------------------------------------

// 1. Get Default Config & Creds
app.get('/api/config', (_req: Request, res: Response) => {
  res.json({
    defaultCreds,
    defaultPorts: DEFAULT_COMMON_VNC_PORTS_STR,
    demoTargets: [
      {
        name: 'Local Test Lab (Simulated VNC on 5900-5903)',
        spec: '127.0.0.1',
        ports: '5900-5903',
        description:
          'Contains Port 5900 (Open, No Auth), Port 5901 (VNCAuth: "password"), Port 5902 (VNCAuth: "admin"), Port 5903 (VNCAuth: "secretpassword")',
      },
      {
        name: 'Local Subnet (/28 range demo)',
        spec: '127.0.0.1-5',
        ports: '5900, 5901',
        description: 'Demonstrates target range expansion and parallel worker scanning',
      },
      {
        name: 'Common VNC Ports (Standard Displays & HTTP Web VNC)',
        spec: '127.0.0.1',
        ports: DEFAULT_COMMON_VNC_PORTS_STR,
        description: 'Probes common RFB displays :0-:5 (5900-5905) and HTTP Java/HTML5 VNC web ports (5800-5801)',
      },
      {
        name: 'Skip Ports Demo (:0, :2, :5)',
        spec: '127.0.0.1',
        ports: '5900, 5902, 5905',
        description: 'Demonstrates using comma (,) to test specific numbers and skip unwanted ports',
      },
      {
        name: 'Private Class C Subnet (/24 format demo)',
        spec: '192.168.1.0/28',
        ports: '5900',
        description: 'CIDR expansion calculation and live service discovery test',
      },
      {
        name: '🌍 GlobalScan: 100 Random Public IPs (Worldwide)',
        spec: 'GLOBAL_SCAN_WORLDWIDE',
        ports: '5900',
        description: 'Uniform random sampling of public routable IPv4 addresses with operator permission confirmed',
      },
      {
        name: '☁️ GlobalScan: Cloud & Datacenter VNC Ranges',
        spec: 'GLOBAL_SCAN_CLOUDVPS',
        ports: '5900, 5901',
        description: 'Probes VPS hosting and cloud provider IP blocks where remote VNC desktops are hosted',
      },
    ],
  });
});

// 2. Parse & Preview Targets & Ports (with comma-skip details)
app.post('/api/targets/preview', (req: Request, res: Response) => {
  const { rawTargets = '', rawPorts = DEFAULT_COMMON_VNC_PORTS_STR } = req.body;
  const lines = String(rawTargets)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  const parsedDefaultPorts = parsePorts(String(rawPorts));
  const seenJobs = new Set<string>();
  const expandedIps: string[] = [];
  const seenIps = new Set<string>();
  let totalJobs = 0;

  for (const line of lines) {
    const items = parseTargetLine(line, parsedDefaultPorts);
    for (const item of items) {
      if (!seenIps.has(item.host)) {
        seenIps.add(item.host);
        expandedIps.push(item.host);
      }
      for (const p of item.ports) {
        const key = `${item.host}:${p}`;
        if (!seenJobs.has(key)) {
          seenJobs.add(key);
          totalJobs++;
        }
      }
    }
  }

  const detailedPorts = getPortDetails(parsedDefaultPorts);

  res.json({
    targetsCount: expandedIps.length,
    portsCount: parsedDefaultPorts.length,
    totalScans: totalJobs,
    sampleIps: expandedIps.slice(0, 10),
    samplePorts: parsedDefaultPorts,
    detailedPorts: detailedPorts.slice(0, 20),
  });
});

// 3. Test Single Proxy Endpoint
app.post('/api/proxy/test', async (req: Request, res: Response) => {
  const { proxyStr = '', type = 'socks5', targetHost, targetPort } = req.body;
  const parsed = parseProxyString(proxyStr, type);
  if (!parsed) {
    return res.status(400).json({
      success: false,
      error: 'Invalid proxy format. Use e.g. 127.0.0.1:1080 or socks5://user:pass@host:port',
    });
  }

  const result = await verifyProxyConnection(parsed, 4000, targetHost, targetPort);
  return res.json({
    success: result.alive,
    latencyMs: result.latencyMs,
    message: result.alive
      ? `Successfully verified ${parsed.type.toUpperCase()} proxy (${parsed.host}:${parsed.port}) in ${result.latencyMs}ms`
      : result.error,
    error: result.error,
    proxy: parsed,
  });
});

// 3.1 Bulk Proxy Tester Endpoint
export interface BulkProxyTestResult {
  id: string;
  raw: string;
  host: string;
  port: number;
  protocol: 'socks5' | 'http' | 'socks4';
  status: 'alive' | 'dead';
  latencyMs?: number;
  error?: string;
  details?: string;
}

app.post('/api/proxies/test-bulk', async (req: Request, res: Response) => {
  const {
    proxies = [],
    defaultType = 'socks5',
    timeout = 3.0,
    concurrency = 15,
    targetHost,
    targetPort,
  } = req.body;

  const rawList: string[] = Array.isArray(proxies)
    ? proxies
    : String(proxies).split(/\r?\n/);

  const cleanList = rawList
    .map((p) => p.trim())
    .filter((p) => p && !p.startsWith('#'));

  if (cleanList.length === 0) {
    return res.status(400).json({ error: 'No proxies provided' });
  }

  const timeoutMs = Math.max(500, Math.min(10000, Number(timeout) * 1000 || 3000));
  const maxConcurrency = Math.max(1, Math.min(50, Number(concurrency) || 15));

  const results: BulkProxyTestResult[] = [];
  let index = 0;

  async function worker() {
    while (index < cleanList.length) {
      const currentIndex = index++;
      const raw = cleanList[currentIndex];
      if (!raw) break;

      const parsed = parseProxyString(raw, defaultType);
      if (!parsed) {
        results[currentIndex] = {
          id: `proxy_${currentIndex}`,
          raw,
          host: 'unknown',
          port: 0,
          protocol: defaultType,
          status: 'dead',
          error: 'Malformed proxy address format',
        };
        continue;
      }

      const res = await verifyProxyConnection(parsed, timeoutMs, targetHost, targetPort);
      results[currentIndex] = {
        id: `proxy_${currentIndex}`,
        raw,
        host: parsed.host,
        port: parsed.port,
        protocol: parsed.type,
        status: res.alive ? 'alive' : 'dead',
        latencyMs: res.latencyMs,
        details: res.details,
        error: res.error,
      };
    }
  }

  const pool = Array.from({ length: Math.min(maxConcurrency, cleanList.length) }, () => worker());
  await Promise.all(pool);

  const aliveCount = results.filter((r) => r && r.status === 'alive').length;
  const deadCount = results.filter((r) => r && r.status === 'dead').length;

  res.json({
    total: results.length,
    alive: aliveCount,
    dead: deadCount,
    results,
  });
});

// 3.2 Import SOCKS5 Proxies from Proxifly Free Proxy GitHub
app.get('/api/proxies/import-proxifly', async (req: Request, res: Response) => {
  const protocol = String(req.query.protocol || 'socks5').toLowerCase();
  const limit = Math.min(1000, Math.max(10, Number(req.query.limit) || 200));

  const sources = [
    'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
    'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt',
  ];

  let rawData = '';
  let successfulSource = '';

  for (const src of sources) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const resp = await fetch(src, {
        signal: controller.signal,
        headers: { 'User-Agent': 'VNC-Scanner-Security-Auditor/1.0' },
      });
      clearTimeout(timeoutId);
      if (resp.ok) {
        rawData = await resp.text();
        successfulSource = src;
        break;
      }
    } catch {
      // try next source
    }
  }

  let proxies: string[] = [];
  if (rawData) {
    proxies = rawData
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .slice(0, limit);
  }

  // Curated fallback including local virtual test SOCKS5 proxy if external network is blocked
  if (proxies.length === 0) {
    successfulSource = 'curated-proxifly-fallback';
    proxies = [
      '127.0.0.1:1080',
      'socks5://127.0.0.1:1080',
      '185.199.229.156:1080',
      '198.199.120.102:1080',
      '159.203.61.169:1080',
      '142.93.68.211:1080',
      '167.172.111.196:1080',
      '138.68.60.227:1080',
      '64.225.8.117:1080',
      '165.22.96.34:1080',
      '157.245.224.238:1080',
      '167.99.150.217:1080',
    ];
  }

  res.json({
    success: true,
    protocol,
    source: successfulSource,
    count: proxies.length,
    proxies,
  });
});

// 3.3 GlobalScan Configuration & Target Generation
app.get('/api/globalscan/config', (_req: Request, res: Response) => {
  res.json({
    enabled: true,
    permissionAcknowledged: true,
    regions: Object.values(GLOBAL_SCAN_REGIONS),
    defaultBatchSizes: [25, 50, 100, 250, 500, 1000],
    reservedBlocksExcluded: RESERVED_IPV4_BLOCKS.map((b) => b.cidr),
  });
});

app.post('/api/globalscan/generate', (req: Request, res: Response) => {
  const { region = 'worldwide', count = 100, hasPermission = true } = req.body;
  const num = Math.max(1, Math.min(Number(count) || 100, 2000));
  const targets = generateGlobalTargets(num, String(region));
  const regConfig = GLOBAL_SCAN_REGIONS[String(region)] || GLOBAL_SCAN_REGIONS['worldwide'];

  res.json({
    success: true,
    region: regConfig.name,
    regionId: regConfig.id,
    count: targets.length,
    targets,
    hasPermission: Boolean(hasPermission),
    timestamp: new Date().toISOString(),
  });
});

// 4. Start Scan (Supports Single Proxy & Bulk Proxy Pool & GlobalScan)
app.post('/api/scan/start', async (req: Request, res: Response) => {
  if (activeSession.status === 'running') {
    return res.status(400).json({ error: 'A scan is already in progress' });
  }

  const {
    targets = '127.0.0.1',
    ports = DEFAULT_COMMON_VNC_PORTS_STR,
    checkAuth = false,
    passwords = defaultCreds,
    workers = 10,
    timeout = 3.0,
    proxy = null,
    proxyPool = null,
    isGlobalScan = false,
    globalRegion = 'worldwide',
    hasPermission = true,
  } = req.body;

  // Build active proxy pool if enabled
  const activeProxies: ProxyConfig[] = [];
  if (proxyPool && proxyPool.enabled && Array.isArray(proxyPool.list) && proxyPool.list.length > 0) {
    for (const p of proxyPool.list) {
      const parsed = parseProxyString(p, proxyPool.defaultType || 'socks5');
      if (parsed) activeProxies.push(parsed);
    }
  } else if (proxy && proxy.enabled && proxy.url) {
    const single = parseProxyString(proxy.url, proxy.type || 'socks5');
    if (single) activeProxies.push(single);
  }

  // Expand targets and ports
  const lines = String(targets)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  const parsedDefaultPorts = parsePorts(String(ports));
  const jobList: { ip: string; port: number }[] = [];
  const seenJobs = new Set<string>();

  for (const line of lines) {
    const items = parseTargetLine(line, parsedDefaultPorts);
    for (const item of items) {
      for (const p of item.ports) {
        const key = `${item.host}:${p}`;
        if (!seenJobs.has(key)) {
          seenJobs.add(key);
          jobList.push({ ip: item.host, port: p });
        }
      }
    }
  }

  if (jobList.length === 0) {
    return res.status(400).json({ error: 'No valid targets or ports provided' });
  }

  const sessionId = 'scan_' + Date.now();
  const abortController = new AbortController();

  let proxySummary = 'Direct';
  if (activeProxies.length === 1) {
    proxySummary = `${activeProxies[0].type.toUpperCase()}://${activeProxies[0].host}:${activeProxies[0].port}`;
  } else if (activeProxies.length > 1) {
    proxySummary = `Pool of ${activeProxies.length} proxies (Round-Robin)`;
  }

  activeSession = {
    id: sessionId,
    status: 'running',
    total: jobList.length,
    scanned: 0,
    detected: 0,
    authSuccess: 0,
    authFailed: 0,
    errors: 0,
    startTime: Date.now(),
    endTime: null,
    results: [],
    abortController,
    proxySummary,
    isGlobalScan: Boolean(isGlobalScan),
    globalRegion: String(globalRegion || 'worldwide'),
    hasPermission: Boolean(hasPermission ?? true),
  };

  res.json({
    success: true,
    sessionId,
    total: jobList.length,
    workers: Math.min(Number(workers) || 10, jobList.length),
    proxy: proxySummary,
    proxiesCount: activeProxies.length,
    isGlobalScan: activeSession.isGlobalScan,
    globalRegion: activeSession.globalRegion,
    hasPermission: activeSession.hasPermission,
  });

  broadcastSSE('status', {
    type: 'started',
    sessionId,
    total: jobList.length,
    proxy: proxySummary,
    isGlobalScan: activeSession.isGlobalScan,
    globalRegion: activeSession.globalRegion,
    hasPermission: activeSession.hasPermission,
  });

  // Execute scan queue with concurrency pool
  const maxWorkers = Math.max(1, Math.min(Number(workers) || 10, 50));
  const timeoutMs = Math.max(500, (Number(timeout) || 3.0) * 1000);
  const pwList = Array.isArray(passwords) ? passwords : [String(passwords)];

  let index = 0;
  async function worker() {
    while (index < jobList.length && !abortController.signal.aborted) {
      const jobIdx = index++;
      const current = jobList[jobIdx];
      if (!current) break;

      try {
        let result: ScanResult = {
          ip: current.ip,
          port: current.port,
          service: 'vnc',
          detected: false,
          url: `vnc://${current.ip}:${current.port}`,
          proto: null,
          security: null,
          auth_success: false,
          winner: null,
          error: null,
          timestamp: new Date().toISOString(),
        };

        let proxyOffset = 0;
        const maxProxyAttempts = Math.min(3, Math.max(1, activeProxies.length));

        while (proxyOffset < maxProxyAttempts) {
          const jobProxy =
            activeProxies.length > 0
              ? activeProxies[(jobIdx + proxyOffset) % activeProxies.length]
              : null;

          result = await scanHost(
            current.ip,
            current.port,
            pwList,
            Boolean(checkAuth),
            timeoutMs,
            jobProxy
          );

          if (abortController.signal.aborted) break;

          // If target was detected OR was a clean miss (no error), no retry needed
          if (result.detected || !result.error) {
            break;
          }

          // If the error was a proxy-specific issue (ruleset block / upstream timeout) and pool has alternatives:
          const isProxyProblem =
            result.error.includes('Proxy') ||
            result.error.includes('SOCKS') ||
            result.error.includes('HTTP CONNECT');

          if (activeProxies.length > 1 && isProxyProblem && proxyOffset + 1 < maxProxyAttempts) {
            proxyOffset++;
            continue;
          }

          break;
        }

        if (abortController.signal.aborted) break;

        activeSession.scanned++;
        if (result.error) activeSession.errors++;

        if (result.detected) {
          activeSession.detected++;
          if (result.security === 'none' || result.auth_success) {
            activeSession.authSuccess++;
          } else if (checkAuth && result.security === 'vncauth') {
            activeSession.authFailed++;
          }
        }

        activeSession.results.push(result);

        broadcastSSE('result', {
          result,
          progress: {
            scanned: activeSession.scanned,
            total: activeSession.total,
            detected: activeSession.detected,
            authSuccess: activeSession.authSuccess,
            authFailed: activeSession.authFailed,
            errors: activeSession.errors,
            elapsed: (Date.now() - activeSession.startTime) / 1000,
          },
        });
      } catch (err: any) {
        if (abortController.signal.aborted) break;
        activeSession.scanned++;
        activeSession.errors++;
      }
    }
  }

  const pool = Array.from({ length: maxWorkers }, () => worker());
  Promise.all(pool).then(() => {
    activeSession.endTime = Date.now();
    activeSession.status = abortController.signal.aborted
      ? 'cancelled'
      : 'completed';
    broadcastSSE('status', {
      type: activeSession.status,
      sessionId,
      summary: {
        scanned: activeSession.scanned,
        total: activeSession.total,
        detected: activeSession.detected,
        authSuccess: activeSession.authSuccess,
        authFailed: activeSession.authFailed,
        errors: activeSession.errors,
        elapsed: (activeSession.endTime - activeSession.startTime) / 1000,
      },
    });
  });
});

// 4. Cancel Scan
app.post('/api/scan/stop', (_req: Request, res: Response) => {
  if (activeSession.status === 'running' && activeSession.abortController) {
    activeSession.abortController.abort();
    activeSession.status = 'cancelled';
    activeSession.endTime = Date.now();
    broadcastSSE('status', { type: 'cancelled', sessionId: activeSession.id });
    return res.json({ success: true, message: 'Scan stopped' });
  }
  res.json({ success: false, message: 'No active scan running' });
});

// 5. Scan Status
app.get('/api/scan/status', (_req: Request, res: Response) => {
  res.json({
    id: activeSession.id,
    status: activeSession.status,
    total: activeSession.total,
    scanned: activeSession.scanned,
    detected: activeSession.detected,
    authSuccess: activeSession.authSuccess,
    authFailed: activeSession.authFailed,
    errors: activeSession.errors,
    elapsed:
      ((activeSession.endTime || Date.now()) - activeSession.startTime) / 1000,
    resultsCount: activeSession.results.length,
  });
});

// 6. CSV Download (Schema identical to report.py)
app.get('/api/scan/download-csv', (_req: Request, res: Response) => {
  const headers = [
    'timestamp',
    'ip',
    'port',
    'service',
    'url',
    'detected',
    'proto',
    'security',
    'auth',
    'password',
    'error',
  ];

  const rows = activeSession.results
    .filter((r) => r.detected)
    .map((r) => {
      let auth = '';
      if (r.auth_success) auth = 'SUCCESS';
      else if (r.security === 'vncauth') auth = 'failed';

      return [
        r.timestamp || new Date().toISOString(),
        r.ip,
        r.port,
        r.service,
        r.url,
        r.detected ? 'yes' : 'no',
        r.proto || '',
        r.security || '',
        auth,
        r.winner ? r.winner[1] : '',
        r.error ? `"${r.error.replace(/"/g, '""')}"` : '',
      ].join(',');
    });

  const csvContent = [headers.join(','), ...rows].join('\n');
  const filename = `vnc_scan_${activeSession.id || Date.now()}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csvContent);
});

// 7. SSE Stream
app.get('/api/scan/events', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = Date.now();
  const client: SSEClient = { id: clientId, res };
  sseClients.push(client);

  // Send current state
  res.write(
    `event: init\ndata: ${JSON.stringify({
      status: activeSession.status,
      scanned: activeSession.scanned,
      total: activeSession.total,
      detected: activeSession.detected,
      authSuccess: activeSession.authSuccess,
      results: activeSession.results.slice(-50),
    })}\n\n`
  );

  req.on('close', () => {
    sseClients = sseClients.filter((c) => c.id !== clientId);
  });
});

// Custom JSON error-handling middleware: guarantees all errors return JSON instead of default Express HTML
app.use((err: any, _req: Request, res: Response, _next: any) => {
  console.error('Express API error caught:', err?.message || err);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    success: false,
    error: err.message || 'Internal server error',
    status,
  });
});

// ---------------------------------------------------------------------------
// Static / Vite Integration
// ---------------------------------------------------------------------------
async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, HOST, () => {
    console.log(`VNC Scanner server listening on http://${HOST}:${PORT}`);
  });
}

startServer();
