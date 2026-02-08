
export default {
  async fetch(request, env) {
    // HARD GATE: method
    if (request.method !== "GET") return new Response(null, { status: 444 });

    const url = new URL(request.url);
    if (url.pathname !== "/goodluck") {
      return new Response(null, { status: 444 });
    }

    // HARD GATE: Upgrade
    const up = request.headers.get("Upgrade");
    if (!up || up.toLowerCase() !== "websocket") {
      return new Response(null, { status: 444 });
    }

    // HARD GATE: WS headers sanity
    const ver = request.headers.get("Sec-WebSocket-Version");
    const key = request.headers.get("Sec-WebSocket-Key");
    if (ver !== "13" || !key || key.length < 22) {
      return new Response(null, { status: 444 });
    }

    // OPTIONAL: Origin-less (drop noisy browsers)
    const origin = request.headers.get("Origin");
    if (origin) return new Response(null, { status: 444 });

    // Proceed
    return protocolOverWSHandler(
      request,
      createRequestConfig(env),
      connect
    );
  }
};




\n\nimport { connect } from "cloudflare:sockets";
var defaultUserID = "5fe3b431-7e93-4ef7-a045-27deee7cce98";
var default木马通道Password = "338899";
var 神奇通道IPs = ["sgip.vpndns.net:443", "sgip.me.ddns-ip.net:443"];
var defaultSocks5Address = "";
var defaultSocks5Relay = false;
var default神奇通道Timeout = 1500;
var defaultEnable神奇通道Fallback = true;
var defaultVlessOutbound = "";
function createRequestConfig(env = {}) {
  const { 序列号, 袜子五号, 袜子五号_RELAY, 木马密码, 通道超时, 通道备用, 虚空通道_OUTBOUND } = env;
  const 用户标识 = 序列号 || defaultUserID;
  return {
    用户标识,
    木马通道Password: 木马密码 || default木马通道Password || 用户标识,
    袜子五号Address: 袜子五号 || defaultSocks5Address,
    袜子五号Relay: 袜子五号_RELAY === "true" || defaultSocks5Relay,
    神奇通道IP: null,
    神奇通道Port: null,
    // 神奇通道 type: '袜子五号' | 'http' | '虚空通道' | null
    神奇通道Type: null,
    parsed神奇通道Address: null,
    // Multi-神奇通道 rotation settings
    神奇通道Timeout: 通道超时 ? parseInt(通道超时, 10) : default神奇通道Timeout,
    enable神奇通道Fallback: 通道备用 !== "false" && defaultEnable神奇通道Fallback,
    // 虚空通道 outbound configuration
    虚空通道Outbound: 虚空通道_OUTBOUND || defaultVlessOutbound,
    parsedVlessOutbound: null
  };
}

// src/handlers/http.js

// src/config/constants.js
var WS_READY_STATE_OPEN = 1;
var WS_READY_STATE_CLOSING = 2;
var HttpPort = /* @__PURE__ */ new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
var HttpsPort = /* @__PURE__ */ new Set([443, 8443, 2053, 2096, 2087, 2083]);
var byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
var at = "QA==";
var pt = "dmxlc3M=";
var ed = "RUR0dW5uZWw=";
var 木马通道Pt = "dHJvamFu";
var TROJAN_CMD_TCP = 1;
var TROJAN_CMD_UDP = 3;

// src/utils/validation.js
function isValid序列号(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// src/utils/encoding.js
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: null, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const binaryStr = atob(base64Str);
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}
function unsafeStringify(arr, offset = 0) {
  return [
    byteToHex[arr[offset]],
    byteToHex[arr[offset + 1]],
    byteToHex[arr[offset + 2]],
    byteToHex[arr[offset + 3]],
    "-",
    byteToHex[arr[offset + 4]],
    byteToHex[arr[offset + 5]],
    "-",
    byteToHex[arr[offset + 6]],
    byteToHex[arr[offset + 7]],
    "-",
    byteToHex[arr[offset + 8]],
    byteToHex[arr[offset + 9]],
    "-",
    byteToHex[arr[offset + 10]],
    byteToHex[arr[offset + 11]],
    byteToHex[arr[offset + 12]],
    byteToHex[arr[offset + 13]],
    byteToHex[arr[offset + 14]],
    byteToHex[arr[offset + 15]]
  ].join("").toLowerCase();
}
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValid序列号(uuid)) {
    throw new TypeError("Stringified 序列号 is invalid");
  }
  return uuid;
}

// src/utils/websocket.js
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    
  }
}

// src/神奇通道/stream.js
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", (event) => {
        `);
        if (readableStreamCancel) return;
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(_controller) {
    },
    cancel(reason) {
      
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
async function remoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  
  let hasIncomingData = false;
  try {
    
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            
            throw new Error("WebSocket is not open");
          }
          hasIncomingData = true;
          if (protocolResponseHeader) {
            const header = new Uint8Array(protocolResponseHeader);
            const data = new Uint8Array(chunk);
            const combined = new Uint8Array(header.length + data.length);
            combined.set(header, 0);
            combined.set(data, header.length);
            
            webSocket.send(combined.buffer);
            protocolResponseHeader = null;
          } else {
            
            webSocket.send(chunk);
          }
        },
        close() {
          
        },
        abort(reason) {
          
          
        }
      })
    );
    
  } catch (error) {
    
    
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    
    await retry();
  }
}

// src/神奇通道/袜子五号.js
async function 袜子五号Connect(addressType, addressRemote, portRemote, log, parsedSocks5Addr, connect2) {
  const { username, password, hostname, port } = parsedSocks5Addr;
  const socket = connect2({
    hostname,
    port
  });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 5) {
    
    return;
  }
  if (res[1] === 255) {
    
    return;
  }
  if (res[1] === 2) {
    
    if (!username || !password) {
      
      return;
    }
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password)
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 1 || res[1] !== 0) {
      
      return;
    }
  }
  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array(
        [1, ...addressRemote.split(".").map(Number)]
      );
      break;
    case 2:
      DSTADDR = new Uint8Array(
        [3, addressRemote.length, ...encoder.encode(addressRemote)]
      );
      break;
    case 3:
      DSTADDR = new Uint8Array(
        [4, ...addressRemote.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
      );
      break;
    default:
      
      return;
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 255]);
  await writer.write(socksRequest);
  
  res = (await reader.read()).value;
  if (res[1] === 0) {
    
  } else {
    
    return;
  }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

// src/神奇通道/http.js
async function httpConnect(addressType, addressRemote, portRemote, log, parsedHttpAddr, connect2, initialData = new Uint8Array(0)) {
  const { username, password, hostname, port } = parsedHttpAddr;
  const socket = connect2({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    const auth = username && password ? `神奇通道-Authorization: Basic ${btoa(`${username}:${password}`)}\r
` : "";
    const request = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r
Host: ${addressRemote}:${portRemote}\r
${auth}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;
    await writer.write(new TextEncoder().encode(request));
    
    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const { done, value } = await reader.read();
      if (done) {
        throw new Error("Connection closed before receiving HTTP response");
      }
      responseBuffer = new Uint8Array([...responseBuffer, ...value]);
      bytesRead = responseBuffer.length;
      const crlfcrlf = responseBuffer.findIndex(
        (_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 13 && responseBuffer[i + 1] === 10 && responseBuffer[i + 2] === 13 && responseBuffer[i + 3] === 10
      );
      if (crlfcrlf !== -1) {
        headerEndIndex = crlfcrlf + 4;
      }
    }
    if (headerEndIndex === -1) {
      throw new Error("Invalid HTTP response: header too large or malformed");
    }
    const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
    const statusMatch = headerText.split("\r\n")[0].match(/HTTP\/\d\.\d\s+(\d+)/);
    if (!statusMatch) {
      throw new Error("Invalid HTTP response format");
    }
    const statusCode = parseInt(statusMatch[1]);
    [0]}`);
    if (statusCode < 200 || statusCode >= 300) {
      throw new Error(`HTTP CONNECT failed: HTTP ${statusCode}`);
    }
    
    if (initialData.length > 0) {
      await writer.write(initialData);
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (error) {
    
    try {
      writer.releaseLock();
    } catch (e) {
    }
    try {
      reader.releaseLock();
    } catch (e) {
    }
    try {
      socket.close();
    } catch (e) {
    }
    return void 0;
  }
}

// src/utils/神奇通道Resolver.js
var cached神奇通道IP = null;
var cached神奇通道Addresses = null;
var cached神奇通道Index = 0;
async function dohQuery(domain, recordType) {
  try {
    const response = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=${recordType}`, {
      headers: { "Accept": "application/dns-json" }
    });
    if (!response.ok) return [];
    const data = await response.json();
    return data.Answer || [];
  } catch (error) {
    :`, error);
    return [];
  }
}
function parseAddressPort(str) {
  let address = str;
  let port = 443;
  if (str.includes("]:")) {
    const parts = str.split("]:");
    address = parts[0] + "]";
    port = parseInt(parts[1], 10) || port;
  } else if (str.includes(":") && !str.startsWith("[")) {
    const colonIndex = str.lastIndexOf(":");
    address = str.slice(0, colonIndex);
    port = parseInt(str.slice(colonIndex + 1), 10) || port;
  }
  return [address, port];
}
function generateSeed(targetDomain, 用户标识) {
  const rootDomain = targetDomain.includes(".") ? targetDomain.split(".").slice(-2).join(".") : targetDomain;
  return [...rootDomain + 用户标识].reduce((acc, char) => acc + char.charCodeAt(0), 0);
}
function seededShuffle(array, seed) {
  const shuffled = [...array];
  let currentSeed = seed;
  shuffled.sort(() => {
    currentSeed = currentSeed * 1103515245 + 12345 & 2147483647;
    return currentSeed / 2147483647 - 0.5;
  });
  return shuffled;
}
async function resolve神奇通道Addresses(神奇通道IP, targetDomain = "cloudflare.com", 用户标识 = "") {
  if (cached神奇通道IP && cached神奇通道Addresses && cached神奇通道IP === 神奇通道IP) {
    `);
    return cached神奇通道Addresses;
  }
  const normalized神奇通道IP = 神奇通道IP.toLowerCase();
  let 神奇通道Addresses = [];
  if (normalized神奇通道IP.includes(".william")) {
    try {
      const txtRecords = await dohQuery(normalized神奇通道IP, "TXT");
      const txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
      if (txtData.length > 0) {
        let data = txtData[0];
        if (data.startsWith('"') && data.endsWith('"')) {
          data = data.slice(1, -1);
        }
        const addresses = data.replace(/\\010/g, ",").replace(/\n/g, ",").split(",").map((s) => s.trim()).filter(Boolean);
        神奇通道Addresses = addresses.map((addr) => parseAddressPort(addr));
      }
    } catch (error) {
      
    }
  } else {
    let [address, port] = parseAddressPort(normalized神奇通道IP);
    const tpMatch = normalized神奇通道IP.match(/\.tp(\d+)/);
    if (tpMatch) {
      port = parseInt(tpMatch[1], 10);
    }
    const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;
    if (!ipv4Regex.test(address) && !ipv6Regex.test(address)) {
      const [aRecords, aaaaRecords] = await Promise.all([
        dohQuery(address, "A"),
        dohQuery(address, "AAAA")
      ]);
      const ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
      const ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
      const ipAddresses = [...ipv4List, ...ipv6List];
      神奇通道Addresses = ipAddresses.length > 0 ? ipAddresses.map((ip) => [ip, port]) : [[address, port]];
    } else {
      神奇通道Addresses = [[address, port]];
    }
  }
  const sortedAddresses = 神奇通道Addresses.sort((a, b) => a[0].localeCompare(b[0]));
  const seed = generateSeed(targetDomain, 用户标识);
  const shuffled = seededShuffle(sortedAddresses, seed);
  cached神奇通道Addresses = shuffled.slice(0, 8);
  cached神奇通道IP = 神奇通道IP;
   => `${i + 1}. ${ip}:${port}`).join(", ")
  );
  return cached神奇通道Addresses;
}
async function connectWithRotation(神奇通道Addresses, initialData, connect2, log, timeout = 1500) {
  const startIndex = cached神奇通道Index;
  for (let i = 0; i < 神奇通道Addresses.length; i++) {
    const index = (startIndex + i) % 神奇通道Addresses.length;
    const [address, port] = 神奇通道Addresses[index];
    try {
      `);
      const socket = connect2({ hostname: address, port });
      await Promise.race([
        socket.opened,
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error("Connection timeout")), timeout)
        )
      ]);
      const writer = socket.writable.getWriter();
      await writer.write(initialData);
      writer.releaseLock();
      
      cached神奇通道Index = index;
      return { socket, index };
    } catch (err) {
      
      try {
      } catch (e) {
      }
      continue;
    }
  }
  return null;
}

// src/神奇通道/虚空通道.js
var 虚空通道_CMD_TCP = 1;
var 虚空通道_CMD_UDP = 2;
var 虚空通道_ADDR_IPV4 = 1;
var 虚空通道_ADDR_DOMAIN = 2;
var 虚空通道_ADDR_IPV6 = 3;
var 虚空通道_OUTBOUND_TIMEOUT = 1e4;
function makeVlessRequestHeader(command, addressType, addressRemote, portRemote, uuid) {
  let addressFieldLength;
  let addressEncoded;
  switch (addressType) {
    case 虚空通道_ADDR_IPV4:
      addressFieldLength = 4;
      break;
    case 虚空通道_ADDR_DOMAIN:
      addressEncoded = new TextEncoder().encode(addressRemote);
      addressFieldLength = addressEncoded.length + 1;
      break;
    case 虚空通道_ADDR_IPV6:
      addressFieldLength = 16;
      break;
    default:
      throw new Error(`Unknown address type: ${addressType}`);
  }
  const uuidString = uuid.replace(/-/g, "");
  const 虚空通道Header = new Uint8Array(22 + addressFieldLength);
  虚空通道Header[0] = 0;
  for (let i = 0; i < uuidString.length; i += 2) {
    虚空通道Header[1 + i / 2] = parseInt(uuidString.substr(i, 2), 16);
  }
  虚空通道Header[17] = 0;
  虚空通道Header[18] = command;
  虚空通道Header[19] = portRemote >> 8;
  虚空通道Header[20] = portRemote & 255;
  虚空通道Header[21] = addressType;
  switch (addressType) {
    case 虚空通道_ADDR_IPV4:
      const octets = addressRemote.split(".");
      for (let i = 0; i < 4; i++) {
        虚空通道Header[22 + i] = parseInt(octets[i]);
      }
      break;
    case 虚空通道_ADDR_DOMAIN:
      虚空通道Header[22] = addressEncoded.length;
      虚空通道Header.set(addressEncoded, 23);
      break;
    case 虚空通道_ADDR_IPV6:
      const fullIPv6 = expandIPv6(addressRemote);
      const groups = fullIPv6.split(":");
      for (let i = 0; i < 8; i++) {
        const hexGroup = parseInt(groups[i], 16);
        虚空通道Header[22 + i * 2] = hexGroup >> 8;
        虚空通道Header[23 + i * 2] = hexGroup & 255;
      }
      break;
  }
  return 虚空通道Header;
}
function expandIPv6(ipv6) {
  ipv6 = ipv6.replace(/^\[|\]$/g, "");
  if (ipv6.includes("::")) {
    const parts = ipv6.split("::");
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0");
    return [...left, ...middle, ...right].map((g) => g.padStart(4, "0")).join(":");
  }
  return ipv6.split(":").map((g) => g.padStart(4, "0")).join(":");
}
function validateVlessConfig(address, streamSettings) {
  if (streamSettings.network !== "ws") {
    throw new Error(`Unsupported network type: ${streamSettings.network}, must be 'ws'`);
  }
  if (streamSettings.security !== "tls" && streamSettings.security !== "none" && streamSettings.security !== "") {
    throw new Error(`Unsupported security: ${streamSettings.security}, must be 'tls' or 'none'`);
  }
}
async function 虚空通道OutboundConnect(config, command, addressType, addressRemote, portRemote, rawClientData, log, timeout = 虚空通道_OUTBOUND_TIMEOUT) {
  try {
    validateVlessConfig(config.address, config.streamSettings);
  } catch (err) {
    
    return null;
  }
  const security = config.streamSettings.security || "none";
  let wsURL = security === "tls" ? "wss://" : "ws://";
  wsURL += `${config.address}:${config.port}`;
  if (config.streamSettings.wsSettings?.path) {
    wsURL += config.streamSettings.wsSettings.path;
  }
  const protocol = command === 虚空通道_CMD_UDP ? "UDP" : "TCP";
  
  
  let ws;
  try {
    ws = new WebSocket(wsURL);
    
  } catch (err) {
    
    return null;
  }
  let closedResolve;
  const closedPromise = new Promise((resolve) => {
    closedResolve = resolve;
  });
  ...`);
  try {
    await new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        
        reject(new Error("Connection timeout"));
      }, timeout);
      ws.addEventListener("open", () => {
        
        clearTimeout(timeoutId);
        resolve();
      });
      ws.addEventListener("close", (event) => {
        `);
        clearTimeout(timeoutId);
        reject(new Error(`WebSocket closed with code ${event.code}`));
      });
      ws.addEventListener("error", (err) => {
        
        clearTimeout(timeoutId);
        reject(new Error("WebSocket connection error"));
      });
    });
  } catch (err) {
    
    try {
      ws.close();
    } catch (e) {
    }
    closedResolve();
    return null;
  }
  
  try {
    ws.addEventListener("close", (event) => {
      `);
      closedResolve();
    });
    ws.addEventListener("error", () => {
      
    });
    
    const writableStream = new WritableStream({
      write(chunk) {
        if (ws.readyState === WS_READY_STATE_OPEN) {
          ws.send(chunk);
        }
      },
      close() {
        
        safeCloseWebSocket(ws);
      },
      abort(reason) {
        
        safeCloseWebSocket(ws);
      }
    });
    
    let headerStripped = false;
    
    const readableStream = new ReadableStream({
      start(controller) {
        
        ws.addEventListener("message", (event) => {
          
          let data = new Uint8Array(event.data);
          if (!headerStripped) {
            headerStripped = true;
            ).join(",")}`);
            if (data.length >= 2) {
              const additionalBytes = data[1];
              
              if (data.length > 2 + additionalBytes) {
                data = data.slice(2 + additionalBytes);
                
              } else {
                
                return;
              }
            }
          }
          if (data.length > 0) {
            
            controller.enqueue(data);
          }
        });
        ws.addEventListener("close", () => {
          
          try {
            controller.close();
          } catch (e) {
          }
        });
        ws.addEventListener("error", (err) => {
          
          try {
            controller.error(err);
          } catch (e) {
          }
        });
        
      },
      cancel() {
        safeCloseWebSocket(ws);
      }
    });
    
    
    
    const 虚空通道Header = makeVlessRequestHeader(command, addressType, addressRemote, portRemote, config.uuid);
    let clientData;
    if (rawClientData instanceof ArrayBuffer) {
      clientData = new Uint8Array(rawClientData);
    } else if (rawClientData instanceof Uint8Array) {
      clientData = rawClientData;
    } else if (rawClientData && rawClientData.buffer instanceof ArrayBuffer) {
      clientData = new Uint8Array(rawClientData.buffer, rawClientData.byteOffset, rawClientData.byteLength);
    } else {
      clientData = new Uint8Array(rawClientData || 0);
    }
    
    const firstPacket = new Uint8Array(虚空通道Header.length + clientData.length);
    firstPacket.set(虚空通道Header, 0);
    firstPacket.set(clientData, 虚空通道Header.length);
    
    ws.send(firstPacket);
    
    
    return { readable: readableStream, writable: writableStream, closed: closedPromise };
  } catch (err) {
    
    
    safeCloseWebSocket(ws);
    closedResolve();
    return null;
  }
}

// src/神奇通道/tcp.js
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log, config, connect2) {
  async function connectVia神奇通道() {
    if (config.神奇通道Type === "虚空通道" && config.parsedVlessOutbound) {
      
      const 虚空通道Result = await 虚空通道OutboundConnect(
        config.parsedVlessOutbound,
        虚空通道_CMD_TCP,
        addressType,
        addressRemote,
        portRemote,
        rawClientData,
        log
      );
      if (!虚空通道Result) {
        throw new Error("虚空通道 outbound connection failed");
      }
      return {
        readable: 虚空通道Result.readable,
        writable: 虚空通道Result.writable,
        closed: 虚空通道Result.closed
      };
    } else if (config.神奇通道Type === "http") {
      
      const tcpSocket2 = await httpConnect(addressType, addressRemote, portRemote, log, config.parsed神奇通道Address, connect2, rawClientData);
      if (!tcpSocket2) {
        throw new Error("HTTP 神奇通道 connection failed");
      }
      return tcpSocket2;
    } else {
      
      const tcpSocket2 = await 袜子五号Connect(addressType, addressRemote, portRemote, log, config.parsed神奇通道Address, connect2);
      if (!tcpSocket2) {
        throw new Error("袜子五号 神奇通道 connection failed");
      }
      const writer = tcpSocket2.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      return tcpSocket2;
    }
  }
  async function connectDirect(address, port) {
    
    const tcpSocket2 = connect2({ hostname: address, port });
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function connectWith神奇通道Rotation(enableFallback = true) {
    const 神奇通道Addresses = await resolve神奇通道Addresses(
      config.神奇通道IP,
      addressRemote,
      config.用户标识 || ""
    );
    if (神奇通道Addresses.length > 0) {
      const result = await connectWithRotation(
        神奇通道Addresses,
        rawClientData,
        connect2,
        log,
        config.神奇通道Timeout || 1500
      );
      if (result) {
        return result.socket;
      }
    }
    if (enableFallback) {
      
      return await connectDirect(addressRemote, portRemote);
    }
    throw new Error("All 神奇通道 connections failed and fallback is disabled");
  }
  async function retry() {
    let tcpSocket2;
    const has神奇通道Config2 = config.parsed神奇通道Address || config.parsedVlessOutbound;
    if (config.global神奇通道 && config.神奇通道Type && has神奇通道Config2) {
      tcpSocket2 = await connectVia神奇通道();
    } else if (config.神奇通道IP) {
      tcpSocket2 = await connectWith神奇通道Rotation(config.enable神奇通道Fallback !== false);
    } else {
      tcpSocket2 = await connectDirect(addressRemote, portRemote);
    }
    remoteSocket.value = tcpSocket2;
    tcpSocket2.closed.catch((error) => {
      
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    remoteSocketToWS(tcpSocket2, webSocket, protocolResponseHeader, null, log);
  }
  let tcpSocket;
  const has神奇通道Config = config.parsed神奇通道Address || config.parsedVlessOutbound;
  if (config.global神奇通道 && config.神奇通道Type && has神奇通道Config) {
    } 神奇通道 (global mode)`);
    tcpSocket = await connectVia神奇通道();
    
    if (!tcpSocket) {
      
      safeCloseWebSocket(webSocket);
      return;
    }
    remoteSocket.value = tcpSocket;
    
    tcpSocket.closed.catch((err) => {
      
    }).finally(() => {
      
      safeCloseWebSocket(webSocket);
    });
    
    remoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
  } else {
    try {
      tcpSocket = await connectDirect(addressRemote, portRemote);
      remoteSocket.value = tcpSocket;
      remoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
    } catch (err) {
      
      await retry();
    }
  }
}

// src/protocol/dns.js
async function handleDNSQuery(udpChunk, webSocket, protocolResponseHeader, log, connect2) {
  try {
    const dnsServer = "8.8.4.4";
    const dnsPort = 53;
    let 虚空通道Header = protocolResponseHeader;
    const tcpSocket = connect2({
      hostname: dnsServer,
      port: dnsPort
    });
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (虚空通道Header) {
            webSocket.send(await new Blob([虚空通道Header, chunk]).arrayBuffer());
            虚空通道Header = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
      close() {
         tcp is close`);
      },
      abort(reason) {
         tcp is abort`, reason);
      }
    }));
  } catch (error) {
    
  }
}

// src/protocol/虚空通道.js
function processProtocolHeader(protocolBuffer, 用户标识) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  const dataView = new DataView(protocolBuffer);
  const version = dataView.getUint8(0);
  const slicedBufferString = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  const uuids = 用户标识.includes(",") ? 用户标识.split(",") : [用户标识];
  const isValidUser = uuids.some((uuid) => slicedBufferString === uuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();
  
  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }
  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux` };
  }
  const portIndex = 18 + optLength + 1;
  const portRemote = dataView.getUint16(portIndex);
  const addressType = dataView.getUint8(portIndex + 2);
  let addressValue, addressLength, addressValueIndex;
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = portIndex + 3;
      addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = dataView.getUint8(portIndex + 3);
      addressValueIndex = portIndex + 4;
      addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      addressValueIndex = portIndex + 3;
      addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)).join(":");
      break;
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }
  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
  }
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    protocolVersion: new Uint8Array([version]),
    isUDP: command === 2
  };
}

// src/utils/crypto.js
function sha224(str) {
  function rightRotate(value, amount) {
    return value >>> amount | value << 32 - amount;
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let result = "";
  const words = [];
  const asciiBitLength = str.length * 8;
  let hash = [
    3238371032,
    914150663,
    812702999,
    4144912697,
    4290775857,
    1750603025,
    1694076839,
    3204075428
  ];
  const k = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ];
  let i, j;
  str += "\x80";
  while (str.length % 64 - 56) str += "\0";
  for (i = 0; i < str.length; i++) {
    j = str.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << (3 - i) % 4 * 8;
  }
  words[words.length] = asciiBitLength / maxWord | 0;
  words[words.length] = asciiBitLength;
  for (j = 0; j < words.length; ) {
    const w = words.slice(j, j += 16);
    const oldHash = hash.slice(0);
    for (i = 0; i < 64; i++) {
      if (i >= 16) {
        const w15 = w[i - 15], w2 = w[i - 2];
        w[i] = w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ w15 >>> 3) + w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ w2 >>> 10) | 0;
      }
      const a = hash[0], e = hash[4];
      const temp1 = hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) + (e & hash[5] ^ ~e & hash[6]) + k[i] + w[i];
      const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + (a & hash[1] ^ a & hash[2] ^ hash[1] & hash[2]);
      hash = [temp1 + temp2 | 0].concat(hash);
      hash[4] = hash[4] + temp1 | 0;
      hash.pop();
    }
    for (i = 0; i < 8; i++) {
      hash[i] = hash[i] + oldHash[i] | 0;
    }
  }
  for (i = 0; i < 7; i++) {
    const hex = hash[i];
    result += (hex >> 28 & 15).toString(16) + (hex >> 24 & 15).toString(16) + (hex >> 20 & 15).toString(16) + (hex >> 16 & 15).toString(16) + (hex >> 12 & 15).toString(16) + (hex >> 8 & 15).toString(16) + (hex >> 4 & 15).toString(16) + (hex & 15).toString(16);
  }
  return result;
}

// src/protocol/木马通道.js
function is木马通道Protocol(buffer, password) {
  if (buffer.byteLength < 58) {
    return false;
  }
  const bytes = new Uint8Array(buffer);
  if (bytes[56] !== 13 || bytes[57] !== 10) {
    return false;
  }
  try {
    const receivedPasswordHash = new TextDecoder().decode(bytes.slice(0, 56));
    const expectedPasswordHash = sha224(password);
    return receivedPasswordHash === expectedPasswordHash;
  } catch {
    return false;
  }
}
function process木马通道Header(buffer, password) {
  if (buffer.byteLength < 58) {
    return { hasError: true, message: "Invalid 木马通道 data: too short" };
  }
  const bytes = new Uint8Array(buffer);
  const dataView = new DataView(buffer);
  const receivedPasswordHash = new TextDecoder().decode(bytes.slice(0, 56));
  const expectedPasswordHash = sha224(password);
  if (receivedPasswordHash !== expectedPasswordHash) {
    return { hasError: true, message: "Invalid 木马通道 password" };
  }
  if (bytes[56] !== 13 || bytes[57] !== 10) {
    return { hasError: true, message: "Invalid 木马通道 header: missing CRLF" };
  }
  const command = bytes[58];
  if (command !== TROJAN_CMD_TCP && command !== TROJAN_CMD_UDP) {
    return { hasError: true, message: `Unsupported 木马通道 command: ${command}` };
  }
  const addressType = bytes[59];
  let addressValue, addressLength, addressValueIndex;
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = 60;
      if (buffer.byteLength < addressValueIndex + addressLength + 2) {
        return { hasError: true, message: "Invalid 木马通道 header: IPv4 address truncated" };
      }
      addressValue = Array.from(bytes.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = bytes[60];
      addressValueIndex = 61;
      if (buffer.byteLength < addressValueIndex + addressLength + 2) {
        return { hasError: true, message: "Invalid 木马通道 header: domain name truncated" };
      }
      addressValue = new TextDecoder().decode(bytes.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      addressValueIndex = 60;
      if (buffer.byteLength < addressValueIndex + addressLength + 2) {
        return { hasError: true, message: "Invalid 木马通道 header: IPv6 address truncated" };
      }
      addressValue = Array.from(
        { length: 8 },
        (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)
      ).join(":");
      break;
    default:
      return { hasError: true, message: `Invalid 木马通道 address type: ${addressType}` };
  }
  const portIndex = addressValueIndex + addressLength;
  if (buffer.byteLength < portIndex + 2) {
    return { hasError: true, message: "Invalid 木马通道 header: port truncated" };
  }
  const portRemote = dataView.getUint16(portIndex);
  const crlfIndex = portIndex + 2;
  if (buffer.byteLength < crlfIndex + 2) {
    return { hasError: true, message: "Invalid 木马通道 header: missing final CRLF" };
  }
  if (bytes[crlfIndex] !== 13 || bytes[crlfIndex + 1] !== 10) {
    return { hasError: true, message: "Invalid 木马通道 header: invalid final CRLF" };
  }
  const rawDataIndex = crlfIndex + 2;
  if (!addressValue) {
    return { hasError: true, message: `Address value is empty, address type is ${addressType}` };
  }
  
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType === 3 ? 2 : addressType,
    // Map 木马通道 type 3 (domain) to 虚空通道 type 2
    portRemote,
    rawDataIndex,
    isUDP: command === TROJAN_CMD_UDP
  };
}

// src/神奇通道/udp-handler.js
function canHandleUDP(config) {
  if (config.神奇通道Type === "虚空通道" && config.parsedVlessOutbound) {
    return true;
  }
  return false;
}
async function handleUDPOutbound(webSocket, protocolResponseHeader, addressType, addressRemote, portRemote, rawClientData, log, config) {
  if (config.神奇通道Type !== "虚空通道" || !config.parsedVlessOutbound) {
    
    safeCloseWebSocket(webSocket);
    return null;
  }
  
  const 虚空通道Result = await 虚空通道OutboundConnect(config.parsedVlessOutbound, 虚空通道_CMD_UDP, addressType, addressRemote, portRemote, rawClientData, log);
  if (!虚空通道Result) {
    
    safeCloseWebSocket(webSocket);
    return null;
  }
  let headerSent = false;
  虚空通道Result.readable.pipeTo(
    new WritableStream({
      write(data) {
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          return;
        }
        if (!headerSent && protocolResponseHeader) {
          const combined = new Uint8Array(protocolResponseHeader.length + data.length);
          combined.set(protocolResponseHeader, 0);
          combined.set(data, protocolResponseHeader.length);
          webSocket.send(combined.buffer);
          headerSent = true;
        } else {
          webSocket.send(data);
        }
      },
      close() {
        
        safeCloseWebSocket(webSocket);
      },
      abort(reason) {
        
        safeCloseWebSocket(webSocket);
      }
    })
  ).catch((err) => {
    
    safeCloseWebSocket(webSocket);
  });
  
  return 虚空通道Result.writable;
}

// src/handlers/websocket.js
async function protocolOverWSHandler(request, config, connect2) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWrapper = {
    value: null
  };
  let isDns = false;
  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns) {
        return await handleDNSQuery(chunk, webSocket, null, log, connect2);
      }
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      let protocolResult;
      let protocolType = "虚空通道";
      if (is木马通道Protocol(chunk, config.木马通道Password)) {
        protocolType = "木马通道";
        protocolResult = process木马通道Header(chunk, config.木马通道Password);
      } else {
        protocolResult = processProtocolHeader(chunk, config.用户标识);
      }
      const {
        hasError,
        message,
        addressType,
        portRemote = 443,
        addressRemote = "",
        rawDataIndex,
        protocolVersion = new Uint8Array([0, 0]),
        isUDP
      } = protocolResult;
      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} [${protocolType}]`;
      if (hasError) {
        throw new Error(message);
      }
      if (isUDP) {
        if (canHandleUDP(config)) {
          const protocolResponseHeader2 = protocolType === "木马通道" ? null : new Uint8Array([protocolVersion[0], 0]);
          const rawClientData2 = chunk.slice(rawDataIndex);
          const udpWritable = await handleUDPOutbound(
            webSocket,
            protocolResponseHeader2,
            addressType,
            addressRemote,
            portRemote,
            rawClientData2,
            log,
            config
          );
          if (udpWritable) {
            remoteSocketWrapper.value = { writable: udpWritable };
          }
          return;
        } else if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error("UDP 神奇通道 requires 虚空通道 outbound configuration");
        }
        return;
      }
      const protocolResponseHeader = protocolType === "木马通道" ? null : new Uint8Array([protocolVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      if (isDns) {
        return handleDNSQuery(rawClientData, webSocket, protocolResponseHeader, log, connect2);
      }
      handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log, config, connect2);
    },
    close() {
      
    },
    abort(reason) {
      );
    }
  })).catch((err) => {
    
  });
  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client
  });
}


// src/generators/subscription.js
function genSub(用户标识_path, hostname, 神奇通道IP, 木马通道Password = null) {
  const mainDomains = /* @__PURE__ */ new Set([
    hostname,
    // public domains
    "icook.hk",
    "japan.com",
    "malaysia.com",
    "russia.com",
    "singapore.com",
    "www.visa.com",
    "www.csgo.com",
    "www.shopify.com",
    "www.whatismyip.com",
    "www.ipget.net",
    // High frequency update sources
    "freeyx.cloudflare88.eu.org",
    // 1000ip/3min
    "cloudflare.182682.xyz",
    // 15ip/15min
    "cfip.cfcdn.vip",
    // 6ip/1day
    ...神奇通道IPs,
    // Manual update and unknown frequency
    "cf.0sm.com",
    "cloudflare-ip.mofashi.ltd",
    "cf.090227.xyz",
    "cf.zhetengsha.eu.org",
    "cloudflare.9jy.cc",
    "cf.zerone-cdn.pp.ua",
    "cfip.1323123.xyz",
    "cdn.tzpro.xyz",
    "cf.877771.xyz",
    "cnamefuckxxs.yuchen.icu",
    "cfip.xxxxxxxx.tk"
    // OTC maintained
  ]);
  const 用户标识Array = 用户标识_path.includes(",") ? 用户标识_path.split(",") : [用户标识_path];
  const 神奇通道IPArray = Array.isArray(神奇通道IP) ? 神奇通道IP : 神奇通道IP ? 神奇通道IP.includes(",") ? 神奇通道IP.split(",") : [神奇通道IP] : 神奇通道IPs;
  const randomPath = () => "/" + Math.random().toString(36).substring(2, 15) + "?ed=2048";
  const commonUrlPartHttp = `?encryption=none&security=none&fp=random&type=ws&host=${hostname}&path=${encodeURIComponent(randomPath())}#`;
  const commonUrlPartHttps = `?encryption=none&security=tls&sni=${hostname}&fp=random&type=ws&host=${hostname}&path=%2F%3Fed%3D2048#`;
  const result = 用户标识Array.flatMap((用户标识) => {
    let allUrls = [];
    if (!hostname.includes("pages.dev")) {
      mainDomains.forEach((domain) => {
        Array.from(HttpPort).forEach((port) => {
          const urlPart = `${hostname.split(".")[0]}-${domain}-HTTP-${port}`;
          const mainProtocolHttp = atob(pt) + "://" + 用户标识 + atob(at) + domain + ":" + port + commonUrlPartHttp + urlPart;
          allUrls.push(mainProtocolHttp);
        });
      });
    }
    mainDomains.forEach((domain) => {
      Array.from(HttpsPort).forEach((port) => {
        const urlPart = `${hostname.split(".")[0]}-${domain}-HTTPS-${port}`;
        const mainProtocolHttps = atob(pt) + "://" + 用户标识 + atob(at) + domain + ":" + port + commonUrlPartHttps + urlPart;
        allUrls.push(mainProtocolHttps);
      });
    });
    神奇通道IPArray.forEach((神奇通道Addr) => {
      const [神奇通道Host, 神奇通道Port = "443"] = 神奇通道Addr.split(":");
      const urlPart = `${hostname.split(".")[0]}-${神奇通道Host}-HTTPS-${神奇通道Port}`;
      const secondaryProtocolHttps = atob(pt) + "://" + 用户标识 + atob(at) + 神奇通道Host + ":" + 神奇通道Port + commonUrlPartHttps + urlPart + "-" + atob(ed);
      allUrls.push(secondaryProtocolHttps);
    });
    return allUrls;
  });
  const effective木马通道Password = 木马通道Password || 用户标识Array[0];
  const 木马通道Urls = generate木马通道Urls(effective木马通道Password, hostname, 神奇通道IPArray);
  return btoa([...result, ...木马通道Urls].join("\n"));
}
function generate木马通道Urls(password, hostname, 神奇通道IPArray) {
  const urls = [];
  const encodedPassword = encodeURIComponent(password);
  const commonParams = `?security=tls&type=ws&host=${hostname}&path=%2F%3Fed%3D2048&sni=${hostname}`;
  Array.from(HttpsPort).forEach((port) => {
    const urlPart = `${hostname.split(".")[0]}-木马通道-HTTPS-${port}`;
    const 木马通道Url = `${atob(木马通道Pt)}://${encodedPassword}@${hostname}:${port}${commonParams}#${urlPart}`;
    urls.push(木马通道Url);
  });
  神奇通道IPArray.forEach((神奇通道Addr) => {
    const [神奇通道Host, 神奇通道Port = "443"] = 神奇通道Addr.split(":");
    const urlPart = `${hostname.split(".")[0]}-${神奇通道Host}-木马通道-${神奇通道Port}`;
    const 木马通道Url = `${atob(木马通道Pt)}://${encodedPassword}@${神奇通道Host}:${神奇通道Port}${commonParams}#${urlPart}`;
    urls.push(木马通道Url);
  });
  return urls;
}
function gen木马通道Sub(password, hostname, 神奇通道IP) {
  const 神奇通道IPArray = Array.isArray(神奇通道IP) ? 神奇通道IP : 神奇通道IP ? 神奇通道IP.includes(",") ? 神奇通道IP.split(",") : [神奇通道IP] : 神奇通道IPs;
  const urls = generate木马通道Urls(password, hostname, 神奇通道IPArray);
  return btoa(urls.join("\n"));
}

// src/utils/parser.js
function parseVlessUrl(url) {
  if (!url || !url.startsWith("虚空通道://")) {
    return null;
  }
  try {
    const urlWithoutProtocol = url.slice(8).split("#")[0];
    const atIndex = urlWithoutProtocol.indexOf("@");
    if (atIndex === -1) return null;
    const uuid = urlWithoutProtocol.slice(0, atIndex);
    const rest = urlWithoutProtocol.slice(atIndex + 1);
    const [hostPort, queryString] = rest.split("?");
    let address, port;
    if (hostPort.startsWith("[")) {
      const bracketEnd = hostPort.indexOf("]");
      if (bracketEnd === -1) return null;
      address = hostPort.slice(1, bracketEnd);
      const portPart = hostPort.slice(bracketEnd + 1);
      if (portPart.startsWith(":")) {
        port = parseInt(portPart.slice(1), 10);
      } else {
        port = 443;
      }
    } else {
      const colonIndex = hostPort.lastIndexOf(":");
      if (colonIndex === -1) {
        address = hostPort;
        port = 443;
      } else {
        address = hostPort.slice(0, colonIndex);
        port = parseInt(hostPort.slice(colonIndex + 1), 10);
      }
    }
    if (isNaN(port)) port = 443;
    const params = {};
    if (queryString) {
      queryString.split("&").forEach((pair) => {
        const [key, value] = pair.split("=");
        if (key) {
          params[decodeURIComponent(key)] = decodeURIComponent(value || "");
        }
      });
    }
    const streamSettings = {
      network: params.type || "ws",
      security: params.security || "none"
    };
    if (streamSettings.network === "ws") {
      streamSettings.wsSettings = {
        path: params.path || "/"
      };
      if (params.host) {
        streamSettings.wsSettings.headers = { Host: params.host };
      }
    }
    if (streamSettings.security === "tls") {
      streamSettings.tlsSettings = {
        serverName: params.sni || params.host || address
      };
    }
    return { uuid, address, port, streamSettings };
  } catch (e) {
    
    return null;
  }
}
function 袜子五号AddressParser(address) {
  let [latter, former] = address.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error("Invalid SOCKS address format");
    }
    [username, password] = formers;
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error("Invalid SOCKS address format");
  }
  hostname = latters.join(":");
  const regex = /^\[.*\]$/;
  if (hostname.includes(":") && !regex.test(hostname)) {
    throw new Error("Invalid SOCKS address format");
  }
  return {
    username,
    password,
    hostname,
    port
  };
}
function handle神奇通道Config(PROXYIP) {
  if (PROXYIP) {
    const 神奇通道Addresses = PROXYIP.split(",").map((addr) => addr.trim());
    const selected神奇通道 = selectRandomAddress(神奇通道Addresses);
    const [ip, port = "443"] = selected神奇通道.split(":");
    return { ip, port };
  } else {
    const default神奇通道 = 神奇通道IPs[Math.floor(Math.random() * 神奇通道IPs.length)];
    const port = default神奇通道.includes(":") ? default神奇通道.split(":")[1] : "443";
    const ip = default神奇通道.split(":")[0];
    return { ip, port };
  }
}
function selectRandomAddress(addresses) {
  const addressArray = typeof addresses === "string" ? addresses.split(",").map((addr) => addr.trim()) : addresses;
  return addressArray[Math.floor(Math.random() * addressArray.length)];
}
function parseEncodedQueryParams(pathname) {
  const params = {};
  if (pathname.includes("%3F")) {
    const encodedParamsMatch = pathname.match(/%3F(.+)$/);
    if (encodedParamsMatch) {
      const encodedParams = encodedParamsMatch[1];
      const paramPairs = encodedParams.split("&");
      for (const pair of paramPairs) {
        const [key, value] = pair.split("=");
        if (value) params[key] = decodeURIComponent(value);
      }
    }
  }
  return params;
}
function decode神奇通道Address(address) {
  if (!address.includes("@")) return address;
  const atIndex = address.lastIndexOf("@");
  let userPass = address.substring(0, atIndex).replace(/%3D/gi, "=");
  const hostPort = address.substring(atIndex + 1);
  if (/^[A-Za-z0-9+/]+=*$/.test(userPass) && !userPass.includes(":")) {
    try {
      userPass = atob(userPass);
    } catch (e) {
    }
  }
  return `${userPass}@${hostPort}`;
}
function parsePath神奇通道Params(pathname) {
  const result = {
    神奇通道ip: null,
    袜子五号: null,
    http: null,
    虚空通道: null,
    global神奇通道: false
  };
  const 神奇通道ipMatch = pathname.match(/^\/(神奇通道ip[.=]|pyip=|ip=)([^/?#]+)/i);
  if (神奇通道ipMatch) {
    const prefix = 神奇通道ipMatch[1].toLowerCase();
    const value = 神奇通道ipMatch[2];
    result.神奇通道ip = prefix === "神奇通道ip." ? `神奇通道ip.${value}` : value;
    return result;
  }
  const socksUrlMatch = pathname.match(/^\/(袜子五号?):\/\/?([^/?#]+)/i);
  if (socksUrlMatch) {
    result.袜子五号 = decode神奇通道Address(socksUrlMatch[2]);
    result.global神奇通道 = true;
    return result;
  }
  const socksEqMatch = pathname.match(/^\/(g?s5|g?袜子五号?)=([^/?#]+)/i);
  if (socksEqMatch) {
    const type = socksEqMatch[1].toLowerCase();
    result.袜子五号 = socksEqMatch[2];
    if (type.startsWith("g")) {
      result.global神奇通道 = true;
    }
    return result;
  }
  const httpUrlMatch = pathname.match(/^\/http:\/\/?([^/?#]+)/i);
  if (httpUrlMatch) {
    result.http = decode神奇通道Address(httpUrlMatch[1]);
    result.global神奇通道 = true;
    return result;
  }
  const httpEqMatch = pathname.match(/^\/(g?http)=([^/?#]+)/i);
  if (httpEqMatch) {
    const type = httpEqMatch[1].toLowerCase();
    result.http = httpEqMatch[2];
    if (type.startsWith("g")) {
      result.global神奇通道 = true;
    }
    return result;
  }
  const 虚空通道UrlMatch = pathname.match(/^\/虚空通道:\/\/([^/?#]+)/i);
  if (虚空通道UrlMatch) {
    const 虚空通道Path = pathname.slice(1);
    result.虚空通道 = 虚空通道Path;
    result.global神奇通道 = true;
    return result;
  }
  const 虚空通道EqMatch = pathname.match(/^\/(g?虚空通道)=([^/?#]+)/i);
  if (虚空通道EqMatch) {
    const type = 虚空通道EqMatch[1].toLowerCase();
    result.虚空通道 = decodeURIComponent(虚空通道EqMatch[2]);
    if (type.startsWith("g")) {
      result.global神奇通道 = true;
    }
    return result;
  }
  return result;
}

// src/handlers/main.js
if (!isValid序列号(defaultUserID)) {
  throw new Error("uuid is not valid");
}
async function handleRequest(request, env, ctx, connect2) {
  try {
    const { 序列号, PROXYIP, 袜子五号, 袜子五号_RELAY, 木马密码 } = env;
    const url = new URL(request.url);
    const requestConfig = createRequestConfig(env);
    let urlPROXYIP = url.searchParams.get("神奇通道ip");
    let url袜子五号 = url.searchParams.get("袜子五号");
    const urlGlobal神奇通道 = url.searchParams.has("global神奇通道");
    if (!urlPROXYIP && !url袜子五号) {
      const encodedParams = parseEncodedQueryParams(url.pathname);
      urlPROXYIP = urlPROXYIP || encodedParams.神奇通道ip;
      url袜子五号 = url袜子五号 || encodedParams.袜子五号;
    }
    const pathParams = parsePath神奇通道Params(url.pathname);
    if (!urlPROXYIP && pathParams.神奇通道ip) {
      urlPROXYIP = pathParams.神奇通道ip;
    }
    if (!url袜子五号 && pathParams.袜子五号) {
      url袜子五号 = pathParams.袜子五号;
    }
    const enableGlobal神奇通道 = pathParams.global神奇通道 || urlGlobal神奇通道;
    let urlHTTP = url.searchParams.get("http") || pathParams.http;
    if (urlPROXYIP) {
      const 神奇通道Pattern = /^([a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/;
      const 神奇通道Addresses = urlPROXYIP.split(",").map((addr) => addr.trim());
      const isValid = 神奇通道Addresses.every((addr) => 神奇通道Pattern.test(addr));
      if (!isValid) {
        console.warn("Invalid 神奇通道ip format:", urlPROXYIP);
        urlPROXYIP = null;
      }
    }
    if (url袜子五号) {
      const 袜子五号Pattern = /^(([^:@]+:[^:@]+@)?[a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$/;
      const 袜子五号Addresses = url袜子五号.split(",").map((addr) => addr.trim());
      const isValid = 袜子五号Addresses.every((addr) => 袜子五号Pattern.test(addr));
      if (!isValid) {
        console.warn("Invalid 袜子五号 format:", url袜子五号);
        url袜子五号 = null;
      }
    }
    requestConfig.袜子五号Address = url袜子五号 || requestConfig.袜子五号Address;
    requestConfig.global神奇通道 = enableGlobal神奇通道 || requestConfig.袜子五号Relay;
    
    const 神奇通道Config = handle神奇通道Config(urlPROXYIP || PROXYIP);
    requestConfig.神奇通道IP = 神奇通道Config.ip;
    requestConfig.神奇通道Port = 神奇通道Config.port;
    
    let url虚空通道 = url.searchParams.get("虚空通道") || pathParams.虚空通道;
    if (url虚空通道 || requestConfig.虚空通道Outbound) {
      try {
        const 虚空通道Url = url虚空通道 || requestConfig.虚空通道Outbound;
        const parsed = parseVlessUrl(虚空通道Url);
        if (parsed) {
          requestConfig.parsedVlessOutbound = parsed;
          requestConfig.神奇通道Type = "虚空通道";
          
        }
      } catch (err) {
        );
      }
    }
    if (requestConfig.神奇通道Type !== "虚空通道") {
      if (urlHTTP) {
        try {
          const selected神奇通道 = selectRandomAddress(urlHTTP);
          requestConfig.parsed神奇通道Address = 袜子五号AddressParser(selected神奇通道);
          requestConfig.神奇通道Type = "http";
        } catch (err) {
          );
        }
      } else if (requestConfig.袜子五号Address) {
        try {
          const selected神奇通道 = selectRandomAddress(requestConfig.袜子五号Address);
          requestConfig.parsed神奇通道Address = 袜子五号AddressParser(selected神奇通道);
          requestConfig.神奇通道Type = "袜子五号";
        } catch (err) {
          );
        }
      }
    }
    const 用户标识s = requestConfig.用户标识.includes(",") ? requestConfig.用户标识.split(",").map((id) => id.trim()) : [requestConfig.用户标识];
    const host = request.headers.get("Host");
    const requestedPath = url.pathname.substring(1);
    const matchingUserID = 用户标识s.length === 1 ? requestedPath === 用户标识s[0] || requestedPath === `sub/${用户标识s[0]}` || requestedPath === `bestip/${用户标识s[0]}` || requestedPath === `木马通道/${用户标识s[0]}` ? 用户标识s[0] : null : 用户标识s.find((id) => {
      const patterns = [id, `sub/${id}`, `bestip/${id}`, `木马通道/${id}`];
      return patterns.some((pattern) => requestedPath.startsWith(pattern));
    });
    if (request.headers.get("Upgrade") !== "websocket") {
      if (url.pathname === "/cf") {
        return new Response(JSON.stringify(request.cf, null, 4), {
          status: 200,
          headers: { "Content-Type": "application/json;charset=utf-8" }
        });
      }
      if (matchingUserID) {
        if (url.pathname === `/${matchingUserID}` || url.pathname === `${matchingUserID}`) {
          const isSubscription = url.pathname.startsWith("");
          const 神奇通道Addresses = urlPROXYIP ? urlPROXYIP.split(",").map((addr) => addr.trim()) : PROXYIP ? PROXYIP.split(",").map((addr) => addr.trim()) : 神奇通道IPs;
          const 木马通道Password = 木马密码 || matchingUserID;
          const content = isSubscription ? genSub(matchingUserID, host, 神奇通道Addresses, 木马通道Password) : getConfig(matchingUserID, host, 神奇通道Addresses, 木马通道Password);
          return new Response(content, {
            status: 200,
            headers: {
              "Content-Type": isSubscription ? "text/plain;charset=utf-8" : ""
            }
          });
        } else if (url.pathname === `/木马通道/${matchingUserID}`) {
          const 神奇通道Addresses = urlPROXYIP ? urlPROXYIP.split(",").map((addr) => addr.trim()) : PROXYIP ? PROXYIP.split(",").map((addr) => addr.trim()) : 神奇通道IPs;
          const 木马通道Password = 木马密码 || matchingUserID;
          const content = gen木马通道Sub(木马通道Password, host, 神奇通道Addresses);
          return new Response(content, {
            status: 200,
            headers: { "Content-Type": "text/plain;charset=utf-8" }
          });
        } else if (url.pathname === `${matchingUserID}`) {
          return fetch(`https://bestip.06151953.xyz/auto?host=${host}&uuid=${matchingUserID}&path=/`, { headers: request.headers });
        }
      }
      return handleDefaultPath(url, request);
    } else {
      return await protocolOverWSHandler(request, requestConfig, connect2);
    }
  } catch (err) {
    return new Response(err.toString());
  }
}

// src/index.js
var index_default = {
  /**
   * Main fetch handler for Cloudflare Worker
   * @param {import("@cloudflare/workers-types").Request} request - The incoming request
   * @param {{序列号: string, PROXYIP: string, 袜子五号: string, 袜子五号_RELAY: string}} env - Environment variables
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx - Execution context
   * @returns {Promise<Response>} Response object
   */
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx, connect);
  }
};
export {
  index_default as default
};
