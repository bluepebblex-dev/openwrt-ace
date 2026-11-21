/* 质量卡异常时段判定单测（纯 node，无依赖）。
 * 直接从上线的 overview.htm 里抠出 aceAnomalyWindows 源码执行，
 * 保证测的就是生产代码，不存在测试与实现两份逻辑漂移。
 * 用法: node tests/quality-anomaly.test.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const HTM = path.join(__dirname, '..', 'files', 'usr', 'lib', 'lua', 'luci', 'view', 'ace', 'overview.htm');
const src = fs.readFileSync(HTM, 'utf8');

// 提取 function aceAnomalyWindows(...) { ... } 的源码（BigInt-free，括号配对）
function extractFunction(text, name) {
  const sig = 'function ' + name + '(';
  const start = text.indexOf(sig);
  assert.ok(start >= 0, 'overview.htm 里找不到 ' + name);
  let i = text.indexOf('{', start);
  assert.ok(i > start, name + ' 找不到函数体起始 {');
  let depth = 0, inStr = null, esc = false;
  for (; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return text.slice(start, i + 1); }
  }
  throw new Error(name + ' 函数体未闭合');
}

const fnSrc = extractFunction(src, 'aceAnomalyWindows');
// eslint-disable-next-line no-eval
const aceAnomalyWindows = eval('(' + fnSrc + ')');

// ---- 测试夹具构造 ----
const AT = 1763700000; // 任意固定时刻；t0 = AT - 86400
const H = 3600;
// 生成 24 小时 × 4 站的数据。baseline: 外国站点 200ms，国内 20ms。
function makeRows(opts = {}) {
  const rows = [];
  const foreign = ['youtube', 'google', 'github'];
  const fgBase = opts.fgBase ?? 200;
  const cnBase = opts.cnBase ?? 20;
  for (let h = 0; h < 24; h++) {
    for (let k = 0; k < 2; k++) { // 每小时每站 2 个采样，外国 6 条 / 国内 2 条
      const ts = AT - 86400 + h * H + k * 300;
      for (const site of foreign) {
        let ms = fgBase;
        if (opts.fgHot && opts.fgHot.includes(h)) ms = fgBase * 2; // > 1.3×
        rows.push({ ts, site, ms });
      }
      let cn = cnBase;
      if (opts.cnHot && opts.cnHot.includes(h)) cn = cnBase * 2;
      rows.push({ ts, site: 'baidu', ms: cn });
    }
  }
  return rows;
}

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok  ' + name); }
  catch (e) { console.error('  FAIL ' + name + '\n       ' + e.message); process.exitCode = 1; }
}

console.log('quality-anomaly 单测（源码来自 overview.htm）');

test('全平稳：无异常窗口', () => {
  assert.deepStrictEqual(aceAnomalyWindows(makeRows(), AT), []);
});

test('仅外国线尖峰（≥1.3×）：判为跨境波动 cross', () => {
  const w = aceAnomalyWindows(makeRows({ fgHot: [19, 20] }), AT);
  assert.ok(w.length >= 1, '应检出至少一个窗口');
  assert.ok(w.some(x => x.kind === 'cross'), '应含 cross');
  assert.ok(!w.some(x => x.kind === 'local'), '不应误报本地拥塞');
});

test('仅国内对照尖峰：判为本地拥塞 local', () => {
  const w = aceAnomalyWindows(makeRows({ cnHot: [3] }), AT);
  assert.ok(w.some(x => x.kind === 'local'), '应含 local');
  assert.ok(!w.some(x => x.kind === 'cross'), '不应误报跨境波动');
});

test('国内+外国同时尖峰：本地拥塞优先（不重复报 cross）', () => {
  const w = aceAnomalyWindows(makeRows({ cnHot: [10], fgHot: [10] }), AT);
  const hit = w.find(x => x.h0 <= 10 && x.h1 >= 10);
  assert.ok(hit, '应检出覆盖第 10 小时的窗口');
  assert.strictEqual(hit.kind, 'local', '本地+跨境同时高时归为 local');
});

test('相邻同类型小时合并为连续窗口', () => {
  const w = aceAnomalyWindows(makeRows({ fgHot: [19, 20, 21] }), AT);
  const cross = w.find(x => x.kind === 'cross');
  assert.ok(cross, '应有 cross 窗口');
  assert.ok(cross.h1 - cross.h0 + 1 >= 3, '应合并成至少 3 小时宽的窗口，实际 ' + JSON.stringify(cross));
});

test('样本 < 4 的小时不判定', () => {
  const rows = makeRows();
  // 第 5 小时只保留 1 条样本（外国），并抬到 3 倍——但单桶 < 4 条不应判异常
  let seen = 0;
  const kept = rows.filter(r => {
    const h = Math.floor((r.ts - (AT - 86400)) / H);
    if (h === 5) {
      if (seen === 0 && r.site === 'youtube') { seen++; return true; }
      return false;
    }
    return true;
  });
  for (const r of kept) {
    const h = Math.floor((r.ts - (AT - 86400)) / H);
    if (h === 5) r.ms = 600;
  }
  assert.strictEqual(seen, 1, '夹具：第 5 小时应只剩 1 条');
  const w = aceAnomalyWindows(kept, AT);
  assert.ok(!w.some(x => x.h0 <= 5 && x.h1 >= 5), '稀疏样本小时不应被判异常');
});

test('基准样本不足（某站 < 4 条）：整体不判，返回空', () => {
  const rows = [];
  for (let i = 0; i < 3; i++) rows.push({ ts: AT - 86400 + i * H, site: 'baidu', ms: 20 });
  for (let i = 0; i < 20; i++) rows.push({ ts: AT - 86400 + i * 3600, site: 'youtube', ms: 200 });
  assert.deepStrictEqual(aceAnomalyWindows(rows, AT), []);
});

test('异常 ms（负数/NaN/字符串）被忽略，不污染基准', () => {
  const rows = makeRows();
  rows.push({ ts: AT - 3600, site: 'youtube', ms: -1 });
  rows.push({ ts: AT - 3600, site: 'youtube', ms: NaN });
  rows.push({ ts: AT - 3600, site: 'youtube', ms: '999999' });
  assert.deepStrictEqual(aceAnomalyWindows(rows, AT), []);
});

test('t0 之外（>24h 前）的样本不计入小时桶', () => {
  const rows = makeRows();
  rows.push({ ts: AT - 86400 - 7200, site: 'youtube', ms: 99999 }); // 26h 前
  const w = aceAnomalyWindows(rows, AT);
  assert.ok(!w.some(x => x.h0 === -1 || x.h1 === -1), '不应产生负小时窗口');
});

console.log('\n' + passed + ' tests passed');
