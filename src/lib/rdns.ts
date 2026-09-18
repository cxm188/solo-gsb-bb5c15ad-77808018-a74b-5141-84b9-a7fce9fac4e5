// 反向 DNS 区域文件生成：/24 网段输出标准 in-addr.arpa 区域 PTR 记录；
// /25～/30 网段按 RFC 2317 输出「父区域 CNAME 片段 + 子区域 PTR」两段文本。
// 本模块只读取当前规划结果与主机登记，绝不修改规划、基线、路由汇总、登记与导出。
//
// 规则：
//   1. 仅纳入所选网段内「当前有效」的主机登记（地址仍在所属网段可用范围内、不重复）；
//      失效登记不参与生成，也不产生错误；
//   2. 设备名必须是合法绝对域名（FQDN）：至少两个标签，标签仅含字母 / 数字 / 连字符、
//      不以连字符开头或结尾、单标签 ≤ 63 字符、全长 ≤ 253 字符；允许显式结尾点；
//      统一规范为小写（DNS 大小写不敏感）；
//   3. 域名在网段内唯一（小写归一后比较）：重复域名或不合法名称逐条报错并停止整体生成；
//   4. /25～/30 的子区域以网段起止末位命名（如 16-19.10.168.192.in-addr.arpa）；
//   5. 记录一律按 IPv4 数值升序；PTR / CNAME 目标均以结尾点写出（绝对形式）。

import { intToIp } from './ip'
import { allocatableSegments, reconcileHosts, type AllocSegment } from './hosts'
import type { HostAssignment, PlanResult } from './types'

/** 支持生成反向区域的网段前缀范围：/24 标准区域；/25～/30 走 RFC 2317 */
export const RDNS_MIN_PREFIX = 24
export const RDNS_MAX_PREFIX = 30

/** 一条参与生成的有效登记及其校验视图（按 IPv4 升序排列，序号为 1 基） */
export interface RdnsEntry {
  index: number
  assignment: HostAssignment
  ip: string
  address: number
  /** 规范化后的绝对域名（小写、无结尾点）；名称非法时为 null */
  domain: string | null
  /** 本条目的错误（非法名称 / 重复域名）；无错为空数组 */
  errors: string[]
}

/** 拍平后的单条错误（含序号与 IP 定位） */
export interface RdnsError {
  index: number
  ip: string
  message: string
}

/** 一份可复制 / 下载的区域文件文本 */
export interface RdnsZoneFile {
  /** zone：/24 或子区域完整区域文件；parent：RFC 2317 父区域 CNAME 片段；child：RFC 2317 子区域文件 */
  kind: 'zone' | 'parent' | 'child'
  /** 区域名（如 10.168.192.in-addr.arpa 或 16-19.10.168.192.in-addr.arpa） */
  zone: string
  /** 面板展示标题 */
  title: string
  /** 记录数 */
  records: number
  /** 区域文件文本（含注释头与 $ORIGIN；有错误时不会产生文件） */
  text: string
}

export interface RdnsResult {
  segment: AllocSegment
  /** 所属 /24 父区域名（如 10.168.192.in-addr.arpa） */
  parentZone: string
  /** /24 时为 null；/25～/30 为子区域名（如 16-19.10.168.192.in-addr.arpa） */
  childZone: string | null
  /** 参与校验的全部有效登记（按 IPv4 升序） */
  entries: RdnsEntry[]
  /** 拍平后的全部错误（非空时停止整体生成，files 为空） */
  errors: RdnsError[]
  /** 可预览 / 复制 / 下载的区域文件（有错误或无有效登记时为空） */
  files: RdnsZoneFile[]
}

/** 网段是否可生成反向区域（成功分配的固定 / 自动网段且前缀在 /24～/30） */
export function isRdnsCapableSegment(s: AllocSegment): boolean {
  return s.prefix >= RDNS_MIN_PREFIX && s.prefix <= RDNS_MAX_PREFIX
}

/** 当前规划中可生成反向区域的网段（按地址升序，与规划结果顺序一致） */
export function rdnsCapableSegments(result: PlanResult): AllocSegment[] {
  return allocatableSegments(result).filter(isRdnsCapableSegment)
}

/** 在当前规划中按需求稳定 ID 解析目标网段；失效（删除 / 分配失败 / 前缀越出 /24～/30）返回 null */
export function resolveRdnsSegment(result: PlanResult, ownerId: string): AllocSegment | null {
  if (!ownerId) return null
  return rdnsCapableSegments(result).find((s) => s.ownerId === ownerId) ?? null
}

/**
 * 校验设备名是否为合法绝对域名（FQDN）。
 * 通过时返回规范名（小写、去掉可选的结尾点）；失败时返回面向用户的原因。
 */
export function normalizeAbsoluteDomain(raw: string): { name: string } | { error: string } {
  const trimmed = raw.trim()
  if (!trimmed) return { error: '设备名为空，不是合法绝对域名' }
  // 允许显式的根域结尾点（绝对形式），校验与规范化时去掉
  const body = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed
  if (!body) return { error: `“${trimmed}”不是合法绝对域名` }
  if (!body.includes('.')) {
    return { error: `“${trimmed}”不是绝对域名：需为含域后缀的完整域名（如 host1.example.com）` }
  }
  if (body.length > 253) {
    return { error: `“${trimmed}”总长 ${body.length} 个字符，超过域名上限 253` }
  }
  for (const label of body.split('.')) {
    if (label.length === 0) {
      return { error: `“${trimmed}”含空标签（连续点号），不是合法绝对域名` }
    }
    if (label.length > 63) {
      return { error: `“${trimmed}”的标签“${label}”为 ${label.length} 个字符，超过单标签上限 63` }
    }
    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return { error: `“${trimmed}”的标签“${label}”含非法字符（仅允许字母、数字与连字符）` }
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return { error: `“${trimmed}”的标签“${label}”以连字符开头或结尾，不是合法绝对域名` }
    }
  }
  return { name: body.toLowerCase() }
}

/** 地址所属 /24 的 in-addr.arpa 区域名（取前三个八位组反转） */
export function parentZoneOf(address: number): string {
  const o1 = (address >>> 24) & 255
  const o2 = (address >>> 16) & 255
  const o3 = (address >>> 8) & 255
  return `${o3}.${o2}.${o1}.in-addr.arpa`
}

/** 记录行格式化：所有者名按列宽对齐，类型固定 5 字符宽，目标以结尾点写出 */
function formatRecords(rows: Array<[string, string, string]>): string {
  const width = Math.max(...rows.map(([owner]) => owner.length))
  return rows
    .map(([owner, type, target]) => `${owner.padEnd(width)} IN ${type.padEnd(5)} ${target}`)
    .join('\n')
}

function zoneHeader(lines: string[]): string {
  return lines.map((l) => `; ${l}`).join('\n')
}

/**
 * 依据当前规划与登记，为所选网段生成反向 DNS 区域视图。
 * 任一有效登记的名称非法或域名重复时：逐条收集错误并停止整体生成（files 为空）。
 * 规划或登记变化后由调用方重新执行本函数，输出随之实时刷新。
 */
export function buildReverseZones(
  assignments: HostAssignment[],
  result: PlanResult,
  segment: AllocSegment,
): RdnsResult {
  const parentZone = parentZoneOf(segment.start)
  const childZone =
    segment.prefix === 24
      ? null
      : `${segment.start & 255}-${segment.end & 255}.${parentZone}`

  // 当前有效且属于该网段的登记，按 IPv4 数值升序
  const { rows } = reconcileHosts(assignments, result)
  const validRows = rows
    .filter((r) => r.valid && r.assignment.ownerId === segment.ownerId)
    .sort((a, b) => a.assignment.address - b.assignment.address)

  const entries: RdnsEntry[] = []
  const errors: RdnsError[] = []
  // 规范域名 -> 首次出现的序号（重复域名只放过第一条，其余报错）
  const firstOfDomain = new Map<string, number>()

  validRows.forEach((row, i) => {
    const index = i + 1
    const { assignment } = row
    const ip = intToIp(assignment.address)
    const entryErrors: string[] = []
    let domain: string | null = null

    const parsed = normalizeAbsoluteDomain(assignment.name)
    if ('error' in parsed) {
      entryErrors.push(parsed.error)
    } else {
      domain = parsed.name
      const first = firstOfDomain.get(domain)
      if (first !== undefined) {
        const firstIp = intToIp(validRows[first - 1].assignment.address)
        entryErrors.push(`域名 ${domain} 与第 ${first} 条（${firstIp}）重复（域名必须唯一）`)
      } else {
        firstOfDomain.set(domain, index)
      }
    }

    for (const message of entryErrors) errors.push({ index, ip, message })
    entries.push({ index, assignment, ip, address: assignment.address, domain, errors: entryErrors })
  })

  const files: RdnsZoneFile[] = []
  if (errors.length === 0 && entries.length > 0) {
    // 无错误时全部条目都有规范域名
    const named = entries.filter((e): e is RdnsEntry & { domain: string } => e.domain !== null)
    const segLabel = `${segment.cidr}（${segment.name}）`

    if (segment.prefix === 24) {
      // 标准 in-addr.arpa 区域：所有者名为末位八位组
      const records: Array<[string, string, string]> = named.map((e) => [
        String(e.address & 255),
        'PTR',
        `${e.domain}.`,
      ])
      files.push({
        kind: 'zone',
        zone: parentZone,
        title: `区域文件 ${parentZone}`,
        records: records.length,
        text: [
          zoneHeader([
            '反向 DNS 区域文件（PTR 记录）',
            `网段：${segLabel}`,
            `区域：${parentZone}`,
          ]),
          `$ORIGIN ${parentZone}.`,
          formatRecords(records),
        ].join('\n'),
      })
    } else {
      // RFC 2317：父区域 CNAME 片段 + 子区域 PTR 文件
      const child = childZone as string
      const cnameRecords: Array<[string, string, string]> = named.map((e) => {
        const last = String(e.address & 255)
        return [last, 'CNAME', `${last}.${child}.`]
      })
      const ptrRecords: Array<[string, string, string]> = named.map((e) => [
        String(e.address & 255),
        'PTR',
        `${e.domain}.`,
      ])
      files.push({
        kind: 'parent',
        zone: parentZone,
        title: `父区域 CNAME 片段（并入 ${parentZone}）`,
        records: cnameRecords.length,
        text: [
          zoneHeader([
            'RFC 2317 父区域 CNAME 片段',
            `网段：${segLabel}`,
            `将以下记录并入父区域 ${parentZone}`,
          ]),
          `$ORIGIN ${parentZone}.`,
          formatRecords(cnameRecords),
        ].join('\n'),
      })
      files.push({
        kind: 'child',
        zone: child,
        title: `子区域文件 ${child}`,
        records: ptrRecords.length,
        text: [
          zoneHeader([
            'RFC 2317 子区域文件（PTR 记录）',
            `网段：${segLabel}`,
            `子区域：${child}`,
          ]),
          `$ORIGIN ${child}.`,
          formatRecords(ptrRecords),
        ].join('\n'),
      })
    }
  }

  return { segment, parentZone, childZone, entries, errors, files }
}

/** 下载为 .zone 文件（Blob 方式，纯前端，不经过任何服务器） */
export function downloadRdnsZone(file: RdnsZoneFile) {
  const blob = new Blob([`${file.text}\n`], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const prefix =
    file.kind === 'parent' ? 'reverse-parent' : file.kind === 'child' ? 'reverse-child' : 'reverse'
  a.href = url
  a.download = `${prefix}-${file.zone}-${stamp}.zone`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
