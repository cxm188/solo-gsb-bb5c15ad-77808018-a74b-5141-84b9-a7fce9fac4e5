import { useMemo, useState } from 'react'
import { allocatableSegments } from '../lib/hosts'
import {
  buildReverseZones,
  downloadRdnsZone,
  rdnsCapableSegments,
  resolveRdnsSegment,
} from '../lib/rdns'
import type { HostAssignment, PlanResult } from '../lib/types'

interface Props {
  result: PlanResult
  assignments: HostAssignment[]
  segmentId: string
  onSegmentChange: (id: string) => void
}

const KIND_LABEL = { fixed: '固定', auto: '自动' } as const

/** 复制到剪贴板；非安全上下文（无 navigator.clipboard）时回退到临时 textarea */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // 落到回退方案
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

/** 反向 DNS 区域文件面板：/24 输出标准 in-addr.arpa PTR；/25～/30 按 RFC 2317 输出父区域 CNAME + 子区域 PTR */
export default function ReverseDnsPanel({ result, assignments, segmentId, onSegmentChange }: Props) {
  const [copiedZone, setCopiedZone] = useState<string | null>(null)

  const invalid = result.inputErrors.length > 0
  // 全部成功分配的固定 / 自动网段与其中可生成反向区域（/24～/30）的子集（按地址升序）
  const allocatable = useMemo(
    () => (invalid ? [] : allocatableSegments(result)),
    [result, invalid],
  )
  const capable = useMemo(() => (invalid ? [] : rdnsCapableSegments(result)), [result, invalid])

  // 选中的网段在当前规划中失效（删除 / 分配失败 / 前缀越出 /24～/30）时暂停结果
  const segment = useMemo(() => resolveRdnsSegment(result, segmentId), [result, segmentId])
  const segmentMissing = !invalid && allocatable.length > 0 && segmentId !== '' && !segment

  // 网段、登记或规划任意变化后实时重算；任一错误都使整体停止生成（files 为空）
  const built = useMemo(
    () => (segment ? buildReverseZones(assignments, result, segment) : null),
    [assignments, result, segment],
  )

  async function handleCopy(key: string, text: string) {
    const ok = await copyText(text)
    if (ok) {
      setCopiedZone(key)
      window.setTimeout(() => setCopiedZone(null), 2000)
    }
  }

  const errors = built?.errors ?? []

  return (
    <div className="panel rdns-panel">
      <h2>⑧ 反向 DNS 区域文件（in-addr.arpa PTR / RFC 2317）</h2>
      <p className="subtitle" style={{ marginBottom: 10 }}>
        选择一个当前<strong>成功分配</strong>的固定 / 自动网段（前缀 /24～/30），读取其中
        <strong>当前有效</strong>且设备名为<strong>合法绝对域名</strong>的主机登记生成反向解析文本：
        <code className="mono opt121-inline-code">/24</code> 生成标准 in-addr.arpa 区域的 PTR 记录；
        <code className="mono opt121-inline-code">/25～/30</code> 按 RFC 2317 为每条登记生成
        <strong>父区域 CNAME</strong> 与<strong>子区域 PTR</strong> 两段文本，子区域以网段起止末位命名
        （如 <code className="mono opt121-inline-code">16-19.10.168.192.in-addr.arpa</code>）。
        记录按 IPv4 升序；<strong>重复域名或不合法名称逐条报错并停止整体生成</strong>。
        网段迁移、登记增删或改址后实时重算；本面板只读取规划与登记，不做任何修改。
      </p>

      {invalid && (
        <div className="summary-disabled-note">
          输入非法（请先修正左侧错误），反向区域生成已暂停；网段选择与全部登记均已保留，修正后自动恢复。
        </div>
      )}
      {!invalid && allocatable.length === 0 && (
        <div className="summary-disabled-note">当前没有成功分配的固定或自动网段，暂无可生成反向区域的网段。</div>
      )}
      {!invalid && allocatable.length > 0 && capable.length === 0 && (
        <div className="summary-disabled-note">
          当前成功分配的网段前缀均不在 /24～/30 范围内（大于 /24 的网段需拆为多个 /24 区域，本面板暂不支持）。
        </div>
      )}
      {segmentMissing && (
        <div className="summary-disabled-note">
          已选择的网段在当前规划中已失效（被删除、分配失败或前缀越出 /24～/30），结果已暂停；登记均已保留，重新选择有效网段后恢复生成。
        </div>
      )}

      <div className="rdns-segment-row">
        <label className="field-label" htmlFor="rdns-segment">
          目标网段（仅列出 /24～/30 的固定 / 自动网段）
        </label>
        <select
          id="rdns-segment"
          className="opt121-select"
          value={segmentId}
          onChange={(e) => {
            setCopiedZone(null)
            onSegmentChange(e.target.value)
          }}
        >
          <option value="">— 请选择网段 —</option>
          {capable.map((seg) => (
            <option key={seg.ownerId} value={seg.ownerId}>
              {`[${KIND_LABEL[seg.kind]}] ${seg.name}　${seg.cidr}（可用 ${seg.firstUsable} ~ ${seg.lastUsable}）`}
            </option>
          ))}
        </select>
      </div>

      {built && (
        <>
          <div className="rdns-zone-meta mono">
            {built.childZone === null ? (
              <>标准区域：{built.parentZone}（PTR 记录按 IPv4 升序）</>
            ) : (
              <>
                RFC 2317：父区域 {built.parentZone}（CNAME）＋ 子区域 {built.childZone}（PTR）
              </>
            )}
          </div>

          {built.entries.length === 0 ? (
            <div className="dnsmasq-empty">
              该网段暂无当前有效的主机登记：请先在「⑥ 主机地址分配」中为该网段登记设备。
            </div>
          ) : (
            <>
              <table className="host-table rdns-entry-table">
                <thead>
                  <tr>
                    <th className="rdns-idx">#</th>
                    <th className="host-addr">IPv4</th>
                    <th className="host-device-name">设备名（绝对域名）</th>
                    <th>状态</th>
                  </tr>
                </thead>
                <tbody>
                  {built.entries.map((entry) => (
                    <tr
                      key={entry.assignment.id}
                      className={entry.errors.length > 0 ? 'host-invalid-row' : ''}
                    >
                      <td className="mono rdns-idx">{entry.index}</td>
                      <td className="mono host-addr">{entry.ip}</td>
                      <td className="mono host-device-name">
                        {entry.domain ? `${entry.domain}.` : entry.assignment.name || '（空）'}
                      </td>
                      <td className="host-reason">
                        {entry.errors.length > 0 ? (
                          <span className="host-invalid-tag">{entry.errors.join('；')}</span>
                        ) : (
                          <span className="rdns-ok-tag">✓ 合法</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {errors.length > 0 && (
                <div className="opt121-error-box">
                  <strong>存在 {errors.length} 处名称错误，已停止整体生成（修正后自动恢复）：</strong>
                  <ul>
                    {errors.map((e, i) => (
                      <li key={i}>
                        第 {e.index} 条（{e.ip}）：{e.message}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {built.files.map((file) => (
                <div className="rdns-file" key={file.kind}>
                  <div className="rdns-file-head">
                    <h3>{file.title}</h3>
                    <div className="dnsmasq-actions">
                      <button
                        onClick={() => handleCopy(file.kind, file.text)}
                        title="复制该区域文件文本"
                      >
                        {copiedZone === file.kind ? '✓ 已复制' : '📋 复制'}
                      </button>
                      <button
                        className="primary"
                        onClick={() => downloadRdnsZone(file)}
                        title="下载为区域文件（.zone）"
                      >
                        ⬇ 下载 .zone
                      </button>
                    </div>
                  </div>
                  <pre className="mono dnsmasq-output">{file.text}</pre>
                  <div className="dnsmasq-count">共 {file.records} 条记录</div>
                </div>
              ))}
            </>
          )}
        </>
      )}
    </div>
  )
}
