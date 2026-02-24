export function formatUnixTimestampSeconds(timestamp: bigint) {
  const ms = Number(timestamp) * 1000
  if (!Number.isFinite(ms)) return timestamp.toString()

  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  const yyyy = d.getFullYear()
  const mm = pad(d.getMonth() + 1)
  const dd = pad(d.getDate())
  const hh = pad(d.getHours())
  const mi = pad(d.getMinutes())
  const ss = pad(d.getSeconds())
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`
}

