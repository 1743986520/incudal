export function formatTrafficUnitPrice(cents: number | null | undefined): string {
  const yuan = Number(cents || 0) / 100
  return yuan.toFixed(4).replace(/\.?(?:0+)$/, '')
}
