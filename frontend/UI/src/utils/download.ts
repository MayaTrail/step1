/**
 * Trigger a client-side download of text content as a file.
 * Used to export detection rules without a backend round-trip: the rule
 * source already lives in the loaded payload.
 */
export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
