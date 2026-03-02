import { useState, useEffect } from 'react'
import type { PlatformId, PlatformData, Emulation, DetectionData, Guardrails, Playbook } from '@/types'
import * as platformService from '@/services/platform.service'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

export function usePlatformData(platformId: PlatformId | undefined): AsyncState<PlatformData> {
  const [state, setState] = useState<AsyncState<PlatformData>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true, error: null }))
    platformService.fetchPlatformData(platformId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: data ? null : 'Platform not found' })
    })
    return () => { cancelled = true }
  }, [platformId])

  return state
}

export function useEmulations(platformId: PlatformId | undefined): AsyncState<Emulation[]> {
  const [state, setState] = useState<AsyncState<Emulation[]>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchEmulations(platformId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: null })
    })
    return () => { cancelled = true }
  }, [platformId])

  return state
}

export function useEmulation(platformId: PlatformId | undefined, emulationId: string | undefined): AsyncState<Emulation> {
  const [state, setState] = useState<AsyncState<Emulation>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId || !emulationId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchEmulationById(platformId, emulationId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: data ? null : 'Emulation not found' })
    })
    return () => { cancelled = true }
  }, [platformId, emulationId])

  return state
}

export function useDetections(platformId: PlatformId | undefined): AsyncState<DetectionData> {
  const [state, setState] = useState<AsyncState<DetectionData>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchDetections(platformId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: data ? null : 'Detections not found' })
    })
    return () => { cancelled = true }
  }, [platformId])

  return state
}

export function useGuardrails(platformId: PlatformId | undefined): AsyncState<Guardrails> {
  const [state, setState] = useState<AsyncState<Guardrails>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchGuardrails(platformId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: data ? null : 'Guardrails not found' })
    })
    return () => { cancelled = true }
  }, [platformId])

  return state
}

export function usePlaybooks(platformId: PlatformId | undefined): AsyncState<Playbook[]> {
  const [state, setState] = useState<AsyncState<Playbook[]>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchPlaybooks(platformId).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: null })
    })
    return () => { cancelled = true }
  }, [platformId])

  return state
}

export function usePlaybook(platformId: PlatformId | undefined, index: number): AsyncState<Playbook> {
  const [state, setState] = useState<AsyncState<Playbook>>({ data: null, loading: true, error: null })

  useEffect(() => {
    if (!platformId || index < 0) {
      setState({ data: null, loading: false, error: null })
      return
    }
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))
    platformService.fetchPlaybookById(platformId, index).then((data) => {
      if (!cancelled) setState({ data, loading: false, error: data ? null : 'Playbook not found' })
    })
    return () => { cancelled = true }
  }, [platformId, index])

  return state
}
