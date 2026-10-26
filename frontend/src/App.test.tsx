import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from './App'

const responseData = {
  classification: 'PHISHING',
  risk_level: 'HIGH',
  indicators: ['Requests an account password', 'Sender domain differs from displayed brand'],
  explanation: 'The message combines a credential request with a brand mismatch.',
  recommended_action: 'Do not follow the message link; verify through a trusted channel.',
}

function successfulResponse(payload: unknown) {
  return { ok: true, json: async () => payload } as Response
}

function submitText(value: string) {
  fireEvent.change(screen.getByLabelText('Email text'), { target: { value } })
  fireEvent.click(screen.getByRole('button', { name: /analyze email/i }))
}

describe('PhishGuard dashboard', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks() })

  it('shows an accessible empty state and validates blank input', async () => {
    render(<App />)
    expect(screen.getByText('Start with an email')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /analyze email/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Paste an email message')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('posts email text and displays validated API response fields', async () => {
    vi.mocked(fetch).mockResolvedValue(successfulResponse(responseData))
    render(<App />)
    submitText('Subject: Account notice\nPlease sign in.')

    expect(await screen.findByRole('heading', { name: 'Phishing' })).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText(responseData.explanation)).toBeInTheDocument()
    expect(screen.getByText(responseData.indicators[0])).toBeInTheDocument()
    expect(screen.getByText(responseData.indicators[1])).toBeInTheDocument()
    expect(screen.getByText(responseData.recommended_action)).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith(expect.stringMatching(/\/detect$/), expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ email_text: 'Subject: Account notice\nPlease sign in.' }),
    }))
  })

  it('shows a clear error for malformed successful JSON', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, json: async () => { throw new SyntaxError('bad json') } } as unknown as Response)
    render(<App />)
    submitText('A message to assess')
    expect(await screen.findByRole('alert')).toHaveTextContent('analysis service returned an invalid response')
    expect(screen.getByRole('heading', { name: 'Could not display the analysis' })).toBeInTheDocument()
  })

  it.each([
    ['invalid classification', { ...responseData, classification: 'MAYBE' }],
    ['invalid risk', { ...responseData, risk_level: 'CRITICAL' }],
    ['missing indicators', { ...responseData, indicators: undefined }],
    ['malformed indicators', { ...responseData, indicators: ['valid', 42] }],
    ['missing explanation', { ...responseData, explanation: undefined }],
    ['unexpected response shape', ['not', 'an', 'object']],
    ['contradictory classification and risk', { ...responseData, classification: 'INCONCLUSIVE', risk_level: 'HIGH' }],
  ])('rejects %s from a successful API response', async (_name, payload) => {
    vi.mocked(fetch).mockResolvedValue(successfulResponse(payload))
    render(<App />)
    submitText('A message to assess')
    expect(await screen.findByRole('alert')).toHaveTextContent('analysis service returned an invalid response')
  })

  it('shows a helpful API error and allows clearing the input', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({ detail: 'The local classification model is unavailable.' }),
    } as Response)
    render(<App />)
    submitText('A message to assess')
    expect(await screen.findByRole('alert')).toHaveTextContent('The local classification model is unavailable.')
    fireEvent.click(screen.getByRole('button', { name: /clear/i }))
    await waitFor(() => expect(screen.getByLabelText('Email text')).toHaveValue(''))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText('Start with an email')).toBeInTheDocument()
  })

  it('shows a clear message when the network request fails', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Failed to fetch'))
    render(<App />)
    submitText('A message to assess')
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not reach the analysis service')
  })

  it('accepts the maximum length and rejects one code point beyond it', async () => {
    vi.mocked(fetch).mockResolvedValue(successfulResponse(responseData))
    render(<App />)
    submitText('a'.repeat(20_000))
    expect(await screen.findByRole('heading', { name: 'Phishing' })).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(1)
    fireEvent.change(screen.getByLabelText('Email text'), { target: { value: 'a'.repeat(20_001) } })
    fireEvent.click(screen.getByRole('button', { name: /analyze email/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('20,000 characters or fewer')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('counts Unicode code points consistently with the backend limit', async () => {
    vi.mocked(fetch).mockResolvedValue(successfulResponse(responseData))
    render(<App />)
    const maxUnicodeText = `${'a'.repeat(19_999)}😀`
    submitText(maxUnicodeText)
    expect(await screen.findByRole('heading', { name: 'Phishing' })).toBeInTheDocument()
    expect(screen.getByLabelText('Email text')).toHaveValue(maxUnicodeText)
    expect(fetch).toHaveBeenCalledTimes(1)
    const overLimitUnicodeText = `${maxUnicodeText}b`
    fireEvent.change(screen.getByLabelText('Email text'), { target: { value: overLimitUnicodeText } })
    expect(screen.getByLabelText('Email text')).toHaveValue(overLimitUnicodeText)
    expect(screen.getByText(/20,001/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /analyze email/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('20,000 characters or fewer')
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
