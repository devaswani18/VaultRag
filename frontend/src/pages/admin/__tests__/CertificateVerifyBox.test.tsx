import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CertificateVerifyBox } from '../CertificateVerifyBox'
import * as apiClient from '../../../api/client'

vi.mock('../../../api/client', () => ({
  verifyCertificate: vi.fn(),
}))

describe('CertificateVerifyBox Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('rejects invalid JSON string syntax', async () => {
    render(<CertificateVerifyBox />)

    const textarea = screen.getByTestId('textarea-certificate-json')
    fireEvent.change(textarea, { target: { value: '{ not valid json }' } })

    const verifyBtn = screen.getByTestId('btn-verify-cert')
    fireEvent.click(verifyBtn)

    expect(await screen.findByTestId('cert-parse-error')).toHaveTextContent(
      'Invalid JSON format'
    )
    expect(apiClient.verifyCertificate).not.toHaveBeenCalled()
  })

  it('displays valid outcome banner when certificate signature is verified', async () => {
    vi.mocked(apiClient.verifyCertificate).mockResolvedValue({
      valid: true,
      reason: null,
    })

    render(<CertificateVerifyBox />)

    const certPayload = JSON.stringify({
      version: 1,
      tenant_id: 'acme',
      doc_id: 'doc-123',
      signature: 'valid-hmac-sha256',
    })

    const textarea = screen.getByTestId('textarea-certificate-json')
    fireEvent.change(textarea, { target: { value: certPayload } })

    const verifyBtn = screen.getByTestId('btn-verify-cert')
    fireEvent.click(verifyBtn)

    const validBanner = await screen.findByTestId('cert-result-valid')
    expect(validBanner).toHaveTextContent('Valid Certificate')
    expect(validBanner).toHaveTextContent('Cryptographic HMAC-SHA256 signature is authentic')
  })

  it('displays invalid outcome banner with error reason when certificate is altered', async () => {
    vi.mocked(apiClient.verifyCertificate).mockResolvedValue({
      valid: false,
      reason: 'Signature mismatch: certificate has been altered',
    })

    render(<CertificateVerifyBox />)

    const tamperedCert = JSON.stringify({
      version: 1,
      tenant_id: 'acme',
      doc_id: 'doc-123',
      signature: 'tampered-signature',
    })

    const textarea = screen.getByTestId('textarea-certificate-json')
    fireEvent.change(textarea, { target: { value: tamperedCert } })

    const verifyBtn = screen.getByTestId('btn-verify-cert')
    fireEvent.click(verifyBtn)

    const invalidBanner = await screen.findByTestId('cert-result-invalid')
    expect(invalidBanner).toHaveTextContent('Invalid Certificate')
    expect(invalidBanner).toHaveTextContent('Signature mismatch: certificate has been altered')
  })
})
