import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { DocumentsPage } from '../DocumentsPage'
import * as apiClient from '../../api/client'

vi.mock('../../api/client', () => ({
  listDocuments: vi.fn(),
  createDocument: vi.fn(),
  uploadToPresigned: vi.fn(),
}))

describe('DocumentsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.listDocuments).mockResolvedValue([
      {
        id: 'doc-1',
        filename: 'policy.txt',
        status: 'READY',
        size_bytes: 2048,
        chunk_count: 2,
        created_at: '2026-10-01T12:00:00Z',
      },
      {
        id: 'doc-2',
        filename: 'report.docx',
        status: 'PROCESSING',
        size_bytes: 4096,
        created_at: '2026-10-01T12:05:00Z',
      },
    ])
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders document table with status badges', async () => {
    render(<DocumentsPage />)

    expect(await screen.findByText('policy.txt')).toBeInTheDocument()
    expect(screen.getByText('report.docx')).toBeInTheDocument()
    expect(screen.getByTestId('status-ready')).toHaveTextContent('READY')
    expect(screen.getByTestId('status-processing')).toHaveTextContent('PROCESSING')
  })

  it('rejects file with disallowed extension', async () => {
    render(<DocumentsPage />)

    const invalidFile = new File(['binary code'], 'malware.exe', { type: 'application/x-msdownload' })
    const fileInput = screen.getByTestId('file-input')

    fireEvent.change(fileInput, { target: { files: [invalidFile] } })

    const errorBanner = await screen.findByTestId('upload-error-banner')
    expect(errorBanner).toHaveTextContent("Invalid file type '.exe'")
    expect(screen.queryByTestId('selected-file-name')).not.toBeInTheDocument()
  })

  it('rejects oversize files (> 10 MB)', async () => {
    render(<DocumentsPage />)

    // 11 MB file
    const oversizeBlob = new Blob(['x'.repeat(1024 * 1024 * 11)], { type: 'text/plain' })
    const oversizeFile = new File([oversizeBlob], 'big_document.txt', { type: 'text/plain' })
    Object.defineProperty(oversizeFile, 'size', { value: 11 * 1024 * 1024 })

    const fileInput = screen.getByTestId('file-input')
    fireEvent.change(fileInput, { target: { files: [oversizeFile] } })

    const errorBanner = await screen.findByTestId('upload-error-banner')
    expect(errorBanner).toHaveTextContent('exceeds maximum allowed size of 10 MB')
    expect(screen.queryByTestId('selected-file-name')).not.toBeInTheDocument()
  })

  it('accepts valid file and toggles role-selector when visibility is roles', async () => {
    render(<DocumentsPage />)

    const validFile = new File(['valid text'], 'manual.pdf', { type: 'application/pdf' })
    const fileInput = screen.getByTestId('file-input')

    fireEvent.change(fileInput, { target: { files: [validFile] } })

    expect(await screen.findByTestId('selected-file-name')).toHaveTextContent('manual.pdf')

    // Change visibility to roles
    const selectVisibility = screen.getByTestId('select-visibility')
    fireEvent.change(selectVisibility, { target: { value: 'roles' } })

    expect(screen.getByTestId('roles-selector-group')).toBeInTheDocument()
    expect(screen.getByTestId('checkbox-role-admin')).toBeInTheDocument()
  })

  it('cleans up polling timer when unmounted', async () => {
    vi.useFakeTimers()
    const { unmount } = render(<DocumentsPage />)

    // Advance time - polling triggered
    await vi.advanceTimersByTimeAsync(3000)
    expect(apiClient.listDocuments).toHaveBeenCalled()

    const callCountBeforeUnmount = vi.mocked(apiClient.listDocuments).mock.calls.length
    unmount()

    // Advance further after unmount - no more calls should be made
    await vi.advanceTimersByTimeAsync(6000)
    expect(vi.mocked(apiClient.listDocuments).mock.calls.length).toBe(callCountBeforeUnmount)

    vi.useRealTimers()
  })
})
