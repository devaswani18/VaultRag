import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  ApiError,
  createDocument,
  getDocument,
  listDocuments,
  me,
  query,
  setTokenGetter,
  uploadToPresigned,
} from '../client'

describe('API Client', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    setTokenGetter(() => null)
  })

  it('attaches Authorization header and X-Request-Id when token is available', async () => {
    setTokenGetter(() => 'fake-jwt-token-123')

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        tenant_id: 'acme',
        user_id: 'usr-1',
        email: 'admin@acme.com',
        roles: ['admin'],
      }),
    })
    global.fetch = mockFetch

    const result = await me()
    expect(result.tenant_id).toBe('acme')

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [, options] = mockFetch.mock.calls[0]
    expect(options.headers['Authorization']).toBe('Bearer fake-jwt-token-123')
    expect(options.headers['X-Request-Id']).toBeDefined()
  })

  it('correctly maps 400 error response to typed ApiError with envelope', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers: {
        get: () => 'req-test-999',
      },
      json: async () => ({
        detail: {
          code: 'VALIDATION_FAILED',
          message: 'File size exceeds limit',
          request_id: 'req-test-999',
        },
      }),
    })
    global.fetch = mockFetch

    await expect(
      createDocument({
        filename: 'test.txt',
        content_type: 'text/plain',
        size_bytes: 99999999,
      })
    ).rejects.toThrow(ApiError)

    try {
      await createDocument({
        filename: 'test.txt',
        content_type: 'text/plain',
        size_bytes: 99999999,
      })
    } catch (err: any) {
      expect(err).toBeInstanceOf(ApiError)
      expect(err.status).toBe(400)
      expect(err.code).toBe('VALIDATION_FAILED')
      expect(err.message).toBe('File size exceeds limit')
      expect(err.requestId).toBe('req-test-999')
    }
  })

  it('correctly calls listDocuments and getDocument', async () => {
    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/documents')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => [
            {
              id: 'doc-1',
              filename: 'test.txt',
              status: 'READY',
              size_bytes: 1024,
              created_at: '2026-10-01T00:00:00Z',
            },
          ],
        })
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({
          id: 'doc-1',
          filename: 'test.txt',
          status: 'READY',
          size_bytes: 1024,
          created_at: '2026-10-01T00:00:00Z',
        }),
      })
    })
    global.fetch = mockFetch

    const docs = await listDocuments()
    expect(docs).toHaveLength(1)
    expect(docs[0].id).toBe('doc-1')

    const doc = await getDocument('doc-1')
    expect(doc.filename).toBe('test.txt')
  })

  it('correctly posts question to /query', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        answer: '20 days paid leave.',
        sources: [
          {
            doc_id: 'doc-1',
            filename: 'policy.txt',
            chunk_id: 'chunk-1',
            page: 1,
            score: 0.85,
            snippet: 'Employees get 20 days.',
          },
        ],
      }),
    })
    global.fetch = mockFetch

    const resp = await query('How many leave days?', 5)
    expect(resp.answer).toBe('20 days paid leave.')
    expect(resp.sources).toHaveLength(1)
    expect(resp.sources[0].filename).toBe('policy.txt')
  })

  it('uploadToPresigned sends form data with fields and file', async () => {
    // Mock XMLHttpRequest
    const xhrMock: any = {
      open: vi.fn(),
      send: vi.fn(function (this: any) {
        this.status = 204
        this.onload()
      }),
      upload: {},
      setRequestHeader: vi.fn(),
    }
    const xhrConstructor = vi.fn(() => xhrMock)
    vi.stubGlobal('XMLHttpRequest', xhrConstructor)

    const file = new File(['test content'], 'test.txt', { type: 'text/plain' })
    const post = {
      url: 'https://s3.amazonaws.com/bucket',
      fields: { key: 'uploads/test.txt', AWSAccessKeyId: 'fake' },
    }

    let progressCalled = false
    await uploadToPresigned(post, file, () => {
      progressCalled = true
    })

    expect(xhrMock.open).toHaveBeenCalledWith('POST', post.url)
    expect(xhrMock.send).toHaveBeenCalled()
    expect(progressCalled).toBe(true)
  })
})
