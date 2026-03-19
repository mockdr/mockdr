import axios from 'axios'

/**
 * Preconfigured Axios instance for the S1 mock API.
 *
 * Request interceptor injects the ApiToken header from localStorage.
 * Response interceptor unwraps the Axios envelope so callers receive the
 * raw S1 response body (e.g. `{ data: [...], pagination: {...} }`).
 * On 401 the token is cleared and the user is redirected to /login.
 */
const client = axios.create({
  baseURL: '/web/api/v2.1',
  timeout: 15000,
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('s1_token')
  if (token) config.headers.Authorization = `ApiToken ${token}`
  return config
})

client.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error: unknown) => {
    if (
      axios.isAxiosError(error) &&
      error.response?.status === 401
    ) {
      localStorage.removeItem('s1_token')
      // Lazy import to avoid circular dependency and test-mock issues
      import('../router').then(({ default: router }) => router.push('/login'))
    }
    return Promise.reject(error)
  },
)

export default client
