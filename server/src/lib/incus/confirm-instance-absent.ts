import { IncusApiError, type IncusClient } from './incus-client.js'

/** A stale state endpoint, a proxy error, or a text message is not deletion proof. */
export async function confirmInstanceAbsent(
  client: Pick<IncusClient, 'request'>,
  name: string,
  initialError: unknown
): Promise<boolean> {
  const path = `/1.0/instances/${name}`
  if (!(initialError instanceof IncusApiError) || initialError.statusCode !== 404 || initialError.method !== 'GET'
      || (initialError.path !== path && initialError.path !== `${path}/state`)) return false
  try {
    await client.request('GET', path)
    return false
  } catch (error) {
    return error instanceof IncusApiError && error.statusCode === 404 && error.method === 'GET' && error.path === path
  }
}
