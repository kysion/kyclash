import { unstable_serialize } from 'swr'
import useSWR, {
  type SWRConfiguration,
  type SWRResponse,
  mutate as swrMutate,
} from 'swr'

type QueryKey = string | readonly unknown[]

type QueryOptions<T> = {
  queryKey: QueryKey
  queryFn: () => Promise<T> | T
  enabled?: boolean
  initialData?: T | (() => T | undefined)
  placeholderData?: T | (() => T | undefined)
  staleTime?: number
  gcTime?: number
  retry?: number | false
  retryDelay?: number | ((attempt: number) => number)
  refetchInterval?: number | false
  refetchIntervalInBackground?: boolean
  refetchOnWindowFocus?: boolean
  refetchOnReconnect?: boolean
}

type QueryResult<T> = Omit<SWRResponse<T>, 'mutate'> & {
  isFetching: boolean
  isPending: boolean
  refetch: () => Promise<{ data: T | undefined }>
  mutate: SWRResponse<T>['mutate']
}

type QueryFilters = {
  queryKey: QueryKey
}

const keyToSWRKey = (queryKey: QueryKey) => {
  return Array.isArray(queryKey) ? [...queryKey] : queryKey
}

const serializeQueryKey = (queryKey: QueryKey) => {
  return unstable_serialize(keyToSWRKey(queryKey))
}

const resolveFallbackData = <T>(
  initialData: QueryOptions<T>['initialData'],
  placeholderData: QueryOptions<T>['placeholderData'],
) => {
  const data = initialData ?? placeholderData
  return typeof data === 'function' ? (data as () => T | undefined)() : data
}

const resolveRetryInterval = (
  retryDelay: QueryOptions<unknown>['retryDelay'],
) => {
  if (typeof retryDelay !== 'function') return retryDelay
  return retryDelay(0)
}

export const queryCache = new Map<string, unknown>()

export const queryClientConfig: SWRConfiguration = {
  dedupingInterval: 2000,
  errorRetryCount: 3,
  errorRetryInterval: 5000,
  revalidateOnFocus: false,
}

export const queryClient = {
  getQueryData<T>(queryKey: QueryKey): T | undefined {
    return queryCache.get(serializeQueryKey(queryKey)) as T | undefined
  },

  setQueryData<T>(
    queryKey: QueryKey,
    updaterOrData: T | undefined | ((current: T | undefined) => T | undefined),
  ) {
    const current = this.getQueryData<T>(queryKey)
    const next =
      typeof updaterOrData === 'function'
        ? (updaterOrData as (current: T | undefined) => T | undefined)(current)
        : updaterOrData

    if (next === undefined) {
      queryCache.delete(serializeQueryKey(queryKey))
    } else {
      queryCache.set(serializeQueryKey(queryKey), next)
    }

    void swrMutate(keyToSWRKey(queryKey), next, {
      populateCache: true,
      revalidate: false,
    })
    return next
  },

  invalidateQueries({ queryKey }: QueryFilters) {
    return swrMutate(keyToSWRKey(queryKey))
  },

  removeQueries({ queryKey }: QueryFilters) {
    queryCache.delete(serializeQueryKey(queryKey))
    return swrMutate(keyToSWRKey(queryKey), undefined, {
      populateCache: true,
      revalidate: false,
    })
  },

  async fetchQuery<T>({
    queryKey,
    queryFn,
  }: {
    queryKey: QueryKey
    queryFn: () => Promise<T> | T
  }) {
    const data = await queryFn()
    this.setQueryData(queryKey, data)
    return data
  },
}

export const invalidateQueries = (queryKeys: readonly QueryKey[]) =>
  Promise.all(
    queryKeys.map((queryKey) => queryClient.invalidateQueries({ queryKey })),
  )

export function useQuery<T>(options: QueryOptions<T>): QueryResult<T> {
  const {
    queryKey,
    queryFn,
    enabled = true,
    initialData,
    placeholderData,
    retry,
    retryDelay,
    refetchInterval,
    refetchIntervalInBackground,
    refetchOnWindowFocus,
    refetchOnReconnect,
    staleTime,
  } = options

  const fallbackData = resolveFallbackData(initialData, placeholderData)
  const serializedKey = serializeQueryKey(queryKey)
  if (enabled && fallbackData !== undefined && !queryCache.has(serializedKey)) {
    queryCache.set(serializedKey, fallbackData)
  }

  const swr = useSWR<T>(enabled ? keyToSWRKey(queryKey) : null, queryFn, {
    dedupingInterval: staleTime,
    errorRetryCount: retry === false ? 0 : retry,
    errorRetryInterval: resolveRetryInterval(retryDelay),
    fallbackData,
    keepPreviousData: placeholderData !== undefined,
    revalidateOnFocus: refetchOnWindowFocus,
    revalidateOnReconnect: refetchOnReconnect,
    refreshInterval: refetchInterval || 0,
    refreshWhenHidden: refetchIntervalInBackground ?? false,
    onSuccess: (data) => {
      queryCache.set(serializedKey, data)
    },
  })

  return {
    ...swr,
    isFetching: swr.isValidating,
    isPending: swr.isLoading,
    refetch: async () => {
      const data = await swr.mutate()
      if (data !== undefined) {
        queryCache.set(serializedKey, data)
      }
      return { data }
    },
  }
}
