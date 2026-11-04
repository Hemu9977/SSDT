/**
 * A deadline for one fetch, including reading its body.
 *
 * `fetch` has no timeout of its own: a request the server never answers keeps a
 * page on its loading state until some proxy gives up, so a loading flag cleared
 * only on response or error can stay set for minutes. Use as:
 *
 *   const deadline = requestTimeout(30_000, controller.signal);
 *   try {
 *     const res = await fetch(url, { signal: deadline.signal });
 *     data = await res.json();
 *   } catch (err) {
 *     if (deadline.timedOut) ...   // ours, as opposed to the caller's abort
 *   } finally {
 *     deadline.clear();
 *   }
 *
 * @param {number} ms
 * @param {AbortSignal} [parentSignal] also aborts when this does (e.g. unmount)
 */
export function requestTimeout(ms, parentSignal) {
  const controller = new AbortController();
  let timedOut = false;
  const onParentAbort = () => controller.abort();

  if (parentSignal?.aborted) controller.abort();
  else parentSignal?.addEventListener('abort', onParentAbort, { once: true });

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, ms);

  return {
    signal: controller.signal,
    get timedOut() { return timedOut; },
    clear() {
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', onParentAbort);
    },
  };
}
