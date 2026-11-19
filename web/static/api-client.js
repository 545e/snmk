/*
 * SNMK centralized API client.
 *
 * Single source of truth for:
 *   - configurable API base URL (server injection > meta tag > localStorage > same-origin)
 *   - authentication headers
 *   - correlation / request IDs
 *   - JSON serialization
 *   - timeouts (AbortController)
 *   - safe retries (idempotent methods only)
 *   - network error classification
 *   - authentication failure events
 *   - response validation
 *
 * Note for maintainers: apiFetch() intentionally uses a bound reference to the
 * *native* fetch captured at load time. It never calls the global `fetch`, so
 * replacing legacy `fetch(...)` call sites with `apiFetch(...)` cannot recurse.
 */
(function (global) {
    'use strict';

    var nativeFetch = global.fetch.bind(global);
    var SNMK = global.SNMK = global.SNMK || {};

    var DEFAULT_TIMEOUT_MS = 30000;
    var DEFAULT_RETRIES = 2; // additional attempts, GET/HEAD/OPTIONS only
    var RETRY_BASE_DELAY_MS = 250;

    function ApiError(message, options) {
        options = options || {};
        var err = new Error(message);
        err.name = options.name || 'ApiError';
        err.status = options.status || 0;
        err.code = options.code || 'api_error';
        err.url = options.url || '';
        err.method = options.method || 'GET';
        err.requestId = options.requestId || '';
        err.retryable = !!options.retryable;
        err.isNetworkError = !!options.isNetworkError;
        err.isTimeout = !!options.isTimeout;
        err.isAuthFailure = !!options.isAuthFailure;
        err.details = options.details || null;
        Object.setPrototypeOf(err, ApiError.prototype);
        return err;
    }
    ApiError.prototype = Object.create(Error.prototype);
    ApiError.prototype.constructor = ApiError;

    var _explicitToken = '';

    function newCorrelationId() {
        try {
            if (global.crypto && typeof global.crypto.randomUUID === 'function') {
                return global.crypto.randomUUID();
            }
        } catch (e) { /* not available in all contexts */ }
        return 'snmk-' + Date.now().toString(16) + '-' + Math.random().toString(16).slice(2, 12);
    }

    function resolveBaseUrl() {
        var base = '';
        if (typeof global.SNMK_API_BASE_URL === 'string') {
            base = global.SNMK_API_BASE_URL;
        }
        if (!base && typeof document !== 'undefined') {
            var meta = document.querySelector('meta[name="snmk-api-base"]');
            if (meta && meta.content) { base = meta.content; }
        }
        if (!base) {
            try {
                base = global.localStorage.getItem('snmk_api_base_url') || '';
            } catch (e) { /* storage disabled */ }
        }
        base = String(base || '').trim();
        if (base === '/' || base === 'same-origin') { base = ''; }
        if (base.indexOf('//') === 0 && typeof location !== 'undefined') {
            base = location.protocol + base;
        }
        return base.replace(/\/+$/, '');
    }

    function resolveToken() {
        if (_explicitToken) { return _explicitToken; }
        var keys = ['snmk_token', 'swa_token', 'snmk_auth_token', 'swa_auth_token', 'authToken'];
        var store;
        for (var s = 0; s < keys.length; s += 1) {
            try { store = global.localStorage; } catch (e) { store = null; }
            if (store && store.getItem(keys[s])) { return store.getItem(keys[s]); }
            try { store = global.sessionStorage; } catch (e) { store = null; }
            if (store && store.getItem(keys[s])) { return store.getItem(keys[s]); }
        }
        // Operator-entered token in the settings view (if present).
        if (typeof document !== 'undefined') {
            var el = document.getElementById('optBearerToken');
            if (el && el.value && el.value.trim()) { return el.value.trim(); }
        }
        return '';
    }

    function buildUrl(path) {
        var base = resolveBaseUrl();
        var raw = String(path == null ? '/' : path);
        if (/^https?:\/\//i.test(raw) || raw.indexOf('//') === 0 || /^(blob|data):/i.test(raw)) {
            return raw;
        }
        if (raw.charAt(0) !== '/') { raw = '/' + raw; }
        return base + raw;
    }

    function isIdempotent(method) {
        return ['GET', 'HEAD', 'OPTIONS'].indexOf(String(method || 'GET').toUpperCase()) !== -1;
    }

    function parseBody(response, requestId) {
        var contentType = response.headers && response.headers.get ? (response.headers.get('content-type') || '') : '';
        if (/application\/json/i.test(contentType)) {
            return response.json().catch(function () { return null; });
        }
        if (/application\/(xml|text\/xml)|xml/i.test(contentType)) {
            return response.text().catch(function () { return null; });
        }
        return response.text().catch(function () { return null; });
    }

    function dispatch(name, detail) {
        if (typeof document === 'undefined' || !document.dispatchEvent) { return; }
        try {
            document.dispatchEvent(new CustomEvent(name, { detail: detail }));
        } catch (e) { /* CustomEvent unavailable in very old browsers */ }
    }

    function apiFetch(path, options) {
        options = options || {};
        var method = String(options.method || 'GET').toUpperCase();
        var url = buildUrl(path);
        var requestId = options.requestId || newCorrelationId();
        var timeoutMs = options.timeout != null ? options.timeout : DEFAULT_TIMEOUT_MS;
        var retries = options.retries != null ? options.retries : (isIdempotent(method) ? DEFAULT_RETRIES : 0);
        var headers = {};

        // Copy caller headers (supports Headers, plain object and array forms).
        if (options.headers) {
            if (typeof options.headers.forEach === 'function' && !Array.isArray(options.headers)) {
                options.headers.forEach(function (v, k) { headers[k] = v; });
            } else if (Array.isArray(options.headers)) {
                options.headers.forEach(function (pair) { headers[pair[0]] = pair[1]; });
            } else {
                Object.keys(options.headers).forEach(function (k) { headers[k] = options.headers[k]; });
            }
        }

        var lowerKeys = Object.keys(headers).reduce(function (acc, k) {
            acc[k.toLowerCase()] = k;
            return acc;
        }, {});
        if (!lowerKeys['x-request-id']) { headers['X-Request-ID'] = requestId; }
        if (!lowerKeys['x-correlation-id']) { headers['X-Correlation-ID'] = requestId; }
        if (!lowerKeys['x-requested-with']) { headers['X-Requested-With'] = 'SNMK'; }

        var body = options.body;
        var isForm = typeof FormData !== 'undefined' && body instanceof FormData;
        var isUrlEncoded = typeof body === 'string' && /application\/x-www-form-urlencoded/i.test(lowerKeys['content-type'] ? headers[lowerKeys['content-type']] : '');
        if (body && !isForm && !isUrlEncoded && !lowerKeys['content-type']) {
            headers['Content-Type'] = 'application/json';
        }
        if (body && !isForm && typeof body !== 'string' && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
            body = JSON.stringify(body);
            headers['Content-Type'] = 'application/json';
        }

        var token = options.token !== undefined ? options.token : resolveToken();
        if (token && !lowerKeys.authorization) { headers['Authorization'] = 'Bearer ' + String(token).replace(/^Bearer\s+/i, ''); }

        var attempt = 0;
        function run() {
            var controller = null;
            var signal = options.signal;
            if (!signal && typeof AbortController !== 'undefined') {
                controller = new AbortController();
                signal = controller.signal;
            }
            var timer = null;
            if (controller && timeoutMs > 0) {
                timer = global.setTimeout(function () {
                    try { controller.abort(); } catch (e) { /* already aborted */ }
                }, timeoutMs);
            }
            return nativeFetch(url, {
                method: method,
                headers: headers,
                body: body,
                credentials: options.credentials || 'same-origin',
                mode: options.mode || 'cors',
                cache: options.cache,
                redirect: options.redirect || 'follow',
                signal: signal
            }).then(function (response) {
                if (timer) { global.clearTimeout(timer); }
                if (!response.ok) {
                    return parseBody(response, requestId).then(function (details) {
                        var detail = (details && (details.detail || details.message)) || '';
                        var message = 'HTTP ' + response.status + (detail ? ': ' + detail : '') + ' for ' + method + ' ' + path;
                        var authFailure = response.status === 401 || response.status === 403;
                        var err = ApiError(message, {
                            name: authFailure ? 'ApiAuthError' : 'ApiHttpError',
                            status: response.status,
                            code: authFailure ? 'auth_failure' : 'http_error',
                            url: url,
                            method: method,
                            requestId: requestId,
                            retryable: response.status === 408 || response.status === 429 || response.status >= 500,
                            isAuthFailure: authFailure,
                            details: details
                        });
                        err.response = response;
                        if (authFailure) {
                            dispatch('snmk:auth-failure', { status: response.status, url: url, requestId: requestId });
                        }
                        throw err;
                    });
                }
                return response;
            }).catch(function (error) {
                if (timer) { global.clearTimeout(timer); }
                var aborted = error && (error.name === 'AbortError' || error.code === 'ABORT_ERR');
                var timedOut = aborted && !options.signal;
                var network = !error || !error.status;
                var classified = error;
                if (classified instanceof ApiError) {
                    if (timedOut) {
                        classified.isTimeout = true;
                        classified.code = 'timeout';
                        classified.name = 'ApiTimeoutError';
                    }
                    var retryableError = classified.retryable && !authFailureOf(classified) && attempt < retries;
                    if (retryableError) {
                        attempt += 1;
                        return new Promise(function (resolve) {
                            global.setTimeout(resolve, RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1));
                        }).then(run);
                    }
                    throw classified;
                }
                classified = ApiError(
                    timedOut ? ('Request timeout after ' + timeoutMs + 'ms for ' + method + ' ' + path)
                             : ('Network error for ' + method + ' ' + path + ': ' + ((error && error.message) || 'unknown')),
                    {
                        name: timedOut ? 'ApiTimeoutError' : 'ApiNetworkError',
                        code: timedOut ? 'timeout' : 'network_error',
                        url: url,
                        method: method,
                        requestId: requestId,
                        isTimeout: timedOut,
                        isNetworkError: network && !timedOut,
                        retryable: !timedOut
                    }
                );
                classified.cause = error;
                if (!timedOut && isIdempotent(method) && attempt < retries) {
                    attempt += 1;
                    return new Promise(function (resolve) {
                        global.setTimeout(resolve, RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1));
                    }).then(run);
                }
                throw classified;
            });
        }
        return run();
    }

    function authFailureOf(err) {
        return err && (err.isAuthFailure || err.status === 401 || err.status === 403);
    }

    function jsonRequest(method, path, body, options) {
        var opts = Object.assign({}, options || {}, { method: method });
        if (body !== undefined) { opts.body = body; }
        return apiFetch(path, opts).then(function (response) {
            var contentType = response.headers && response.headers.get ? (response.headers.get('content-type') || '') : '';
            if (/application\/json/i.test(String(contentType || ''))) { return response.json(); }
            return response.text();
        });
    }

    SNMK.api = {
        fetch: apiFetch,
        get: function (path, options) { return jsonRequest('GET', path, undefined, options); },
        post: function (path, body, options) { return jsonRequest('POST', path, body, options); },
        put: function (path, body, options) { return jsonRequest('PUT', path, body, options); },
        patch: function (path, body, options) { return jsonRequest('PATCH', path, body, options); },
        delete: function (path, options) { return jsonRequest('DELETE', path, undefined, options); },
        setBaseUrl: function (base) {
            try { global.localStorage.setItem('snmk_api_base_url', String(base || '').trim()); } catch (e) { /* ignore */ }
            return resolveBaseUrl();
        },
        getBaseUrl: resolveBaseUrl,
        setToken: function (token) { _explicitToken = String(token || '').trim(); return !!_explicitToken; },
        newCorrelationId: newCorrelationId,
        ApiError: ApiError
    };

    // Global aliases keep legacy call sites simple and auditable.
    global.apiFetch = apiFetch;
}(window));
