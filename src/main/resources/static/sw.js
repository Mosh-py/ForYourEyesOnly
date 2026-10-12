/**
 * F.Y.E.O Progressive Web App Service Worker (v4.0)
 *
 * Implements:
 * 1. Offline Cache-First asset retrieval for instant standalone launch.
 * 2. Web Share Target Level 2 file interception: captures shared image blobs
 *    in-memory via CacheStorage or BroadcastChannel, preventing network exposure.
 */

const CACHE_NAME = 'fyeo-cache-v4';
const STATIC_ASSETS = [
    '/',
    '/css/fyeo.css',
    '/js/fyeo-worker.js',
    '/js/qrcode.min.js',
    '/manifest.json',
    '/icons/icon-192.png',
    '/icons/icon-512.png',
    '/fonts/inter-latin.woff2',
    '/fonts/inter-latin-ext.woff2',
    '/fonts/fira-code-latin.woff2',
    '/fonts/fira-code-latin-ext.woff2'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(STATIC_ASSETS);
        }).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Intercept Web Share Target POST /share-target
    if (event.request.method === 'POST' && url.pathname === '/share-target') {
        event.respondWith((async () => {
            try {
                const formData = await event.request.formData();
                const photoFile = formData.get('photo');

                if (photoFile) {
                    const cache = await caches.open('fyeo-shared-media');
                    // Store shared file in dedicated ephemeral cache for client consumption
                    const fileResponse = new Response(photoFile, {
                        headers: {
                            'content-type': photoFile.type || 'image/png',
                            'x-file-name': encodeURIComponent(photoFile.name || 'shared-image.png')
                        }
                    });
                    await cache.put('/shared-incoming-photo', fileResponse);
                }

                // Redirect client back to the main app interface
                return Response.redirect('/?shared=1#lock', 303);
            } catch (err) {
                console.error('[SW] Share target processing failed:', err);
                return Response.redirect('/#lock', 303);
            }
        })());
        return;
    }

    // Default Cache-First strategy with Network Fallback
    event.respondWith(
        caches.match(event.request).then((cached) => {
            if (cached) {
                return cached;
            }
            return fetch(event.request).catch(() => {
                // Return offline fallback if navigating to document
                if (event.request.mode === 'navigate') {
                    return caches.match('/');
                }
            });
        })
    );
});
