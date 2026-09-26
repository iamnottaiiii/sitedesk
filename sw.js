var CACHE = 'sitedesk-v7';
var CORE = ['index.html', 'styles.css', 'app.js', 'config.js', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'icon.svg'];

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE).then(function(c){ return c.addAll(CORE); }).then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.map(function(k){ return k === CACHE ? null : caches.delete(k); }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e){
  if(e.request.method !== 'GET') return;
  var url = new URL(e.request.url);
  /* Never intercept cross-origin traffic (api.github.com and friends). Letting
     the browser handle it natively means a network failure comes back as a
     proper error the app can report and retry, instead of a null response from
     a cache fallback that never had the URL. */
  if(url.origin !== self.location.origin) return;
  function offline(){
    return new Response('offline', { status: 503, statusText: 'Service Unavailable' });
  }
  /* Lead catalog + queue chunks: serve the cached copy instantly, refresh it
     quietly in the background. This is what makes repeat visits paint with
     no spinner. */
  if(url.pathname.replace(/\/+$/, '') === '/sites.json' ||
     url.pathname.indexOf('/sitedesk/data/queue/') === 0){
    e.respondWith(
      caches.match(e.request).then(function(cached){
        var net = fetch(e.request).then(function(resp){
          if(resp && resp.ok){
            var copy = resp.clone();
            caches.open(CACHE).then(function(c){ c.put(e.request, copy); });
          }
          return resp;
        }).catch(function(){ return cached || offline(); });
        return cached || net;
      })
    );
    return;
  }
  e.respondWith(
    fetch(e.request).then(function(resp){
      var copy = resp.clone();
      caches.open(CACHE).then(function(c){ c.put(e.request, copy); });
      return resp;
    }).catch(function(){
      return caches.match(e.request).then(function(cached){ return cached || offline(); });
    })
  );
});

self.addEventListener('push', function(e){
  var data = {};
  try{ data = e.data ? e.data.json() : {}; }catch(_){}
  var title = String(data.title || 'SiteDesk');
  var body = String(data.body || '').slice(0, 140);
  var url = String(data.url || 'index.html');
  e.waitUntil(
    self.registration.showNotification(title, {
      body: body, icon: 'icon-192.png', badge: 'icon-192.png',
      tag: 'sitedesk-push', renotify: true, data: { url: url }
    })
  );
});

self.addEventListener('notificationclick', function(e){
  e.notification.close();
  var url = (e.notification.data && e.notification.data.url) || 'index.html';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list){
      for(var i = 0; i < list.length; i++){
        if(list[i].url.indexOf('/sitedesk') >= 0){ list[i].focus(); return; }
      }
      return clients.openWindow(url);
    })
  );
});
