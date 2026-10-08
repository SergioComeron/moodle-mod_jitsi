/**
 * Service Worker for Jitsi Web Push notifications.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/* global clients */

self.addEventListener('push', function(event) {
    var data = {};
    if (event.data) {
        try {
            data = event.data.json();
        } catch (e) {
            data = {title: 'Jitsi', body: event.data.text()};
        }
    }

    var title = data.title || 'Jitsi';
    // The server sends absolute (wwwroot) URLs for icon/url. Fallbacks are relative to this
    // service worker (served at <wwwroot>/mod/jitsi/push-sw.js) so they also work when Moodle
    // is installed in a subdirectory — never hardcode a domain-root path here.
    var iconUrl = data.icon || 'pix/icon.png';
    var options = {
        body: data.body || '',
        icon: iconUrl,
        badge: iconUrl,
        data: {url: data.url || './'},
        requireInteraction: true,
        vibrate: [200, 100, 200],
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    var url = event.notification.data && event.notification.data.url
        ? event.notification.data.url
        : './';

    event.waitUntil(
        clients.matchAll({type: 'window', includeUncontrolled: true}).then(function(clientList) {
            for (var i = 0; i < clientList.length; i++) {
                var client = clientList[i];
                if (client.url.indexOf(url) !== -1 && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(url);
            }
            return null;
        })
    );
});
