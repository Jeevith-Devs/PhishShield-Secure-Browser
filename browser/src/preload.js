const { contextBridge, ipcRenderer } = require('electron');

// ─── 5-Second Rotating GPS Location Scrambler ─────────────────────────────────
const SPOOF_COORDINATES = [
  { lat: 47.3769, lng: 8.5417, city: 'Zurich', country: 'Switzerland', flag: '🇨🇭' },
  { lat: 64.1466, lng: -21.9426, city: 'Reykjavik', country: 'Iceland', flag: '🇮🇸' },
  { lat: 35.6762, lng: 139.6503, city: 'Tokyo', country: 'Japan', flag: '🇯🇵' },
  { lat: 1.3521, lng: 103.8198, city: 'Singapore', country: 'Singapore', flag: '🇸🇬' },
  { lat: 50.1109, lng: 8.6821, city: 'Frankfurt', country: 'Germany', flag: '🇩🇪' },
  { lat: 52.3676, lng: 4.9041, city: 'Amsterdam', country: 'Netherlands', flag: '🇳🇱' },
  { lat: -33.8688, lng: 151.2093, city: 'Sydney', country: 'Australia', flag: '🇦🇺' },
  { lat: 43.6532, lng: -79.3832, city: 'Toronto', country: 'Canada', flag: '🇨🇦' },
  { lat: 51.5074, lng: -0.1278, city: 'London', country: 'United Kingdom', flag: '🇬🇧' },
  { lat: 59.9139, lng: 10.7522, city: 'Oslo', country: 'Norway', flag: '🇳🇴' },
];

let spoofIndex = 0;
let scramblerEnabled = true;

setInterval(() => {
  if (scramblerEnabled) {
    spoofIndex = (spoofIndex + 1) % SPOOF_COORDINATES.length;
  }
}, 5000);

// Intercept Geolocation API in rendered pages
try {
  if (typeof navigator !== 'undefined') {
    const fakeGeolocation = {
      getCurrentPosition: (success) => {
        if (!scramblerEnabled) return;
        const loc = SPOOF_COORDINATES[spoofIndex];
        if (success) {
          success({
            coords: {
              latitude: loc.lat,
              longitude: loc.lng,
              accuracy: 15,
              altitude: 35,
              altitudeAccuracy: 5,
              heading: 0,
              speed: 0,
            },
            timestamp: Date.now(),
          });
        }
      },
      watchPosition: (success) => {
        if (success) fakeGeolocation.getCurrentPosition(success);
        return setInterval(() => {
          if (success) fakeGeolocation.getCurrentPosition(success);
        }, 5000);
      },
      clearWatch: (id) => clearInterval(id),
    };

    Object.defineProperty(navigator, 'geolocation', {
      value: fakeGeolocation,
      configurable: true,
      writable: true,
    });
  }
} catch (e) {
  // context isolation fallback
}

contextBridge.exposeInMainWorld('phishshield', {
  scanUrl: (url) => ipcRenderer.invoke('scan-url', url),
  launchSandbox: (url, threatLevel) => ipcRenderer.invoke('launch-sandbox', { url, threatLevel }),
  generateAnalystReport: (scanId) => ipcRenderer.invoke('generate-report', scanId),
  onSecurityUpdate: (callback) => ipcRenderer.on('security-update', (_event, value) => callback(value)),
  onNavigationBlocked: (callback) => ipcRenderer.on('navigation-blocked', (_event, value) => callback(value)),
  getLocationStatus: () => ({
    enabled: scramblerEnabled,
    currentLocation: SPOOF_COORDINATES[spoofIndex],
  }),
  toggleLocationScrambler: (enabled) => {
    scramblerEnabled = enabled;
    return scramblerEnabled;
  },
});
