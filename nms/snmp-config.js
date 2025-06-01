const snmp = require('net-snmp');

function getDeviceStatus(ip, community = 'public') {
  const session = snmp.createSession(ip, community);
  const oid = '1.3.6.1.2.1.1.5.0'; // sysName
  return new Promise((resolve, reject) => {
    session.get([oid], (error, varbinds) => {
      if (error) {
        reject(error);
      } else {
        const status = varbinds[0].value.toString() ? 'Online' : 'Offline';
        resolve({ ip, status });
      }
      session.close();
    });
  });
}

async function monitorDevices() {
  const devices = [
    { ip: '192.168.1.10', name: 'Huawei MA5800' },
    { ip: '192.168.1.11', name: 'VSOL ONU' },
    { ip: '192.168.1.12', name: 'BDCOM GP3600' }
  ];
  for (const device of devices) {
    try {
      const { status } = await getDeviceStatus(device.ip);
      console.log(`${device.name} (${device.ip}): ${status}`);
      // Update database via API
      fetch('http://localhost:3000/api/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + localStorage.getItem('token') },
        body: JSON.stringify({ name: device.name, type: device.name.includes('ONU') ? 'ONU' : 'OLT', ip: device.ip, status })
      });
    } catch (err) {
      console.error(`Error monitoring ${device.name}: ${err.message}`);
    }
  }
}

// Run every 5 minutes
setInterval(monitorDevices, 300000);

module.exports = { monitorDevices };