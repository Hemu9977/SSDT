const http = require('http');

const data = JSON.stringify({
  email: 'test' + Date.now() + '@example.com',
  password: 'password123',
  name: 'Test User'
});

const req = http.request('http://localhost:3001/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
}, (res) => {
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('end', () => {
    const parsed = JSON.parse(body);
    const token = parsed.token;
    
    if(!token) {
      console.log('Login failed', parsed);
      return;
    }
    
    const sData = JSON.stringify({ planType: 'pro', billingCycle: 'monthly' });
    const sReq = http.request('http://localhost:3001/api/stripe/create-checkout-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-auth-token': token,
        'Content-Length': Buffer.byteLength(sData)
      }
    }, (res2) => {
      let b2 = '';
      res2.on('data', chunk => b2 += chunk);
      res2.on('end', () => console.log('Stripe Response:', b2));
    });
    sReq.write(sData);
    sReq.end();
  });
});

req.write(data);
req.end();
