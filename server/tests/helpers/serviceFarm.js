import net from 'node:net'

async function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve(server.address().port)
    })
  })
}

export async function createServiceFarm() {
  const servers = []
  const connections = []
  const tlsServers = []

  async function serve(handler) {
    const server = net.createServer((socket) => {
      connections.push(socket)
      socket.on('error', () => {})
      handler(socket)
    })
    const port = await listen(server)
    servers.push(server)
    return port
  }

  const ssh = await serve((socket) => {
    socket.write('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n')
  })

  const http = await serve((socket) => {
    socket.once('data', () => {
      socket.end(
        'HTTP/1.1 200 OK\r\n' +
          'Server: Apache/2.4.49 (Ubuntu)\r\n' +
          'X-Powered-By: PHP/7.4.3\r\n' +
          'Content-Type: text/html\r\n' +
          'Content-Length: 13\r\n\r\nHello, world!'
      )
    })
  })

  const ftp = await serve((socket) => {
    socket.write('220 (vsFTPd 2.3.4)\r\n')
    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      let index
      while ((index = buffer.indexOf('\r\n')) !== -1) {
        const line = buffer.slice(0, index)
        buffer = buffer.slice(index + 2)
        if (/^USER /i.test(line)) socket.write('331 Please specify the password.\r\n')
        else if (/^PASS /i.test(line)) socket.write('230 Login successful.\r\n')
        else socket.write('500 Unknown command.\r\n')
      }
    })
  })

  const proxy = await serve((socket) => {
    socket.once('data', () => {
      socket.end(
        'HTTP/1.1 200 OK\r\n' +
          'Content-Type: text/html\r\n' +
          'Content-Length: 22\r\n\r\n<title>Example Domain</title>'
      )
    })
  })

  const scripted = await serve((socket) => {
    socket.write('welcome \u001b]0;owned\u0007to the machine\r\n')
  })

  const silent = await serve(() => {})

  const tarpit = await serve((socket) => {
    socket.on('data', () => {})
  })

  const bannerBomb = await serve((socket) => {
    socket.write('SSH-2.0-OpenSSH_9.6p1 ' + 'A'.repeat(256 * 1024) + '\r\n')
  })

  return {
    ports: { ssh, http, ftp, proxy, scripted, silent, tarpit, bannerBomb },
    connections,
    tlsServers,
    async close() {
      for (const socket of connections.splice(0)) {
        try {
          socket.destroy()
        } catch {}
      }
      await Promise.all(
        servers.splice(0).map(
          (server) => new Promise((resolve) => server.close(() => resolve()))
        )
      )
      for (const server of tlsServers.splice(0)) {
        await new Promise((resolve) => server.close(() => resolve()))
      }
    },
  }
}
