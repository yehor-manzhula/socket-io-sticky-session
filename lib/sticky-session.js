const net = require('net');
const cluster = require('cluster');
const crypto = require('crypto');
const _ = require('lodash');
const cpuNumbers = require('os').cpus().length;

module.exports = sticky;

function hash(ip, seed) {
  var hash = ip.reduce(function(r, num) {
    r += parseInt(num, 10);
    r %= 2147483648;
    r += (r << 10);
    r %= 2147483648;
    r ^= r >> 6;
    return r;
  }, seed);

  hash += hash << 3;
  hash %= 2147483648;
  hash ^= hash >> 11;
  hash += hash << 15;
  hash %= 2147483648;

  return hash >>> 0;
}

// Hash balanced layer 3 connection listener.
function layer3HashBalancedConnectionListener(connection) {
  // Get int31 hash of ip
  const ipHash = hash((connection.remoteAddress || '').split(/\./g), this.seed);

  Promise.resolve(this.getWorkerBy(ipHash))
    // Pass connection to worker
    .then(worker => worker.send('sticky-session:connection', connection));
}

// Hash balanced layer 4 connection listener.
// The node is choosed randomly initial and gets hash balanced later in
// patchConnection.
function layer4HashBalancedConnectionListener(connection) {
  // Get int31 hash of ip
  const random = crypto.randomBytes(4).readUInt32BE(0, true);
  
  Promise.resolve(this.getWorkerBy(random))
    .then(worker => worker.send('sticky-session:sync', connection));
}

// Handle sending messages to dead worker
function spawnWorker() {
  const worker = cluster.fork();

  worker.send = (original => {
    return function(message, socket) {
      if (this.isDead()) {
        socket.write('sticky-session: worker has been died');
        socket.end();
        
        return;
      }

      original.apply(this, arguments);
    };
  })(worker.send);

  worker.on('exit', (code, signal) => {
    if (signal) {
      console.log('sticky-session: worker was killed by signal', signal);
    } 
    
    if (code !== 0) {
      console.log('sticky-session: worker exited with error code', code);
    }

    console.log('sticky-session: worker died!');
  });

  worker.on('uncaughtException', err => console.error('stick-session: uncaught exception', err));
  worker.on('error', (...args) => console.error('sticky-session: worker error', args));

  return Promise.resolve(worker);
}

function sticky(options, callback) {
  const agent = new StickyAgent(options, callback);
  const mode = cluster.isMaster ? 'Master' : 'Slave';

  return agent[`setup${mode}`]();
}

function StickyAgent(options, callback) {
  Object.assign(this, {
    callback,
    seed: 0,

    // Changing the header if user specified something else than
    // 'x-forwarded-for'.
    header: _.get(options, 'header', 'x-forwarded-for').toString().toLowerCase(),
    ignoreMissingHeader: !!options.ignoreMissingHeader,
    
    // Overwriting sync object to sync with users options.
    sync: options.sync || {
      isSynced: false,
      event: 'sticky-sessions:sync'
    },

    serverOptions: {
      pauseOnConnect: true
    },
   
    connectionListener: (options.proxy ? layer4HashBalancedConnectionListener : layer3HashBalancedConnectionListener).bind(this)
  });
  
  if (!callback) {
    this.callback = options;
  } 

  this.num = _.isNumber(options) ? options : _.get(options, 'num', cpuNumbers);

  return this;
}

StickyAgent.prototype = {
  // Access 'private' object _handle of file decriptor to republish the read
  // packet.
  // Supports Node version from 0.12 and up.
  republishPacket(fd, data) {
    fd._handle.onread(1, new Buffer(data));
  },

  // Hash balance on the real ip and send data + file decriptor to final node.
  balance(connection, fd) {
    // Get int31 hash of ip
    const ipHash = hash((connection.realIP || '').split(/\./g), this.seed);

    Promise.resolve(this.getWorkerBy(ipHash))
      // Pass connection to worker
      .then(worker => worker.send({
        cmd: 'sticky-session:connection', 
        data: connection.data
      }, fd));
  },

  getWorkerBy(value) {
    return this.workers[value % this.workers.length];
  },

  setupMaster() {
    const self = this;

    // Master will spawn `num` workers
    self.workers = _.times(self.num, function spawn(index) {
      const worker = spawnWorker();
      
      worker.then(instance => {
        // Balance messages
        instance.on('message', (message, connection) => {
          if (_.get(message, 'cmd', '') !== 'sticky-session:ack') {
            return;
          }

          self.balance(message, connection);
        });

        // Respawn worker on exit
        instance.on('exit', () => {
          console.log('sticky-session: Respawn worker', index);
          self.workers[index] = spawn(index);
        });
      });

      return worker;
    });

    self.seed = crypto.randomBytes(4).readUInt32BE(0, true) % 0x80000000;
    
    return net.createServer(self.serverOptions, self.connectionListener);
  },

  setupSlave() {
    const self = this;
  
    self.server = _.result(self, 'callback');
  
    if (!self.server) {
      throw new Error('sticky-session: worker hasn\'t created server!');
    }

    process.on('message', self.dispatch.bind(self));
  
    // Monkey patch server listen method
    self.server.listen = (origin => {
      return function(...args) {
        const callback = args.pop();
    
        if (_.isFunction(callback)) {
          callback();
        }
    
        return origin.call(this, () => {});
      };
    })(self.server.listen);
  
    return self.server;
  },
  
  // Worker process
  dispatch(msg, socket) {
    const self = this;

    if (!socket) {
      return;
    }
    
    if (_.isString(msg)) {
      // Worker received sync flagged request.
      if (msg === 'sticky-session:sync') {
        // Reading data once from file descriptor and extract ip from the
        // header.
        socket.once('data', data => {
          let dataString = data.toString().toLowerCase();

          if (self.serverOptions.pauseOnConnect) {
            socket.pause();
          }

          // If the header was not found return, probably unwanted behavior.
          if (dataString.includes(self.header)) {
            if (self.ignoreMissingHeader) {
              process.send({ 
                cmd: 'sticky-session:ack', 
                realIP: socket.remoteAddress, 
                data: data 
              }, socket);
              
              return;
            } 
              
            socket.destroy();
            return;
          }
          
          let searchPos = dataString.indexOf(self.header);
          searchPos = dataString.indexOf(':', searchPos) + 1;
          let endPos = dataString.indexOf('\n', searchPos);
          const realIP = dataString.substr(searchPos, endPos - searchPos - 1).trim();

          // Send ackknownledge + data and real ip adress back to master
          process.send({ 
            cmd: 'sticky-session:ack', 
            realIP, 
            data 
          }, socket);
        });

        if (self.serverOptions.pauseOnConnect) {
          socket.resume();
        }

        return;
      }

      if (msg !== 'sticky-session:connection') {
        return;
      }
    }

    // Message was an object and has to contain a cmd variable.
    if (_.isObject(msg)) {
      // Master send us a finalized to us assigned file descriptor
      // and the read data from the ip extraction.
      if (msg.cmd === 'sticky-session:connection') {
        const sync = self.sync;
  
        // We register the event, to synchronize the data republishing
        // if the user wants for some reason manually call the sync.
        if (sync.isSynced) {
          socket.once(sync.event, function() {
            self.republishPacket(socket, msg.data);
          });
        }
  
        self.server.emit('connection', socket);
  
        // We're going to push the packet back to the net controller,
        // to let this node complete the original request.
        if (!sync.isSynced) {
          self.republishPacket(socket, msg.data);
        }

        return;
      }
      
      return;
    }
    
    self.server.emit('connection', socket);
  }  
}