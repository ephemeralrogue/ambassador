let nullStore = {};

Object.defineProperties(nullStore,
{
  build:
  {
    value: function build(options) {},
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  _store:
  {
    value: function store(req, cb)
    { cb(); },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _verifyState:
  {
    value: function verifyState(req, providedState, cb)
    { cb(null, true); },
    writable: false,
    configurable: true,
    enumerable: false
  }
});

export default nullStore;