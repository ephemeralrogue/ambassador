let nullStore =
{
  build: function(options) {},
  
  store: function(req, cb)
  { cb(); },
  
  verify: function(req, providedState, cb)
  { cb(null, true); }
}

export default nullStore;